"""FastAPI entrypoint with sanitized errors and optional real stage streaming."""
import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from app.chain.registry import AnchorUnavailableError, create_registry
from app.config import Settings
from app.db import Database
from app.fixtures import fixture_metadata
from app.models import (FixtureMetadata, HealthResponse, InvestigateRequest, InvestigationReport,
    TamperRequest, TamperResponse, VerificationResponse, VerifyRequest)
from app.pipeline import investigate
from app.verifier import Verifier


def create_app(settings: Settings | None = None, registry=None):
    settings = settings or Settings()
    # Access logs can otherwise retain arbitrary query parameters sent to this API.
    logging.getLogger("uvicorn.access").disabled = True

    @asynccontextmanager
    async def lifespan(application):
        database = Database(settings.database_path)
        application.state.database = database
        application.state.registry = registry if registry is not None else await asyncio.to_thread(create_registry, settings)
        application.state.verifier = Verifier(database, application.state.registry)
        try:
            yield
        finally:
            database.close()

    application = FastAPI(title="VERIDICT Evidence Passport API", version="1.0.0", lifespan=lifespan)
    application.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Accept"])

    @application.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic errors include raw input by default; never return it.
        return JSONResponse(status_code=422, content={"detail": "Invalid request", "fields": [".".join(map(str, error["loc"])) for error in exc.errors()]})

    @application.exception_handler(AnchorUnavailableError)
    async def anchor_error(request, exc):
        return JSONResponse(status_code=503, content={"detail": "The original anchor is unavailable; verification cannot establish integrity."})

    @application.exception_handler(ValueError)
    async def input_error(request, exc):
        return JSONResponse(status_code=422, content={"detail": "Invalid URL, fixture input, or evidence selection."})

    @application.exception_handler(LookupError)
    async def missing_error(request, exc):
        return JSONResponse(status_code=404, content={"detail": "Report or fixture not found."})

    @application.exception_handler(Exception)
    async def unexpected_error(request, exc):
        return JSONResponse(status_code=500, content={"detail": "Investigation could not complete. No safety conclusion is available."})

    @application.get("/health", response_model=HealthResponse)
    async def health():
        chain = application.state.registry
        return HealthResponse(chain_connected=await asyncio.to_thread(lambda: chain.connected), contract_address=chain.address, chain_mode=chain.mode)

    @application.get("/api/fixtures", response_model=list[FixtureMetadata])
    async def fixtures():
        return fixture_metadata()

    @application.post("/api/investigate", response_model=InvestigationReport)
    async def investigate_route(payload: InvestigateRequest, request: Request):
        async def run(emit):
            return await investigate(payload, settings, application.state.database, application.state.registry, application.state.verifier, emit)

        if "text/event-stream" not in request.headers.get("accept", ""):
            async def quiet(stage):
                return None
            return await run(quiet)

        async def events():
            queue = asyncio.Queue()

            async def emit(stage):
                await queue.put(("stage", {"stage": stage}))

            async def worker():
                try:
                    result = await run(emit)
                    await queue.put(("report", result.model_dump(mode="json", by_alias=True)))
                except Exception:
                    await queue.put(("error", {"detail": "Inspection unavailable. Navigation remains blocked."}))
                finally:
                    await queue.put(None)

            task = asyncio.create_task(worker())
            try:
                while True:
                    entry = await queue.get()
                    if entry is None:
                        break
                    event, data = entry
                    yield f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    def get_report(report_id):
        report = application.state.database.get(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report

    @application.get("/api/reports/{report_id}", response_model=InvestigationReport)
    async def report_route(report_id: str):
        return get_report(report_id)

    @application.post("/api/reports/{report_id}/verify", response_model=VerificationResponse)
    async def verify_route(report_id: str, payload: VerifyRequest):
        original = get_report(report_id)
        return await asyncio.to_thread(application.state.verifier.verify_bundle, report_id, payload.candidate_bundle or original.bundle, payload.evidence_id)

    @application.post("/api/reports/{report_id}/tamper-demo", response_model=TamperResponse)
    async def tamper_route(report_id: str, payload: TamperRequest):
        get_report(report_id)
        return await asyncio.to_thread(application.state.verifier.tamper, report_id, payload.mutation, payload.evidence_id)

    @application.middleware("http")
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    return application


app = create_app()
