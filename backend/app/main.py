"""FastAPI entrypoint with sanitized errors and optional real stage streaming."""
import asyncio
import json
import logging
import hmac
from urllib.parse import urlsplit
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from app.chain.registry import AnchorUnavailableError, create_registry
from app.config import Settings
from app.db import Database
from app.deployment import FixtureRegistry, FixtureReportStore, UnavailableRegistry, fixture_report_id
from app.fixtures import fixture_metadata, load_fixture
from app.models import (FixtureMetadata, HealthResponse, InvestigateRequest, InvestigationReport,
    TamperRequest, TamperResponse, VerificationResponse, VerifyRequest)
from app.pipeline import STAGES, investigate
from app.security.url import normalize_url
from app.verifier import Verifier
from app.models import AnchorResponse
from app.storage import BlobReportStore, DurableControls, StorageUnavailableError, QuotaExceededError
from app.production import ProductionVerifier
from app.chain.sepolia import SepoliaRegistry
from app.chain.anchoring import AnchorService


def create_app(settings: Settings | None = None, registry=None, store=None, public_chain=None):
    settings = settings or Settings()
    # Access logs can otherwise retain arbitrary query parameters sent to this API.
    logging.getLogger("uvicorn.access").disabled = True

    @asynccontextmanager
    async def lifespan(application):
        hosted = settings.runtime_mode == "serverless" or settings.chain_mode == "demo_fixture"
        production = hosted or settings.report_storage == "vercel_blob" or settings.chain_mode == "public_chain"
        database = store or (BlobReportStore() if settings.report_storage == "vercel_blob" else FixtureReportStore() if production else Database(settings.database_path))
        application.state.database = database
        chain = public_chain
        if chain is None and settings.chain_mode == "public_chain":
            try:
                chain = SepoliaRegistry(settings)
            except Exception:
                chain = None
        application.state.public_chain = chain
        application.state.production = production
        if registry is not None:
            selected_registry = registry
        elif production:
            selected_registry = FixtureRegistry() if chain is not None or settings.chain_mode in {"auto", "fixture", "demo_fixture"} else UnavailableRegistry()
        else:
            selected_registry = await asyncio.to_thread(create_registry, settings)
        application.state.registry = selected_registry
        application.state.verifier = ProductionVerifier(database, chain, require_chain=settings.chain_mode in {"public_chain", "unavailable"}) if production else Verifier(database, application.state.registry)
        application.state.anchoring = AnchorService(settings, database, chain, application.state.verifier)
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

    @application.exception_handler(StorageUnavailableError)
    async def storage_error(request, exc):
        return JSONResponse(status_code=503, content={"detail": "Private report storage is unavailable. The report has not been confirmed saved."})

    @application.exception_handler(QuotaExceededError)
    async def quota_error(request, exc):
        return JSONResponse(status_code=429, content={"detail": "The controlled rollout limit was reached or an operation is pending. Retry later."}, headers={"Retry-After": "3600"})

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
        hosted = isinstance(application.state.database, FixtureReportStore)
        mode = ("UNAVAILABLE" if chain.mode == "unavailable" else "DEMO_FIXTURE" if isinstance(chain, FixtureRegistry)
                else "PUBLIC_CHAIN" if chain.mode == "evm" and chain.chain_id != 31337 else "LOCAL_DEVELOPMENT")
        if isinstance(chain, FixtureRegistry) and not chain.path.is_file():
            mode = "UNAVAILABLE"
        if application.state.production:
            persistent = isinstance(application.state.database, BlobReportStore)
            available = await asyncio.to_thread(application.state.database.objects.available) if persistent else False
            public = application.state.public_chain
            connected = False
            if public is not None:
                try:
                    connected = await asyncio.to_thread(public.check)
                except AnchorUnavailableError:
                    connected = False
            mode = "PUBLIC_CHAIN" if connected else "UNAVAILABLE" if settings.chain_mode in {"public_chain", "unavailable"} else "DEMO_FIXTURE"
            return HealthResponse(chain_connected=bool(connected), contract_address=public.address if public else "",
                chain_mode="evm" if connected else "unavailable" if settings.chain_mode == "public_chain" else chain.mode,
                runtime_mode=settings.runtime_mode, verification_mode=mode,
                live_scanning_enabled=bool(settings.live_checks and available and len(settings.scan_api_secret) >= 32 and settings.scan_allowed_hosts and not (application.state.verifier.require_chain and public is None)),
                report_storage="vercel_blob" if available else "unavailable" if persistent else "packaged-read-only")
        return HealthResponse(chain_connected=bool(getattr(chain, "health_connected", False)), contract_address=chain.address,
            chain_mode=chain.mode, runtime_mode=settings.runtime_mode, verification_mode=mode,
            live_scanning_enabled=not hosted, report_storage="packaged-read-only" if hosted else "sqlite")

    @application.get("/api/fixtures", response_model=list[FixtureMetadata])
    async def fixtures():
        return fixture_metadata()

    @application.post("/api/investigate", response_model=InvestigationReport)
    async def investigate_route(payload: InvestigateRequest, request: Request):
        live = application.state.production and not payload.fixture_id
        if live:
            if not settings.live_checks or not isinstance(application.state.database, BlobReportStore) or len(settings.scan_api_secret) < 32 or not settings.scan_allowed_hosts:
                raise HTTPException(status_code=403, detail="Demo fixture mode: live scanning requires private durable storage, a protected proxy, and an allowed-host rollout.")
            if not hmac.compare_digest(request.headers.get("x-veridict-scan-secret", ""), settings.scan_api_secret):
                raise HTTPException(status_code=401, detail="Live scanning requires the authorized application proxy.")
            parts = urlsplit(payload.url)
            if parts.scheme != "https" or parts.username is not None or parts.password is not None or (parts.port or 443) != 443 or (parts.hostname or "").lower() not in settings.scan_allowed_hosts:
                raise HTTPException(status_code=422, detail="Controlled live scanning accepts credential-free HTTPS URLs on approved hosts and port 443.")
            await asyncio.to_thread(DurableControls(application.state.database.objects).scan, request.headers.get("x-veridict-client", "unknown")[:256], settings)

        async def run(emit):
            if live:
                # A durable lease bounds active collection across function instances.
                # Crashed leases fail closed and require explicit operator cleanup.
                lease = DurableControls(application.state.database.objects).lease("live-scanner")
                await asyncio.to_thread(lease.__enter__)
                try:
                    async with asyncio.timeout(45):
                        return await investigate(payload, settings, application.state.database, application.state.registry, application.state.verifier, emit, seal_only=True)
                finally:
                    await asyncio.to_thread(lease.__exit__, None, None, None)
            if application.state.production:
                if application.state.registry.mode == "unavailable":
                    raise AnchorUnavailableError("No valid verification source is configured")
                if not payload.fixture_id:
                    raise HTTPException(status_code=403, detail="Demo fixture mode: custom investigations are disabled. Choose one of the six packaged cases.")
                fixture = load_fixture(payload.fixture_id)
                if normalize_url(payload.url).normalized_url != normalize_url(fixture["input"]["url"]).normalized_url:
                    raise ValueError("Fixture URL mismatch")
                for stage in STAGES:
                    await emit(stage)
                report = await asyncio.to_thread(application.state.database.get, fixture_report_id(payload.fixture_id))
                if report is None:
                    raise AnchorUnavailableError("Packaged fixture passport is missing")
                checked = await asyncio.to_thread(application.state.verifier.verify_bundle, report.bundle.report_id, report.bundle)
                return report.model_copy(update={"verification": checked})
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
                except HTTPException as exc:
                    await queue.put(("error", {"detail": exc.detail}))
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

    async def get_report(report_id):
        report = await asyncio.to_thread(application.state.database.get, report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report

    @application.get("/api/reports/{report_id}", response_model=InvestigationReport)
    async def report_route(report_id: str):
        report = await get_report(report_id)
        if application.state.production:
            checked = await asyncio.to_thread(application.state.verifier.verify_bundle, report_id, report.bundle)
            status = await asyncio.to_thread(application.state.verifier.anchor_status, report_id, report.merkle.root)
            return report.model_copy(update={"verification": checked, "chain_receipt": status.receipt or report.chain_receipt})
        return report

    @application.get("/api/reports/{report_id}/anchor", response_model=AnchorResponse)
    async def anchor_status_route(report_id: str):
        original = await get_report(report_id)
        if not application.state.production:
            return AnchorResponse(report_id=report_id, status="NOT_CONFIGURED")
        return await asyncio.to_thread(application.state.verifier.anchor_status, report_id, original.merkle.root)

    @application.post("/api/reports/{report_id}/anchor", response_model=AnchorResponse)
    async def anchor_route(report_id: str, request: Request):
        if len(settings.anchor_api_secret) < 32 or not hmac.compare_digest(request.headers.get("x-veridict-anchor-secret", ""), settings.anchor_api_secret):
            raise HTTPException(status_code=401, detail="Registration requires separate operator authorization.")
        await get_report(report_id)
        return await asyncio.to_thread(application.state.anchoring.anchor, report_id)

    @application.post("/api/reports/{report_id}/verify", response_model=VerificationResponse)
    async def verify_route(report_id: str, payload: VerifyRequest):
        original = await get_report(report_id)
        return await asyncio.to_thread(application.state.verifier.verify_bundle, report_id, payload.candidate_bundle or original.bundle, payload.evidence_id)

    @application.post("/api/reports/{report_id}/tamper-demo", response_model=TamperResponse)
    async def tamper_route(report_id: str, payload: TamperRequest):
        await get_report(report_id)
        return await asyncio.to_thread(application.state.verifier.tamper, report_id, payload.mutation, payload.evidence_id)

    @application.middleware("http")
    async def no_store(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    application.add_middleware(RequestLimitMiddleware)
    return application


class RequestLimitMiddleware:
    """Bound JSON bodies before parsing, including chunked requests."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 524288:
                response = JSONResponse(status_code=413, content={"detail": "Request exceeds inspection limits"})
                return await response(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()
        await self.app(scope, bounded_receive, send)


app = create_app()
