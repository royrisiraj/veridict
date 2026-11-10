import { NextRequest } from "next/server";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const route = path.join("/");
  if (!/^(?:health|fixtures|investigate|reports\/0x[0-9a-f]{64}(?:\/(?:verify|tamper-demo))?)$/.test(route)) {
    return Response.json({ detail: "Unknown API route" }, { status: 404 });
  }
  try {
    const body = request.method === "POST" ? await request.text() : undefined;
    if (body && new TextEncoder().encode(body).length > 524288) return Response.json({ detail: "Request exceeds inspection limits" }, { status: 413 });
    const base = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";
    const upstream = await fetch(`${base}${route === "health" ? "/health" : "/api/" + route}`, {
      method: request.method, body, cache: "no-store",
      headers: { "Content-Type": "application/json", Accept: request.headers.get("accept") ?? "application/json" },
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(60000)]),
    });
    return new Response(upstream.body, { status: upstream.status, headers: { "Content-Type": upstream.headers.get("content-type") ?? "application/json", "Cache-Control": "no-store", "X-Accel-Buffering": "no" } });
  } catch {
    return Response.json({ detail: "The inspection service is unavailable. Navigation remains blocked." }, { status: 503 });
  }
}
export const GET = proxy;
export const POST = proxy;
