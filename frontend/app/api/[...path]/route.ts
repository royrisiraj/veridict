import { NextRequest } from "next/server";
export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 60;

async function proxy(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const route = path.join("/");
  if (!/^(?:health|fixtures|investigate|reports\/0x[0-9a-f]{64}(?:\/(?:verify|tamper-demo|anchor))?)$/.test(route)) {
    return Response.json({ detail: "Unknown API route" }, { status: 404 });
  }
  const isRead = /^(?:health|fixtures|reports\/0x[0-9a-f]{64}(?:\/anchor)?)$/.test(route);
  if (request.method !== (isRead ? "GET" : "POST")) return Response.json({ detail: "Method not allowed" }, { status: 405, headers: { Allow: isRead ? "GET" : "POST" } });
  const configured = process.env.BACKEND_BASE_URL || process.env.BACKEND_URL;
  if (!configured) return Response.json({ detail: "Backend is not configured. Set the server-side BACKEND_BASE_URL environment variable." }, { status: 503 });
  let base: URL;
  try {
    base = new URL(configured);
    if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.pathname !== '/' || base.search || base.hash) throw new Error("Invalid base");
    if (process.env.VERCEL === "1" && (base.protocol !== "https:" || ["localhost", "127.0.0.1", "[::1]", "backend"].includes(base.hostname))) throw new Error("Public backend required");
  } catch {
    return Response.json({ detail: "Invalid BACKEND_BASE_URL. Configure an HTTPS backend origin without a path or credentials." }, { status: 503 });
  }
  try {
    let body: string | undefined;
    if (request.method === "POST") {
      const reader = request.body?.getReader();
      const decoder = new TextDecoder();
      let size = 0;
      body = "";
      if (reader) {
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            size += chunk.value.byteLength;
            if (size > 524288) { await reader.cancel(); return Response.json({ detail: "Request exceeds inspection limits" }, { status: 413 }); }
            body += decoder.decode(chunk.value, { stream: true });
          }
          body += decoder.decode();
        } finally { reader.releaseLock(); }
      }
    }
    const headers: Record<string, string> = { "Content-Type": "application/json", Accept: request.headers.get("accept") ?? "application/json" };
    if (process.env.BACKEND_PROTECTION_BYPASS) headers["x-vercel-protection-bypass"] = process.env.BACKEND_PROTECTION_BYPASS;
    // Never relay caller-supplied authorization headers. Registration remains an
    // operator-only backend endpoint and cannot be called through this proxy.
    if (route === "investigate" && process.env.SCAN_API_SECRET) {
      headers["x-veridict-scan-secret"] = process.env.SCAN_API_SECRET;
      headers["x-veridict-client"] = request.headers.get("x-vercel-forwarded-for")?.split(",")[0]?.trim() || "shared-preview";
    }
    const upstream = await fetch(new URL(route === "health" ? "/health" : "/api/" + route, base), {
      method: request.method, body, cache: "no-store",
      headers, redirect: "manual",
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(55000)]),
    });
    const contentType = upstream.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json") && !contentType.includes("text/event-stream")) return Response.json({ detail: "Backend returned a non-API response. Check its URL and Vercel Deployment Protection." }, { status: upstream.ok || upstream.status < 400 ? 502 : upstream.status });
    const responseHeaders: Record<string, string> = { "Content-Type": contentType, "Cache-Control": "no-store", "X-Accel-Buffering": "no" };
    for (const name of ["retry-after", "allow"]) { const value = upstream.headers.get(name); if (value) responseHeaders[name] = value; }
    return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
  } catch {
    return Response.json({ detail: "The inspection service is unavailable. Navigation remains blocked." }, { status: 503 });
  }
}
export const GET = proxy;
export const POST = proxy;
