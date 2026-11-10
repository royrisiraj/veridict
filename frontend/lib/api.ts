import type { InvestigationInput, Report } from "./types";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/${path}`, { ...init, cache: "no-store", headers: { "Content-Type": "application/json", ...init?.headers } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? "The inspection service is unavailable.");
  }
  return response.json() as Promise<T>;
}

export async function streamInvestigation(input: InvestigationInput, signal: AbortSignal, onStage: (stage: string) => void): Promise<Report> {
  const response = await fetch("/api/investigate", { method: "POST", headers: { "Content-Type": "application/json", Accept: "text/event-stream" }, body: JSON.stringify(input), signal });
  if (!response.ok || !response.body) {
    const error = await response.json().catch(() => ({}));
    throw new Error((error.detail ?? "Inspection unavailable.") + " Navigation remains blocked.");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      let end: number;
      while ((end = buffer.indexOf("\n\n")) >= 0) {
        const event = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        const kind = event.split("\n").find((line) => line.startsWith("event: "))?.slice(7);
        const data = event.split("\n").filter((line) => line.startsWith("data: ")).map((line) => line.slice(6)).join("\n");
        if (!data) continue;
        const payload = JSON.parse(data);
        if (kind === "stage") onStage(payload.stage);
        if (kind === "error") throw new Error(payload.detail);
        if (kind === "report") return payload as Report;
      }
      if (done) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  throw new Error("Inspection ended before sealing. Navigation remains blocked.");
}
