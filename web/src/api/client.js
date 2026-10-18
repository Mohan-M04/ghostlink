import { createMockReport, mockAlerts, mockInvestigate } from "./mock.js";
import { normalizeBackendReport } from "./backendAdapter.js";
import { parseStream } from "./parseStream.js";

const useMock = import.meta.env.MODE === "test" || import.meta.env.VITE_USE_MOCK !== "false";
const baseUrl = (import.meta.env.VITE_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, options);
  } catch (error) {
    throw new Error(`Network request failed: ${error.message}`);
  }
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const payload = await response.json();
      message = payload?.error?.message || payload?.detail || message;
    } catch {
      // Keep the HTTP status as the explicit fallback when the server body is not JSON.
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return response;
}

export async function getAlerts() {
  if (useMock) return mockAlerts;
  try {
    const response = await request("/alerts");
    const payload = await response.json();
    const alerts = Array.isArray(payload) ? payload : payload?.alerts;
    if (!Array.isArray(alerts)) throw new Error("The alerts response did not contain an alerts array.");
    return alerts.map((alert) => ({
      ...alert,
      source: alert.source ?? null,
      timestamp: alert.timestamp ?? null
    }));
  } catch (error) {
    if (error.status === 404) return mockAlerts;
    throw error;
  }
}

export async function getCase(caseId) {
  if (useMock) {
    const alert = mockAlerts.find((item) => createMockReport(item).case_id === caseId);
    if (!alert) {
      const error = new Error("Case not found.");
      error.status = 404;
      throw error;
    }
    return createMockReport(alert);
  }
  const response = await request(`/case/${encodeURIComponent(caseId)}`);
  return response.json();
}

export async function* investigate(alert, signal) {
  if (useMock) {
    yield* mockInvestigate(alert, signal);
    return;
  }
  const response = await request("/investigate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
    body: JSON.stringify({ ip: alert.ip, alert_id: alert.id ?? null, severity: alert.severity ?? null, source: alert.source ?? null, replay: false }),
    signal
  });
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const rawReport = await response.json();
    const report = normalizeBackendReport(rawReport);
    const ts = new Date().toISOString();
    let seq = 1;
    for (const entry of report.trace) {
      const tool = entry.tool ?? "tool";
      const message = entry.reason
        ? entry.status === "fallback"
          ? entry.reason
          : `${entry.planner ?? "Planner"} ${entry.status === "selected" ? "selected" : "considered"} ${tool}: ${entry.reason}`
        : entry.summary ?? `Backend trace: ${tool} — ${entry.status ?? "status not returned"}.`;
      yield {
        type: "step",
        seq: seq++,
        ts,
        kind: entry.kind ?? "info",
        message,
        tool: entry.tool ?? null,
        args: null,
        ok: entry.status === "ok" ? true : entry.status === "failed" ? false : null,
        evidence_ids: entry.evidence_ids ?? []
      };
    }
    yield { type: "step", seq: seq++, ts, kind: "info", message: "This backend returned a completed JSON response; live investigation steps are not streamed.", tool: null, args: null, ok: null, evidence_ids: [] };
    yield { type: "report", seq: seq++, ts, report };
    yield { type: "done", seq, ts, status: "complete", case_id: report.case_id };
    return;
  }
  if (!response.body) throw new Error("The server returned no investigation stream.");
  yield* parseStream(response.body, signal);
}

export async function decideAction(actionId, decision) {
  if (useMock) {
    const action = createMockReport(mockAlerts[0]).actions.find((item) => item.id === actionId);
    if (!action) {
      const error = new Error("Action not found.");
      error.status = 404;
      throw error;
    }
    return { id: action.id, case_id: action.case_id, type: action.type, status: decision === "approve" ? "APPROVED" : "REJECTED", decided_at: new Date().toISOString(), decided_by: "demo-analyst" };
  }
  const response = await request(`/actions/${encodeURIComponent(actionId)}/${decision}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision })
  });
  const result = await response.json();
  return { ...result, id: result.id ?? result.action_id };
}

export { createMockReport, useMock };
