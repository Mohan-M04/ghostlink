import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "../App.jsx";
import { createMockReport, mockAlerts, mockInvestigate } from "../api/mock.js";
import { transformGraph } from "../components/GraphView.jsx";
import { decideAction } from "../api/client.js";
import InvestigationPanel from "../components/InvestigationPanel.jsx";

vi.mock("react-force-graph-2d", () => ({ default: () => <div data-testid="graph" /> }));

describe("GhostLink UI", () => {
  afterEach(cleanup);
  beforeEach(() => { vi.stubEnv("VITE_USE_MOCK", "true"); });
  it("runs a mock investigation and renders report/disclaimer", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Investigate 203.0.113.45" }));
    expect(await screen.findByText("Review the trigger and retrieve graph context.")).toBeTruthy();
    expect(await screen.findByText("71")).toBeTruthy();
    expect(screen.getByText("not a probability of guilt")).toBeTruthy();
    expect(screen.getByText("Simulated data")).toBeTruthy();
  });
  it("mock flow ends with report and done in contract order", async () => {
    const events = [];
    for await (const event of mockInvestigate({ ...createMockReport({ ip: "203.0.113.45", severity: "high", source: "FEED-ALPHA", timestamp: "2026-10-01T00:00:00Z", id: "ALERT-001" }).trigger, id: "ALERT-001" })) events.push(event.type);
    expect(events[0]).toBe("started");
    expect(events.at(-2)).toBe("report");
    expect(events.at(-1)).toBe("done");
  });
  it("keeps every mock finding citation in its evidence and tool results", async () => {
    const knownIds = new Set();
    for (const alert of mockAlerts) {
      const report = createMockReport(alert);
      const reportIds = new Set(report.evidence.map((item) => item.id));
      expect(report.score_breakdown.final).toBe(report.score);
      expect(report.band).toBe(report.score < 40 ? "monitor" : report.score < 70 ? "investigate" : report.score < 85 ? "human_review" : "urgent_review");
      for (const item of report.evidence) {
        expect(knownIds.has(item.id)).toBe(false);
        knownIds.add(item.id);
      }
      for (const finding of report.findings) for (const id of finding.evidence_ids) expect(reportIds.has(id)).toBe(true);
      const results = [];
      for await (const event of mockInvestigate(alert)) {
        if (event.type === "step" && event.kind === "tool_result") results.push(...event.evidence_ids);
      }
      for (const id of reportIds) expect(results).toContain(id);
    }
  });
  it("transforms decoys and highlights selected finding path", () => {
    const graph = { nodes: [{ id: "acct:A", type: "Account", decoy: false }, { id: "ip:1", type: "IP", decoy: true }], links: [{ source: "acct:A", target: "ip:1", decoy: true }] };
    const data = transformGraph(graph, { path: ["acct:A", "ip:1"] });
    expect(data.nodes[0].highlighted).toBe(true);
    expect(data.nodes[1].color).toBe("#737d85");
    expect(data.links[0].highlighted).toBe(true);
    expect(data.links[0].decoy).toBe(true);
  });
  it("shows empty states for actions/findings and streams retry state", async () => {
    render(<App />);
    expect(await screen.findByText("No proposed actions returned.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Investigate 203.0.113.45" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Results" })).toBeTruthy());
  });
  it("uses required pending approval decisions", async () => {
    const report = createMockReport({ ip: "203.0.113.45", severity: "high", source: "FEED-ALPHA", timestamp: "2026-10-01T00:00:00Z", id: "ALERT-001" });
    expect(report.actions.every((action) => action.status === "PENDING_APPROVAL")).toBe(true);
    const approve = await decideAction(report.actions[0].id, "approve");
    const reject = await decideAction(report.actions[1].id, "reject");
    expect(approve.status).toBe("APPROVED");
    expect(reject.status).toBe("REJECTED");
  });
  it("shows a clear conflict on failed human decision", async () => {
    const onDecide = vi.fn().mockRejectedValue(Object.assign(new Error("Conflict"), { status: 409 }));
    const { default: ActionCard } = await import("../components/ActionCard.jsx");
    render(<ActionCard actions={[{ id: "act-abc123", case_id: "case-abc123", type: "MANUAL_REVIEW", status: "PENDING_APPROVAL" }]} onDecide={onDecide} />);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(await screen.findByRole("alert").then((element) => element.textContent)).toContain("already decided");
  });
  it("shows a clear not-found message on a missing action", async () => {
    const onDecide = vi.fn().mockRejectedValue(Object.assign(new Error("Not found"), { status: 404 }));
    const { default: ActionCard } = await import("../components/ActionCard.jsx");
    render(<ActionCard actions={[{ id: "act-abc123", case_id: "case-abc123", type: "MANUAL_REVIEW", status: "PENDING_APPROVAL" }]} onDecide={onDecide} />);
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(await screen.findByRole("alert").then((element) => element.textContent)).toContain("was not found");
  });
  it("retains partial steps and offers retry after a disconnected stream", () => {
    const retry = vi.fn();
    render(<InvestigationPanel steps={[{ seq: 1, kind: "tool_result", message: "Partial result" }]} status="disconnected" error="" onRetry={retry} onCancel={() => {}} />);
    expect(screen.getByRole("alert").textContent).toContain("Connection lost");
    expect(screen.getByText("Partial result")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledOnce();
  });
});
