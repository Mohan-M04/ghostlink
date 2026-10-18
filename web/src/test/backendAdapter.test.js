import { normalizeBackendReport } from "../api/backendAdapter.js";

describe("normalizeBackendReport", () => {
  it("keeps only tool evidence citations and adapts returned graph data", () => {
    const report = normalizeBackendReport({
      case_id: "CASE-12345678",
      simulated_data: true,
      trigger: { ip: "203.0.113.45", simulated: true },
      score: 99.6,
      band: "urgent_human_review",
      recommended_action: "escalate_for_human_review",
      signals: { shared_device: 0.75, txn_cycle: 0.85 },
      findings: [
        { tier: "OBSERVED", claim: "Indicator claim with a non-evidence citation.", evidence_ids: ["TI-001"] },
        { tier: "DERIVED", claim: "Accounts share a device.", device_id: "DEV-RING-1", evidence_ids: ["EV-005", "EV-006", "EV-007"] },
        { tier: "DERIVED", claim: "Transaction cycle returned.", evidence_ids: ["EV-011", "EV-012", "EV-013"], details: { txns: [{ id: "TX-0001", from: "acct:A1", to: "acct:A2" }, { id: "TX-0002", from: "acct:A2", to: "acct:A3" }] } }
      ],
      evidence_ids: ["EV-005", "EV-006", "EV-007", "EV-011", "EV-012", "EV-013"],
      evidence: [
        { id: "EV-005", tier: "OBSERVED", reliability: 0.9, source: "synthetic", relationship: "acct:A1 -[USES_DEVICE]-> dev:DEV-RING-1", simulated: true },
        { id: "EV-006", tier: "OBSERVED", reliability: 0.9, source: "synthetic", relationship: "acct:A2 -[USES_DEVICE]-> dev:DEV-RING-1", simulated: false }
      ],
      graph: {
        accounts: { ip: "203.0.113.45", accounts: [{ id: "A1", count: 1, last_seen: "2026-09-29T06:03:00Z" }] },
        shared_devices: { devices: [{ id: "DEV-RING-1", device_type: "mobile", degree: 3, is_hub: false, accounts: [{ id: "A1" }, { id: "A2" }, { id: "A3" }] }] },
        cycles: { cycles: [{ accounts: ["acct:A1", "acct:A2", "acct:A3"], txns: [{ id: "TX-0001", from: "acct:A1", to: "acct:A2", amount: 10, timestamp: "2026-09-29T06:00:00Z" }, { id: "TX-0002", from: "acct:A2", to: "acct:A3", amount: 8, timestamp: "2026-09-29T07:00:00Z" }] }] }
      },
      actions: [{ id: "ACT-ABC12345", type: "MANUAL_REVIEW", status: "PENDING_APPROVAL" }],
      limitations: [],
      trace: [],
      innocent_explanations: [],
      conflicts: [],
      check_next: []
    });

    expect(report.findings.map((finding) => finding.signal_type)).toEqual(["SHARED_DEVICE", "TXN_CYCLE"]);
    expect(report.findings[0].path).toEqual(["acct:A1", "dev:DEV-RING-1", "acct:A2"]);
    const toolEvidenceIds = new Set(["EV-005", "EV-006", "EV-007", "EV-011", "EV-012", "EV-013"]);
    expect(report.findings.every((finding) => finding.evidence_ids.every((id) => toolEvidenceIds.has(id)))).toBe(true);
    expect(report.limitations).toHaveLength(1);
    expect(report.evidence.map((item) => item.id)).toEqual(["EV-005"]);
    expect(report.band).toBe("urgent_review");
    expect(report.score).toBe(99.6);
    expect(report.graph.links.some((link) => link.label === "SENDS_TO")).toBe(true);
    expect(report.actions[0].case_id).toBe("CASE-12345678");
  });

  it("surfaces malformed backend report shapes as an error", () => {
    expect(() => normalizeBackendReport({ case_id: "CASE-ABC" })).toThrow("does not match its expected response shape");
  });
});
