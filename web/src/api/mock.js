const iso = (hoursAgo) => new Date(Date.parse("2026-10-01T00:00:00Z") - hoursAgo * 3600000).toISOString();

export const mockAlerts = [
  { id: "ALERT-001", ip: "203.0.113.45", severity: "high", source: "FEED-ALPHA", timestamp: iso(12), simulated: true },
  { id: "ALERT-002", ip: "198.51.100.77", severity: "medium", source: "FEED-ALPHA", timestamp: iso(30), simulated: true },
  { id: "ALERT-003", ip: "192.0.2.88", severity: "low", source: "FEED-ALPHA", timestamp: iso(400 * 24), simulated: true },
  { id: "ALERT-004", ip: "192.0.2.150", severity: "low", source: "FEED-BETA", timestamp: iso(7), simulated: true }
];

const evidence = (id, tier, source, relationship, subjectIds, timestamp = iso(6)) => ({
  id, tier, reliability: tier === "OBSERVED" ? 0.9 : 0.78, timestamp, source,
  relationship, subject_ids: subjectIds, simulated: true
});

const scenarios = {
  "203.0.113.45": {
    score: 71, band: "human_review", recommended_action: "Review the linked accounts and transaction cycle; do not take automated account action.",
    findings: [
      { id: "F-1", tier: "OBSERVED", signal_type: "IP_FLAG", claim: "A simulated indicator flags this documentation-range IP.", strength: 0.72, evidence_ids: ["EV-001"], path: ["ip:203.0.113.45"] },
      { id: "F-2", tier: "DERIVED", signal_type: "SHARED_DEVICE", claim: "Accounts A1–A3 share a device in the synthetic graph.", strength: 0.61, evidence_ids: ["EV-002", "EV-005", "EV-006"], path: ["acct:A1", "dev:DEV-RING-1", "acct:A2"] },
      { id: "F-3", tier: "OBSERVED", signal_type: "TXN_CYCLE", claim: "A three-account transaction cycle was returned within the scenario window.", strength: 0.67, evidence_ids: ["EV-003", "EV-007", "EV-008", "EV-013", "EV-014", "EV-015"], path: ["acct:A1", "txn:TX-0001", "acct:A2", "txn:TX-0002", "acct:A3", "txn:TX-0003", "acct:A1"] }
    ],
    evidence: [
      evidence("EV-001", "OBSERVED", "FEED-ALPHA", "ip:203.0.113.45 -[FLAGGED_BY]-> ti:TI-001", ["ip:203.0.113.45", "ti:TI-001"]),
      evidence("EV-004", "OBSERVED", "FEED-BETA", "ip:203.0.113.45 -[FLAGGED_BY]-> ti:TI-002", ["ip:203.0.113.45", "ti:TI-002"]),
      evidence("EV-002", "DERIVED", "auth_logs", "acct:A1 -[USES_DEVICE]-> dev:DEV-RING-1", ["acct:A1", "dev:DEV-RING-1"]),
      evidence("EV-005", "DERIVED", "auth_logs", "acct:A2 -[USES_DEVICE]-> dev:DEV-RING-1", ["acct:A2", "dev:DEV-RING-1"]),
      evidence("EV-006", "DERIVED", "auth_logs", "acct:A3 -[USES_DEVICE]-> dev:DEV-RING-1", ["acct:A3", "dev:DEV-RING-1"]),
      evidence("EV-003", "OBSERVED", "transaction_ledger", "acct:A1 -[INITIATED]-> txn:TX-0001", ["acct:A1", "txn:TX-0001"]),
      evidence("EV-007", "OBSERVED", "transaction_ledger", "txn:TX-0001 -[SENDS_TO]-> acct:A2", ["txn:TX-0001", "acct:A2"]),
      evidence("EV-008", "OBSERVED", "transaction_ledger", "acct:A2 -[INITIATED]-> txn:TX-0002", ["acct:A2", "txn:TX-0002"]),
      evidence("EV-013", "OBSERVED", "transaction_ledger", "txn:TX-0002 -[SENDS_TO]-> acct:A3", ["txn:TX-0002", "acct:A3"]),
      evidence("EV-014", "OBSERVED", "transaction_ledger", "acct:A3 -[INITIATED]-> txn:TX-0003", ["acct:A3", "txn:TX-0003"]),
      evidence("EV-015", "OBSERVED", "transaction_ledger", "txn:TX-0003 -[SENDS_TO]-> acct:A1", ["txn:TX-0003", "acct:A1"]),
      evidence("EV-009", "OBSERVED", "auth_logs", "acct:A1 -[OBSERVED_FROM]-> ip:203.0.113.45", ["acct:A1", "ip:203.0.113.45"]),
      evidence("EV-010", "OBSERVED", "auth_logs", "acct:A2 -[OBSERVED_FROM]-> ip:203.0.113.45", ["acct:A2", "ip:203.0.113.45"]),
      evidence("EV-011", "OBSERVED", "auth_logs", "acct:A3 -[OBSERVED_FROM]-> ip:203.0.113.45", ["acct:A3", "ip:203.0.113.45"]),
      evidence("EV-012", "OBSERVED", "auth_logs", "acct:A4 -[OBSERVED_FROM]-> ip:203.0.113.45", ["acct:A4", "ip:203.0.113.45"])
    ],
    graph: {
      nodes: [
        { id: "ip:203.0.113.45", type: "IP", label: "203.0.113.45", detail: "Simulated trigger IP; conflicting indicators returned.", decoy: false },
        { id: "acct:A1", type: "Account", label: "A1", detail: "Synthetic account in ring scenario.", decoy: false },
        { id: "acct:A2", type: "Account", label: "A2", detail: "Synthetic account in ring scenario.", decoy: false },
        { id: "acct:A3", type: "Account", label: "A3", detail: "Synthetic account in ring scenario.", decoy: false },
        { id: "acct:A4", type: "Account", label: "A4", detail: "Synthetic account in ring scenario.", decoy: false },
        { id: "dev:DEV-RING-1", type: "Device", label: "DEV-RING-1", detail: "Shared synthetic device.", decoy: false },
        { id: "txn:TX-0001", type: "Transaction", label: "TX-0001", detail: "Synthetic transaction.", decoy: false },
        { id: "txn:TX-0002", type: "Transaction", label: "TX-0002", detail: "Synthetic transaction.", decoy: false },
        { id: "txn:TX-0003", type: "Transaction", label: "TX-0003", detail: "Synthetic transaction.", decoy: false }
      ],
      links: [
        { source: "acct:A1", target: "ip:203.0.113.45", label: "OBSERVED_FROM", decoy: false },
        { source: "acct:A2", target: "ip:203.0.113.45", label: "OBSERVED_FROM", decoy: false },
        { source: "acct:A3", target: "ip:203.0.113.45", label: "OBSERVED_FROM", decoy: false },
        { source: "acct:A4", target: "ip:203.0.113.45", label: "OBSERVED_FROM", decoy: false },
        { source: "acct:A1", target: "dev:DEV-RING-1", label: "USES_DEVICE", decoy: false },
        { source: "acct:A2", target: "dev:DEV-RING-1", label: "USES_DEVICE", decoy: false },
        { source: "acct:A1", target: "txn:TX-0001", label: "INITIATED", decoy: false },
        { source: "txn:TX-0001", target: "acct:A2", label: "SENDS_TO", decoy: false },
        { source: "acct:A2", target: "txn:TX-0002", label: "INITIATED", decoy: false },
        { source: "txn:TX-0002", target: "acct:A3", label: "SENDS_TO", decoy: false },
        { source: "acct:A3", target: "txn:TX-0003", label: "INITIATED", decoy: false },
        { source: "txn:TX-0003", target: "acct:A1", label: "SENDS_TO", decoy: false }
      ]
    },
    guardrails: [{ code: "CONFLICTING_SOURCES", severity: "warn", message: "The simulated feeds disagree: TI-001 is high severity while TI-002 is low severity.", evidence_ids: ["EV-001", "EV-004"] }],
    penalties: [{ code: "CONFLICTING_SOURCES", points: 15, reason: "The simulated indicator feeds conflict." }],
    innocent_explanations: ["A shared device or network may have a legitimate explanation.", "An IP indicator may be stale or incorrect."],
    conflicts: ["FEED-ALPHA high and FEED-BETA low indicators disagree for the trigger IP."],
    limitations: ["Synthetic scenario; graph links do not establish intent or guilt."],
    check_next: ["Review the source and age of both indicators.", "Confirm the transaction cycle with an analyst."]
  },
  "198.51.100.77": {
    score: 0, band: "monitor", recommended_action: "Monitor only; shared public Wi-Fi is not evidence of account fraud.",
    findings: [{ id: "F-1", tier: "OBSERVED", signal_type: "IP_FLAG", claim: "The simulated network context identifies a shared public Wi-Fi IP.", strength: 0.2, evidence_ids: ["EV-101"], path: ["ip:198.51.100.77"] }],
    evidence: [
      evidence("EV-101", "OBSERVED", "network_inventory", "ip:198.51.100.77 is_public_network=true; network_kind=public_wifi", ["ip:198.51.100.77"]),
      evidence("EV-102", "OBSERVED", "auth_logs", "acct:P001 -[OBSERVED_FROM]-> ip:198.51.100.77", ["acct:P001", "ip:198.51.100.77"])
    ],
    graph: { nodes: [{ id: "ip:198.51.100.77", type: "IP", label: "198.51.100.77", detail: "Public Wi-Fi; high degree; simulated decoy.", decoy: true }, { id: "acct:P001", type: "Account", label: "P001", detail: "Synthetic account.", decoy: true }], links: [{ source: "acct:P001", target: "ip:198.51.100.77", label: "OBSERVED_FROM", decoy: true }] },
    guardrails: [{ code: "PUBLIC_NETWORK", severity: "warn", message: "Public Wi-Fi is a shared network and is not proof of fraud.", evidence_ids: ["EV-101"] }],
    penalties: [{ code: "PUBLIC_NETWORK", points: 25, reason: "The signal relies on a shared public Wi-Fi IP." }],
    innocent_explanations: ["Accounts may legitimately use public Wi-Fi."], conflicts: [], limitations: ["Only synthetic demo data is shown."], check_next: ["Do not infer wrongdoing from shared infrastructure."]
  },
  "192.0.2.88": {
    score: 0, band: "monitor", recommended_action: "Review indicator freshness before taking any further investigative step.",
    findings: [{ id: "F-1", tier: "OBSERVED", signal_type: "IP_FLAG", claim: "A simulated indicator was reported approximately 400 days before the scenario clock.", strength: 0.05, evidence_ids: ["EV-201"], path: ["ip:192.0.2.88"] }],
    evidence: [evidence("EV-201", "OBSERVED", "FEED-ALPHA", "ip:192.0.2.88 -[FLAGGED_BY]-> ti:TI-003", ["ip:192.0.2.88", "ti:TI-003"], iso(400 * 24))],
    graph: { nodes: [{ id: "ip:192.0.2.88", type: "IP", label: "192.0.2.88", detail: "Stale simulated indicator.", decoy: false }], links: [] },
    guardrails: [{ code: "STALE_INDICATOR", severity: "warn", message: "The indicator is older than 365 days.", evidence_ids: ["EV-201"] }],
    penalties: [{ code: "STALE_INDICATOR", points: 20, reason: "The simulated indicator is older than 365 days." }],
    innocent_explanations: ["The indicator may no longer be relevant."], conflicts: [], limitations: ["No current indicator validation is included."], check_next: ["Verify the indicator's expiry and current status."]
  },
  "192.0.2.150": {
    score: 16, band: "monitor", recommended_action: "No action is indicated; household device sharing can be benign.",
    findings: [{ id: "F-1", tier: "DERIVED", signal_type: "SHARED_DEVICE", claim: "Three synthetic family accounts share a device.", strength: 0.16, evidence_ids: ["EV-301", "EV-302", "EV-303"], path: ["acct:F1", "dev:DEV-FAM-1", "acct:F2"] }],
    evidence: [
      evidence("EV-301", "DERIVED", "auth_logs", "acct:F1 -[USES_DEVICE]-> dev:DEV-FAM-1", ["acct:F1", "dev:DEV-FAM-1"]),
      evidence("EV-302", "DERIVED", "auth_logs", "acct:F2 -[USES_DEVICE]-> dev:DEV-FAM-1", ["acct:F2", "dev:DEV-FAM-1"]),
      evidence("EV-303", "DERIVED", "auth_logs", "acct:F3 -[USES_DEVICE]-> dev:DEV-FAM-1", ["acct:F3", "dev:DEV-FAM-1"]),
      evidence("EV-304", "OBSERVED", "auth_logs", "acct:F1 -[OBSERVED_FROM]-> ip:192.0.2.150", ["acct:F1", "ip:192.0.2.150"])
    ],
    graph: { nodes: [{ id: "acct:F1", type: "Account", label: "F1", detail: "Synthetic family scenario.", decoy: false }, { id: "acct:F2", type: "Account", label: "F2", detail: "Synthetic family scenario.", decoy: false }, { id: "acct:F3", type: "Account", label: "F3", detail: "Synthetic family scenario.", decoy: false }, { id: "dev:DEV-FAM-1", type: "Device", label: "DEV-FAM-1", detail: "Shared synthetic household device.", decoy: false }, { id: "ip:192.0.2.150", type: "IP", label: "192.0.2.150", detail: "Residential scenario IP.", decoy: false }], links: [{ source: "acct:F1", target: "dev:DEV-FAM-1", label: "USES_DEVICE", decoy: false }, { source: "acct:F2", target: "dev:DEV-FAM-1", label: "USES_DEVICE", decoy: false }, { source: "acct:F3", target: "dev:DEV-FAM-1", label: "USES_DEVICE", decoy: false }, { source: "acct:F1", target: "ip:192.0.2.150", label: "OBSERVED_FROM", decoy: false }] },
    guardrails: [], innocent_explanations: ["Family or household members may share devices legitimately."], conflicts: [], limitations: ["No suspicious transaction activity in this scenario."], check_next: ["No escalation is suggested based on device sharing alone."]
  }
};

function scoreBreakdown(scenario) {
  const signalsByType = new Map();
  for (const finding of scenario.findings) {
    const current = signalsByType.get(finding.signal_type);
    if (!current || finding.strength > current.strength) {
      signalsByType.set(finding.signal_type, { type: finding.signal_type, strength: finding.strength, finding_ids: [finding.id] });
    }
  }
  const signals = [...signalsByType.values()];
  const [first = 0, second = 0, third = 0] = signals.map((item) => item.strength).sort((left, right) => right - left);
  const combinedRaw = first + 0.5 * second * (1 - first) + 0.25 * third * (1 - first);
  const penalties = scenario.penalties ?? [];
  let final = Math.max(0, Math.min(100, Math.round(combinedRaw * 100 - penalties.reduce((total, item) => total + item.points, 0))));
  const caps = [];
  if (signals.length === 1 && ["IP_FLAG", "SHARED_DEVICE"].includes(signals[0].type)) {
    caps.push({ code: "SINGLE_INFRA_SIGNAL", max_score: 39, reason: "Only one infrastructure signal is validated." });
  }
  if (!scenario.findings.some((finding) => finding.tier === "OBSERVED" || finding.tier === "DERIVED")) {
    caps.push({ code: "INFERRED_ONLY", max_score: 39, reason: "No observed or derived finding is present." });
  }
  for (const cap of caps) final = Math.min(final, cap.max_score);
  return { signals, combined_raw: combinedRaw, penalties, caps, final };
}

export function createMockReport(alert) {
  const scenario = scenarios[alert.ip] ?? scenarios["198.51.100.77"];
  const { penalties = [], ...reportData } = scenario;
  const breakdown = scoreBreakdown({ ...scenario, penalties });
  const band = breakdown.final >= 85 ? "urgent_review" : breakdown.final >= 70 ? "human_review" : breakdown.final >= 40 ? "investigate" : "monitor";
  return {
    case_id: `case-${alert.ip === "203.0.113.45" ? "ab12cd34" : alert.ip.replaceAll(".", "").slice(-8).toLowerCase()}`,
    simulated: true,
    created_at: iso(0),
    trigger: { ip: alert.ip, severity: alert.severity, source: alert.source, flagged_at: alert.timestamp, alert_id: alert.id },
    ...reportData,
    score: breakdown.final,
    band,
    disclaimer: "This score is a provisional prioritisation aid, not a probability of guilt.",
    score_breakdown: breakdown,
    actions: alert.ip === "203.0.113.45" ? [
      { id: "act-1a2b3c4d", case_id: "case-ab12cd34", type: "MANUAL_REVIEW", status: "PENDING_APPROVAL", payload: { entity_ids: ["acct:A1"], rationale: "Human analyst review only." }, created_at: iso(0), decided_at: null, decided_by: null },
      { id: "act-5e6f7a8b", case_id: "case-ab12cd34", type: "STEP_UP_VERIFICATION", status: "PENDING_APPROVAL", payload: { entity_ids: ["acct:A1"], rationale: "Request additional verification, subject to approval." }, created_at: iso(0), decided_at: null, decided_by: null }
    ] : [],
    trace: [], limits_hit: []
  };
}

export async function* mockInvestigate(alert, signal) {
  const ts = iso(0);
  const report = createMockReport(alert);
  const contextIds = report.evidence.filter((item) => item.relationship.includes("FLAGGED_BY") || item.relationship.includes("is_public_network")).map((item) => item.id);
  const accountIds = report.evidence.filter((item) => item.relationship.includes("OBSERVED_FROM")).map((item) => item.id);
  const deviceIds = report.findings.filter((item) => item.signal_type === "SHARED_DEVICE").flatMap((item) => item.evidence_ids);
  const cycleIds = report.findings.filter((item) => item.signal_type === "TXN_CYCLE").flatMap((item) => item.evidence_ids);
  yield { type: "started", seq: 1, ts, run_id: `mock-${alert.id}`, ip: alert.ip, limits: { max_steps: 12, max_tool_calls: 15, timeout_s: 60 }, simulated: true };
  const steps = [
    ["plan", "Review the trigger and retrieve graph context."],
    ["tool_call", "Request IP alert context.", "get_alert_context"],
    ["tool_result", "Received simulated indicator and network context.", "get_alert_context", true, contextIds],
    ["tool_call", "Find related accounts and shared devices.", "accounts_on_ip"],
    ["tool_result", "Graph tool returned linked synthetic entities.", "accounts_on_ip", true, accountIds],
    ["tool_call", "Inspect shared devices for related accounts.", "shared_devices"],
    ["tool_result", "Graph tool returned shared-device evidence.", "shared_devices", true, deviceIds],
    ["tool_call", "Check for transaction cycles.", "detect_cycles"],
    ["tool_result", "Graph tool returned transaction-cycle evidence.", "detect_cycles", true, cycleIds],
    ["score", "Calculate deterministic provisional prioritisation score."]
  ];
  let seq = 2;
  for (const [kind, message, tool = null, ok = null, evidence_ids = []] of steps) {
    if (signal?.aborted) throw new DOMException("The operation was aborted.", "AbortError");
    await new Promise((resolve) => setTimeout(resolve, 70));
    yield { type: "step", seq: seq++, ts: iso(0), kind, message, tool, args: null, ok, evidence_ids };
  }
  yield { type: "report", seq: seq++, ts: iso(0), report };
  yield { type: "done", seq, ts: iso(0), status: "complete", case_id: report.case_id };
}
