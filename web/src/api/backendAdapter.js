const evidenceIdPattern = /^EV-\d{3,}$/;

function idsFrom(value) {
  return Array.isArray(value) ? value.filter((id) => typeof id === "string" && evidenceIdPattern.test(id)) : [];
}

function graphFromBackend(raw, ip) {
  const nodes = new Map();
  const links = [];
  const addNode = (node) => nodes.set(node.id, { ...nodes.get(node.id), ...node });
  const addLink = (source, target, label, decoy = false) => {
    if (!links.some((link) => link.source === source && link.target === target && link.label === label)) {
      links.push({ source, target, label, decoy });
    }
  };

  if (ip) addNode({ id: `ip:${ip}`, type: "IP", label: ip, detail: "Trigger IP returned by the backend.", decoy: false });

  const accountData = raw.graph?.accounts;
  for (const account of accountData?.accounts ?? []) {
    const accountId = `acct:${account.id}`;
    addNode({ id: accountId, type: "Account", label: account.id, detail: `Observed ${account.count ?? 1} time(s); last seen ${account.last_seen ?? "not returned"}.`, decoy: false });
    if (accountData.ip) addLink(accountId, `ip:${accountData.ip}`, "OBSERVED_FROM");
  }

  for (const device of raw.graph?.shared_devices?.devices ?? []) {
    const deviceId = `dev:${device.id}`;
    addNode({ id: deviceId, type: "Device", label: device.id, detail: `${device.device_type ?? "Device type not returned"}; degree ${device.degree ?? "not returned"}.`, decoy: Boolean(device.is_hub) });
    for (const account of device.accounts ?? []) {
      const accountId = `acct:${account.id}`;
      addNode({ id: accountId, type: "Account", label: account.id, detail: "Account returned by the shared-device tool.", decoy: false });
      addLink(accountId, deviceId, "USES_DEVICE", Boolean(device.is_hub));
    }
  }

  for (const cycle of raw.graph?.cycles?.cycles ?? []) {
    for (const id of cycle.accounts ?? []) {
      const accountId = id.includes(":") ? id : `acct:${id}`;
      addNode({ id: accountId, type: "Account", label: accountId.split(":").at(-1), detail: "Account returned in a transaction cycle.", decoy: false });
    }
    for (const transaction of cycle.txns ?? []) {
      const transactionId = `txn:${transaction.id}`;
      const from = transaction.from?.includes(":") ? transaction.from : `acct:${transaction.from}`;
      const to = transaction.to?.includes(":") ? transaction.to : `acct:${transaction.to}`;
      addNode({ id: transactionId, type: "Transaction", label: transaction.id, detail: `Amount ${transaction.amount}; timestamp ${transaction.timestamp}.`, decoy: false });
      addNode({ id: from, type: "Account", label: from.split(":").at(-1), detail: "Account returned in a transaction cycle.", decoy: false });
      addNode({ id: to, type: "Account", label: to.split(":").at(-1), detail: "Account returned in a transaction cycle.", decoy: false });
      addLink(from, transactionId, "INITIATED");
      addLink(transactionId, to, "SENDS_TO");
    }
  }

  for (const path of raw.graph?.paths?.paths ?? []) {
    for (const node of path.nodes ?? []) {
      addNode({
        id: node.id,
        type: node.type,
        label: node.label ?? node.id,
        detail: `Returned on a bounded ${path.hops ?? "multi-hop"}-hop graph path.`,
        decoy: false
      });
    }
    for (const edge of path.edges ?? []) addLink(edge.from, edge.to, edge.type);
  }

  return { nodes: [...nodes.values()], links };
}

function pathForFinding(finding, raw) {
  if (finding.device_id) {
    const device = raw.graph?.shared_devices?.devices?.find((item) => item.id === finding.device_id);
    const accounts = device?.accounts ?? [];
    if (accounts.length > 1) return [`acct:${accounts[0].id}`, `dev:${device.id}`, `acct:${accounts[1].id}`];
  }
  const cycle = finding.details;
  if (Array.isArray(cycle?.txns) && cycle.txns.length) {
    const first = cycle.txns[0].from;
    const path = [first];
    for (const transaction of cycle.txns) path.push(`txn:${transaction.id}`, transaction.to);
    return path;
  }
  return [];
}

export function normalizeBackendReport(raw) {
  if (!raw || typeof raw !== "object" || !Array.isArray(raw.findings) || !Array.isArray(raw.evidence_ids)) {
    throw new Error("The backend returned a JSON report that does not match its expected response shape.");
  }

  const evidenceIds = new Set(idsFrom(raw.evidence_ids));
  const evidence = (Array.isArray(raw.evidence) ? raw.evidence : [])
    .filter((item) => evidenceIds.has(item.id) && item.simulated === true);
  const limitations = [...(raw.limitations ?? [])];
  const findings = [];
  let omittedUnsupportedFinding = false;

  for (const finding of raw.findings) {
    const validIds = idsFrom(finding.evidence_ids).filter((id) => evidenceIds.has(id));
    if (!validIds.length) {
      omittedUnsupportedFinding = true;
      continue;
    }
    const signalType = finding.device_id ? "SHARED_DEVICE" : finding.details ? "TXN_CYCLE" : "IP_FLAG";
    const signalKey = { IP_FLAG: "ip_flag", SHARED_DEVICE: "shared_device", TXN_CYCLE: "txn_cycle" }[signalType];
    findings.push({
      id: finding.id ?? `F-${findings.length + 1}`,
      tier: finding.tier,
      signal_type: signalType,
      claim: finding.claim,
      strength: raw.signals?.[signalKey],
      evidence_ids: validIds,
      path: pathForFinding(finding, raw)
    });
  }
  if (omittedUnsupportedFinding) {
    limitations.push("Backend findings were omitted because their citations were not valid evidence IDs returned by this investigation.");
  }

  const band = raw.band === "urgent_human_review" ? "urgent_review" : raw.band;
  const recommendation = {
    monitor: "Monitor the scenario for additional evidence.",
    investigate: "Continue investigating with independent corroborating evidence.",
    request_review: "Request review by a human analyst.",
    escalate_for_human_review: "Escalate to a human reviewer for assessment."
  }[raw.recommended_action] ?? raw.recommended_action;
  const actions = (raw.actions ?? []).map((action) => ({
    ...action,
    case_id: action.case_id ?? raw.case_id,
    payload: action.payload ?? {}
  }));

  return {
    case_id: raw.case_id,
    simulated: raw.simulated_data === true || raw.trigger?.simulated === true,
    created_at: raw.created_at,
    trigger: {
      ip: raw.trigger?.ip,
      severity: raw.trigger?.severity ?? null,
      source: raw.trigger?.source ?? null,
      flagged_at: raw.trigger?.flagged_at ?? null,
      alert_id: raw.trigger?.alert_id ?? null
    },
    score: raw.score,
    band,
    recommended_action: recommendation,
    disclaimer: "This score is a provisional prioritisation aid, not a probability of guilt.",
    findings,
    evidence,
    graph: graphFromBackend(raw, raw.trigger?.ip),
    score_breakdown: raw.score_breakdown,
    guardrails: raw.guardrails ?? [],
    innocent_explanations: raw.innocent_explanations ?? [],
    conflicts: raw.conflicts ?? [],
    limitations,
    check_next: raw.check_next ?? [],
    actions,
    trace: raw.trace ?? [],
    limits_hit: []
  };
}
