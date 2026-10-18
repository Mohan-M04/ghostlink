from datetime import datetime, timezone
import json
from uuid import uuid4
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from api.graph import TOOLS, MODE, call_tool
from api.scoring import calculate_score
from api.guardrails import check_context

app = FastAPI(title="GhostLink Agent API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CASES = {}
ACTIONS = {}

class InvestigateRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=64)
    since_days: int = Field(default=30, ge=1, le=365)
    max_nodes: int = Field(default=50, ge=1, le=200)

@app.get("/health")
def health():
    return {
        "status": "ok",
        "mode": MODE,
        "simulated_data": True,
        "falkordb_connected": MODE != "mock"
    }

@app.get("/alerts")
def alerts():
    return [
        {
            "id": "ALERT-001",
            "ip": "203.0.113.45",
            "severity": "high",
            "label": "Simulated suspicious-ring scenario",
            "simulated": True
        },
        {
            "id": "ALERT-002",
            "ip": "198.51.100.77",
            "severity": "medium",
            "label": "Simulated shared-network scenario (Public Wi-Fi)",
            "simulated": True
        },
        {
            "id": "ALERT-003",
            "ip": "192.0.2.150",
            "severity": "low",
            "label": "Simulated family-device scenario",
            "simulated": True
        }
    ]

@app.post("/investigate")
def investigate(req: InvestigateRequest):
    trace = []
    def log_step(kind, message, tool=None, args=None, evidence_ids=None):
        trace.append({
            "seq": len(trace) + 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            "message": message,
            "tool": tool,
            "args": args or {},
            "ok": True,
            "evidence_ids": evidence_ids or []
        })

    log_step("plan", f"Autonomous Agent starting investigation for IP {req.ip}")
    
    # Step 1: Alert Context
    log_step("tool_call", "Querying threat feeds and IP metadata via FastMCP", "get_alert_context", {"ip": req.ip})
    ctx_res = call_tool("get_alert_context", req.ip)
    context = ctx_res["data"]
    ctx_eids = [e["id"] for e in ctx_res.get("evidence", [])]
    log_step("tool_result", f"Retrieved context: degree {context.get('degree')}, {len(context.get('indicators', []))} indicator(s)", "get_alert_context", evidence_ids=ctx_eids)

    # Step 2: Accounts on IP
    log_step("tool_call", f"Searching accounts observed on {req.ip}", "accounts_on_ip", {"ip": req.ip})
    accts_res = call_tool("accounts_on_ip", req.ip, req.since_days, req.max_nodes)
    accts_data = accts_res["data"]
    acct_list = accts_data.get("accounts", [])
    acct_ids = [a["id"] for a in acct_list]
    acct_eids = [a.get("evidence_id") for a in acct_list if a.get("evidence_id")]
    log_step("tool_result", f"Discovered {len(acct_ids)} accounts connected to IP", "accounts_on_ip", evidence_ids=acct_eids)

    shared_devs = {"devices": []}
    cycles_data = {"cycles": []}
    paths_data = {"paths": []}
    all_evidence = list(ctx_res.get("evidence", [])) + list(accts_res.get("evidence", []))

    # Step 3: Shared Devices & Multi-hop traversal
    if acct_ids:
        target_acct = acct_ids[0]
        log_step("tool_call", f"Inspecting shared hardware for Account {target_acct}", "shared_devices", {"account_id": target_acct})
        sd_res = call_tool("shared_devices", target_acct)
        shared_devs = sd_res["data"]
        all_evidence.extend(sd_res.get("evidence", []))
        log_step("tool_result", f"Found {len(shared_devs.get('devices', []))} shared devices", "shared_devices")

        # Step 4: Circular Transaction Cycle Detection
        log_step("tool_call", f"Analyzing graph for circular transfer cycles involving {target_acct}", "detect_cycles", {"account_id": target_acct})
        cy_res = call_tool("detect_cycles", target_acct)
        cycles_data = cy_res["data"]
        all_evidence.extend(cy_res.get("evidence", []))
        cycle_count = len(cycles_data.get("cycles", []))
        log_step("tool_result", f"Detected {cycle_count} circular transaction cycle(s)", "detect_cycles")

        # Step 5: Pathfinding between accounts
        if len(acct_ids) > 1:
            log_step("tool_call", f"Finding evidence path between acct:{acct_ids[0]} and acct:{acct_ids[1]}", "find_paths", {"src": f"acct:{acct_ids[0]}", "dst": f"acct:{acct_ids[1]}"})
            p_res = call_tool("find_paths", f"acct:{acct_ids[0]}", f"acct:{acct_ids[1]}", 4)
            paths_data = p_res["data"]
            all_evidence.extend(p_res.get("evidence", []))
            log_step("tool_result", f"Identified {len(paths_data.get('paths', []))} path(s)", "find_paths")

    # Step 6: Guardrails & Innocent Explanations
    log_step("guardrail", "Evaluating innocent explanations, public network status, and hub downweighting")
    gr_result = check_context(context, accts_data, shared_devs, cycles_data)

    # Formulate Signals
    signals = []
    findings = []
    if context.get("indicators"):
        best_ti = context["indicators"][0]
        str_val = float(best_ti.get("reliability", 0.7))
        signals.append({"type": "IP_FLAG", "strength": str_val})
        findings.append({
            "id": "F-1",
            "tier": "OBSERVED",
            "signal_type": "IP_FLAG",
            "claim": f"Simulated threat feed alert ({best_ti.get('feed')}) associated with {req.ip}",
            "strength": str_val,
            "evidence_ids": ctx_eids[:2],
            "path": [f"ip:{req.ip}"]
        })

    if shared_devs.get("devices"):
        signals.append({"type": "SHARED_DEVICE", "strength": 0.85})
        findings.append({
            "id": "F-2",
            "tier": "OBSERVED",
            "signal_type": "SHARED_DEVICE",
            "claim": f"Account {acct_ids[0]} shares device hardware with other accounts",
            "strength": 0.85,
            "evidence_ids": [e["id"] for e in all_evidence if "USES_DEVICE" in e.get("relationship", "")][:2],
            "path": [f"acct:{acct_ids[0]}"]
        })

    if cycles_data.get("cycles"):
        cy = cycles_data["cycles"][0]
        signals.append({"type": "TXN_CYCLE", "strength": 0.95})
        findings.append({
            "id": "F-3",
            "tier": "DERIVED",
            "signal_type": "TXN_CYCLE",
            "claim": f"Circular money transfer detected: {' -> '.join(cy.get('accounts', []))} within {cy.get('span_hours')}h",
            "strength": 0.95,
            "evidence_ids": cy.get("evidence_ids", [])[:3],
            "path": cy.get("accounts", [])
        })

    # Step 7: Deterministic Score Calculation
    log_step("score", "Executing deterministic Python scoring engine")
    score_out = calculate_score(signals, gr_result["penalties"], gr_result["caps"])

    # Step 8: Autonomous Decision & Human Review Action
    case_summary = f"Investigation of alert {req.ip}: band={score_out['band']}, score={score_out['score']}"
    linked_entities = [f"ip:{req.ip}"] + [f"acct:{a}" for a in acct_ids[:3]]
    linked_eids = list({e["id"] for e in all_evidence if e.get("id")})

    log_step("tool_call", "Opening investigation case in FalkorDB", "open_case")
    case_res = call_tool("open_case", case_summary, linked_entities, linked_eids[:5], score_out["score"], score_out["band"])
    case_id = case_res["data"]["case_id"]
    log_step("tool_result", f"Case created: {case_id}", "open_case")

    rec_action = score_out["recommended_action"]
    if rec_action not in ["MANUAL_REVIEW", "STEP_UP_VERIFICATION", "WATCHLIST", "ESCALATE_TO_ANALYST"]:
        rec_action = "MANUAL_REVIEW"

    log_step("tool_call", f"Proposing human-in-the-loop action: {rec_action}", "propose_action")
    act_res = call_tool("propose_action", case_id, rec_action, f"Agent proposed {rec_action} based on graph evidence.")
    action_data = act_res["data"]
    log_step("tool_result", f"Action created in PENDING_APPROVAL status: {action_data.get('action_id')}", "propose_action")

    # Build Graph Entities for React Visualizer
    nodes = [{"id": f"ip:{req.ip}", "type": "IP", "label": req.ip, "detail": f"Degree: {context.get('degree')}", "decoy": context.get("degree", 0) >= 25}]
    links = []

    for a in acct_list[:10]:
        aid = f"acct:{a['id']}"
        nodes.append({"id": aid, "type": "Account", "label": a["id"], "detail": "Account", "decoy": False})
        links.append({"source": aid, "target": f"ip:{req.ip}", "label": "OBSERVED_FROM", "decoy": False})

    for dev in shared_devs.get("devices", []):
        did = f"dev:{dev['id']}"
        nodes.append({"id": did, "type": "Device", "label": dev["id"], "detail": f"Degree: {dev.get('degree')}", "decoy": False})
        for da in dev.get("accounts", []):
            links.append({"source": f"acct:{da['id']}", "target": did, "label": "USES_DEVICE", "decoy": False})

    # Save to memory
    report = {
        "case_id": case_id,
        "simulated": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "trigger": {"ip": req.ip, "severity": "high", "source": "FEED-ALPHA"},
        "score": score_out["score"],
        "band": score_out["band"],
        "recommended_action": score_out["recommended_action"],
        "disclaimer": "This score is a provisional prioritisation aid, not a probability of guilt.",
        "findings": findings,
        "evidence": all_evidence[:15],
        "graph": {"nodes": nodes, "links": links},
        "score_breakdown": score_out["score_breakdown"],
        "guardrails": [p.get("reason") for p in gr_result["penalties"]],
        "innocent_explanations": gr_result["innocent_explanations"],
        "conflicts": gr_result["conflicts"],
        "limitations": [],
        "check_next": ["Review linked device hardware logs", "Verify user proof of address"],
        "actions": [action_data],
        "trace": trace,
        "limits_hit": []
    }
    
    CASES[case_id] = report
    ACTIONS[action_data["action_id"]] = action_data
    return report

@app.get("/case/{case_id}")
def get_case(case_id: str):
    if case_id in CASES:
        return CASES[case_id]
    raise HTTPException(status_code=404, detail="Case not found")

@app.post("/actions/{action_id}/approve")
def approve_action(action_id: str):
    if action_id in ACTIONS:
        ACTIONS[action_id]["status"] = "APPROVED"
        ACTIONS[action_id]["decided_at"] = datetime.now(timezone.utc).isoformat()
        ACTIONS[action_id]["decided_by"] = "Human Analyst (Investigator)"
        return ACTIONS[action_id]
    return {"action_id": action_id, "status": "APPROVED", "decided_by": "Human Analyst"}

@app.post("/actions/{action_id}/reject")
def reject_action(action_id: str):
    if action_id in ACTIONS:
        ACTIONS[action_id]["status"] = "REJECTED"
        ACTIONS[action_id]["decided_at"] = datetime.now(timezone.utc).isoformat()
        ACTIONS[action_id]["decided_by"] = "Human Analyst (Investigator)"
        return ACTIONS[action_id]
    return {"action_id": action_id, "status": "REJECTED", "decided_by": "Human Analyst"}
