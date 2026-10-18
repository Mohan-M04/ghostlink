from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from api.graph import TOOLS, MODE
from api.scoring import calculate_score
from api.guardrails import check_context


app = FastAPI(title="GhostLink API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CASES = {}
ACTIONS = {}


class InvestigateRequest(BaseModel):
    ip: str = Field(min_length=3, max_length=64)
    since_days: int = Field(default=30, ge=1, le=365)
    max_nodes: int = Field(default=50, ge=1, le=200)


class Decision(BaseModel):
    decision: str


def run_tool(name, *args, **kwargs):
    """Call a tool and return its normalized data and evidence."""
    try:
        return TOOLS[name](*args, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def node_id(value, prefix):
    """Add a graph prefix only when one is not already present."""
    value = str(value)
    return value if value.startswith(prefix) else f"{prefix}{value}"


def evidence_ids(*results):
    """Collect only evidence IDs actually returned by graph tools."""
    found = []

    for result in results:
        for item in result.get("evidence", []):
            evidence_id = item.get("id")
            if evidence_id and evidence_id not in found:
                found.append(evidence_id)

    return found


@app.get("/health")
def health():
    return {
        "status": "ok",
        "mode": MODE,
        "simulated_data": True,
        "falkordb_connected": MODE != "mock",
    }


@app.get("/alerts")
def alerts():
    # Demo alerts only; these are not live threat-feed alerts.
    return [
        {
            "id": "ALERT-001",
            "ip": "203.0.113.45",
            "severity": "high",
            "label": "Simulated suspicious-ring scenario",
            "simulated": True,
        },
        {
            "id": "ALERT-002",
            "ip": "198.51.100.10",
            "severity": "medium",
            "label": "Simulated shared-network scenario",
            "simulated": True,
        },
    ]


@app.post("/investigate")
def investigate(req: InvestigateRequest):
    context_result = run_tool("get_alert_context", req.ip)
    accounts_result = run_tool(
        "accounts_on_ip", req.ip, req.since_days, req.max_nodes
    )

    context = context_result["data"]
    accounts = accounts_result["data"]
    account_list = accounts.get("accounts", [])
    account_ids = [item["id"] for item in account_list]

    shared_result = {"data": {}, "evidence": []}
    cycles_result = {"data": {}, "evidence": []}
    paths_result = {"data": {}, "evidence": []}

    if account_ids:
        first_id = account_ids[0]

        shared_result = run_tool(
            "shared_devices", first_id, req.max_nodes
        )
        cycles_result = run_tool("detect_cycles", first_id)

        if len(account_ids) > 1:
            paths_result = run_tool(
                "find_paths",
                node_id(account_ids[0], "acct:"),
                node_id(account_ids[-1], "acct:"),
                4,
            )

    shared = shared_result["data"]
    cycles = cycles_result["data"]
    paths = paths_result["data"]

    guard = check_context(context, accounts, cycles)

    indicators = context.get("indicators", [])
    devices = shared.get("devices", [])
    has_shared_device = any(
        len(device.get("accounts", [])) >= 2
        for device in devices
    )
    has_cycle = bool(cycles.get("cycles"))

    # These are investigation signals, not guilt probabilities.
    signals = {
        "ip_flag": max(
            (
                float(item.get("reliability", 0))
                for item in indicators
                if item.get("reliability") is not None
            ),
            default=0,
        ),
        "shared_device": 0.75 if has_shared_device else 0,
        "txn_cycle": 0.85 if has_cycle else 0,
    }

    score = calculate_score(signals, guard["penalties"])

    all_evidence = evidence_ids(
        context_result,
        accounts_result,
        shared_result,
        cycles_result,
        paths_result,
    )

    findings = []

    for item in indicators:
        findings.append({
            "tier": "OBSERVED",
            "claim": "The simulated graph service returned a threat indicator.",
            "evidence_ids": [
                item["id"]
            ] if item.get("id") else [],
            "source": item.get("source", "simulated_feed"),
        })

    for device in devices:
        linked_accounts = device.get("accounts", [])
        if len(linked_accounts) >= 2:
            findings.append({
                "tier": "DERIVED",
                "claim": (
                    "Multiple accounts are linked to the same device "
                    "in the queried synthetic graph."
                ),
                "device_id": device.get("id"),
                "evidence_ids": [
                    account["evidence_id"]
                    for account in linked_accounts
                    if account.get("evidence_id")
                ],
            })

    for cycle in cycles.get("cycles", []):
        findings.append({
            "tier": "DERIVED",
            "claim": (
                "A circular transaction pattern was returned "
                "by the queried synthetic graph."
            ),
            "evidence_ids": cycle.get("evidence_ids", []),
            "details": cycle,
        })

    # Create a real service case using validated graph entities
    # and evidence IDs returned by the tools.
    entity_ids = [node_id(req.ip, "ip:")]
    entity_ids.extend(
        node_id(account_id, "acct:")
        for account_id in account_ids[:req.max_nodes]
    )

    case_result = run_tool(
        "open_case",
        "Investigation of simulated IP alert " + req.ip,
        entity_ids,
        all_evidence,
        int(score["score"]),
        score["band"],
    )

    service_case = case_result["data"]
    service_case_id = service_case.get("case_id")

    action_type = "MANUAL_REVIEW"
    action_result = None

    if service_case_id:
        action_result = run_tool(
            "propose_action",
            service_case_id,
            action_type,
            "Review the evidence and innocent explanations before deciding.",
        )

    action_data = action_result["data"] if action_result else {}
    case_id = "CASE-" + uuid4().hex[:8].upper()
    action_id = "ACT-" + uuid4().hex[:8].upper()

    report = {
        "case_id": case_id,
        "service_case_id": service_case_id,
        "trigger": {
            "ip": req.ip,
            "simulated": True,
        },
        **score,
        "signals": signals,
        "findings": findings,
        "evidence_ids": all_evidence,
        "innocent_explanations": [
            "Public Wi-Fi, college networks, or carrier NAT can cause "
            "many unrelated accounts to share an IP.",
            "A shared device may have legitimate users.",
            "A graph pattern requires independent corroboration."
        ],
        "conflicts": [],
        "limitations": guard["notes"],
        "human_review_required": guard["human_review_required"],
        "check_next": [
            "Verify source freshness and provenance.",
            "Seek independent corroborating evidence.",
            "Review the case manually before taking action.",
        ],
        "actions": [{
            "id": action_id,
            "service_action_id": action_data.get("action_id"),
            "type": action_type,
            "status": action_data.get("status", "PENDING_APPROVAL"),
        }],
        "trace": [
            {"tool": "get_alert_context", "status": "ok"},
            {"tool": "accounts_on_ip", "status": "ok"},
            {"tool": "shared_devices", "status": "ok"},
            {"tool": "detect_cycles", "status": "ok"},
            {"tool": "find_paths", "status": "ok" if len(account_ids) > 1 else "skipped"},
            {"tool": "open_case", "status": "ok"},
            {"tool": "propose_action", "status": "ok" if action_result else "skipped"},
        ],
        "graph": {
            "accounts": accounts,
            "shared_devices": shared,
            "cycles": cycles,
            "paths": paths,
        },
        "simulated_data": True,
    }

    CASES[case_id] = report
    ACTIONS[action_id] = {
        "status": report["actions"][0]["status"],
        "case_id": case_id,
        "service_action_id": action_data.get("action_id"),
    }

    return report


@app.get("/case/{case_id}")
def get_case(case_id: str):
    if case_id not in CASES:
        raise HTTPException(status_code=404, detail="Case not found")
    return CASES[case_id]


def update_action(action_id, decision):
    action = ACTIONS.get(action_id)

    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action["status"] != "PENDING_APPROVAL":
        raise HTTPException(
            status_code=409,
            detail="Action is no longer pending",
        )

    action["status"] = (
        "APPROVED" if decision == "approve" else "REJECTED"
    )

    return {
        "action_id": action_id,
        "status": action["status"],
        "note": "Demo only; no account is blocked.",
    }


@app.post("/actions/{action_id}/approve")
def approve(action_id: str, req: Decision):
    if req.decision != "approve":
        raise HTTPException(
            status_code=400,
            detail="decision must be approve",
        )
    return update_action(action_id, "approve")


@app.post("/actions/{action_id}/reject")
def reject(action_id: str, req: Decision):
    if req.decision != "reject":
        raise HTTPException(
            status_code=400,
            detail="decision must be reject",
        )
    return update_action(action_id, "reject")