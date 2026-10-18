import os
from dotenv import load_dotenv
from mcp_server.service import ToolService

load_dotenv()

MODE = os.getenv("TOOL_MODE", "mock").strip().lower()
service = ToolService(mock=(MODE == "mock"))


def call_tool(name, *args, **kwargs):
    """Call a graph tool and safely unwrap its response."""
    method = getattr(service, name, None)

    if method is None or name.startswith("_"):
        raise ValueError(f"Unknown graph tool: {name}")

    result = method(*args, **kwargs)

    if not isinstance(result, dict):
        raise ValueError(f"{name} returned an invalid response")

    if not result.get("ok"):
        error = result.get("error") or {}
        message = error.get("message", "Graph tool failed")
        raise ValueError(f"{name}: {message}")

    return {
        "data": result.get("data") or {},
        "evidence": result.get("evidence") or [],
        "simulated": result.get("simulated", True),
    }


TOOLS = {
    "get_alert_context": lambda ip: call_tool(
        "get_alert_context", ip
    ),
    "accounts_on_ip": lambda ip, since_days=30, max_nodes=50:
        call_tool("accounts_on_ip", ip, since_days, max_nodes),
    "shared_devices": lambda account_id, max_nodes=50:
        call_tool("shared_devices", account_id, max_nodes),
    "find_paths": lambda src, dst, max_hops=4:
        call_tool("find_paths", src, dst, max_hops),
    "detect_cycles": lambda account_id, min_len=3, max_len=5,
        window_hours=72:
        call_tool(
            "detect_cycles",
            account_id,
            min_len,
            max_len,
            window_hours,
        ),
    "past_cases": lambda entity_id: call_tool(
        "past_cases", entity_id
    ),
    "open_case": lambda summary, entity_ids, evidence_ids,
        score=None, band=None:
        call_tool(
            "open_case",
            summary,
            entity_ids,
            evidence_ids,
            score,
            band,
        ),
    "propose_action": lambda case_id, action_type, rationale="":
        call_tool("propose_action", case_id, action_type, rationale),
}