import os
from dotenv import load_dotenv
from mcp_server.service import ToolService

load_dotenv()
MODE = os.getenv("TOOL_MODE", "mock").strip().lower()
service = ToolService(mock=(MODE == "mock"))

TOOLS = {
    "get_alert_context": service.get_alert_context,
    "accounts_on_ip": service.accounts_on_ip,
    "shared_devices": service.shared_devices,
    "find_paths": service.find_paths,
    "detect_cycles": service.detect_cycles,
    "past_cases": service.past_cases,
    "open_case": service.open_case,
    "propose_action": service.propose_action,
}

def call_tool(name, *args, **kwargs):
    if name not in TOOLS:
        raise ValueError(f"Unknown graph tool: {name}")
    result = TOOLS[name](<*args, **kwargs>)
    if not isinstance(result, dict):
        raise ValueError(f"{name} returned an invalid response")
    if not result.get("ok"):
        error = result.get("error") or {}
        message = error.get("message", "Graph tool failed")
        raise ValueError(f"{name}: {message}")
    return result
