"""GhostLink MCP server. Assumption: MCP Python SDK v1.x FastMCP API (mcp>=1.28,<2)."""
import os
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp_server.service import ToolService
load_dotenv()
MODE=os.getenv('TOOL_MODE','mock').strip().lower()
service=ToolService(mock=(MODE=='mock'))
mcp=FastMCP('GhostLink MCP Server', json_response=True)
@mcp.tool()
def get_alert_context(ip: str) -> dict:
    """Return IP network context and associated simulated threat indicators."""
    return service.get_alert_context(ip)
@mcp.tool()
def accounts_on_ip(ip: str, since_days: int = 30, max_nodes: int = 50) -> dict:
    """List accounts observed on an IP within a bounded time window."""
    return service.accounts_on_ip(ip,since_days,max_nodes)
@mcp.tool()
def shared_devices(account_id: str, max_nodes: int = 50) -> dict:
    """Find devices shared by an account and other accounts, including hub metadata."""
    return service.shared_devices(account_id,max_nodes)
@mcp.tool()
def find_paths(src: str, dst: str, max_hops: int = 4) -> dict:
    """Find up to five bounded paths between prefixed graph node IDs."""
    return service.find_paths(src,dst,max_hops)
@mcp.tool()
def detect_cycles(account_id: str, min_len: int = 3, max_len: int = 5, window_hours: int = 72) -> dict:
    """Detect bounded circular transaction patterns in a time window."""
    return service.detect_cycles(account_id,min_len,max_len,window_hours)
@mcp.tool()
def past_cases(entity_id: str) -> dict:
    """Retrieve prior cases associated with a prefixed entity ID."""
    return service.past_cases(entity_id)
@mcp.tool()
def open_case(summary: str, entity_ids: list[str], evidence_ids: list[str], score: int | None = None, band: str | None = None) -> dict:
    """Create an idempotent case and link validated entities and evidence."""
    return service.open_case(summary,entity_ids,evidence_ids,score,band)
@mcp.tool()
def propose_action(case_id: str, action_type: str, rationale: str = '') -> dict:
    """Create a human-review proposal; never deactivate or block an account."""
    return service.propose_action(case_id,action_type,rationale)
if __name__=='__main__':
    transport=os.getenv('MCP_TRANSPORT','stdio')
    if transport=='streamable-http': mcp.run(transport='streamable-http')
    else: mcp.run(transport='stdio')
