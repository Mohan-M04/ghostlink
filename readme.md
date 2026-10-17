# GhostLink — Mohan's Graph + MCP Module

**Contract:** GhostLink v1.0-draft. **Data:** synthetic only. No real threat intelligence is included.

## Ownership

This module owns the FalkorDB graph schema, deterministic data generator, idempotent loader, eight MCP tools, examples and graph tests. Inchara owns the agent/scoring/FastAPI layer; Jyothika owns the React UI.

## Dependency/API assumption

- Python 3.11 or newer.
- `FalkorDB` Python client, using `from falkordb import FalkorDB` and `graph.query(cypher, params, timeout=...)`.
- Official MCP Python SDK **v1.x** using `from mcp.server.fastmcp import FastMCP`; `requirements.txt` pins `mcp[cli]>=1.28,<2` because the current SDK v2 renamed `FastMCP` to `MCPServer` and moved its import path. References: [MCP Python SDK v1 docs](https://py.sdk.modelcontextprotocol.io/v1/) and [FalkorDB Python client docs](https://falkordb-py.readthedocs.io/en/stable/falkordb.html).

## Quick start (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

### Generate deterministic synthetic dataset

```powershell
python -m data.generate_dataset
```

This writes `data/fixtures/dataset.json`, including 300 normal accounts, the ring/cycle, public Wi-Fi decoy, family-device decoy, conflicting feeds and stale flag.

### Run offline tests

```powershell
python -m pytest -q
```

### Run FalkorDB locally

Install Docker Desktop and start it first:

```powershell
docker compose up -d
```

Wait for health:

```powershell
docker compose ps
```

Then set `.env` to `TOOL_MODE=mcp`, load data and initialize indexes:

```powershell
python -m graph.loader
```

### Start the MCP server

Mock mode is the safe default and needs no database:

```powershell
$env:TOOL_MODE='mock'
python -m mcp_server.server
```

For FalkorDB-backed tools, set `TOOL_MODE=mcp` after starting/loading FalkorDB. The default MCP transport is stdio. For local MCP Inspector experiments, set `MCP_TRANSPORT=streamable-http` and run the server; the SDK exposes its streamable HTTP endpoint. Do not expose it publicly without authentication/network controls.

## Graph schema

Nodes: `Account(id, created_at_ts)`, `IP(addr, city, is_public_network, network_kind)`, `Device(id, device_type)`, `Txn(id, amount, ts)`, `ThreatIndicator(id, feed, severity, seen_at_ts, expires_at_ts, reliability, note)`, `Case(id, score, band, status, created_at_ts, outcome, summary)`, `Evidence(id, tier, reliability, ts, source, relationship, subject_ids, simulated)`, and `Action(id, type, status, rationale, created_at_ts, decided_at_ts, decided_by)`.

Relationships: `OBSERVED_FROM`, `USES_DEVICE`, `INITIATED`, `SENDS_TO`, `FLAGGED_BY`, inferred `LINKED_TO`, `HAS_EVIDENCE`, `ABOUT`, and `PROPOSES`. Loader uses `MERGE` and stable IDs. Indexes are attempted for Account.id, IP.addr, Device.id, Txn.id/ts, ThreatIndicator.id, Evidence.id, Case.id, Action.id; unsupported/duplicate index responses are reported by `ensure_schema`.

## Tool names and contracts

1. `get_alert_context(ip)`
2. `accounts_on_ip(ip, since_days=30, max_nodes=50)`
3. `shared_devices(account_id, max_nodes=50)`
4. `find_paths(src, dst, max_hops=4)`
5. `detect_cycles(account_id, min_len=3, max_len=5, window_hours=72)`
6. `past_cases(entity_id)`
7. `open_case(summary, entity_ids, evidence_ids, score=null, band=null)`
8. `propose_action(case_id, action_type, rationale='')`

All tools return JSON envelope fields: `ok`, `tool`, `simulated`, `truncated`, `limits`, `data`, `evidence`, `error`. Tool examples for Inchara's mock adapter are in `data/fixtures/tool_examples.json`. The examples are explicitly illustrative, not outputs from a live DB.

## Useful Cypher queries

```cypher
MATCH (a:Account)-[r:OBSERVED_FROM]->(i:IP {addr:$ip})
WHERE r.last_seen_ts >= $cutoff
RETURN a.id, r.first_seen_ts, r.last_seen_ts, r.evidence_id
ORDER BY a.id LIMIT $limit;

MATCH (a:Account {id:$id})-[:USES_DEVICE]->(d:Device)<-[:USES_DEVICE]-(other:Account)
RETURN d.id, collect(DISTINCT other.id) AS accounts;

MATCH (a:Account)-[:INITIATED]->(t:Txn)-[:SENDS_TO]->(b:Account)
WHERE t.ts >= $cutoff
RETURN a.id, t.id, t.amount, t.ts, b.id LIMIT 2000;
```

## Evidence and safety

- Evidence IDs are stable `EV-001` style identifiers for the generated dataset.
- Node IDs in paths use `acct:`, `ip:`, `dev:`, `txn:`, and `ti:` prefixes.
- IPs are documentation-only ranges; every indicator is simulated.
- Shared public Wi-Fi, office networks, CGNAT, VPNs and family devices can create innocent links. Sharing an IP/device alone is not proof.
- `propose_action` only creates `PENDING_APPROVAL`. It does not deactivate/block/suspend accounts.
- Agent-supplied Cypher is never accepted. Query shapes are fixed and values parameterized; the hop bound is an integer validated to 1–4.

## Environment variables

See `.env.example`: `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_PASSWORD`, `GRAPH_NAME`, `HUB_DEGREE_THRESHOLD`, `QUERY_TIMEOUT_MS`, `GHOSTLINK_NOW`, `TOOL_MODE`. `TOOL_MODE=mock` is default; `TOOL_MODE=mcp` connects to FalkorDB.

## Test status

Run `python -m pytest -q`. Unit tests use deterministic mock data and do not require Docker. A live FalkorDB integration run must be done separately after Docker is running; do not claim it passed unless it has been run.
