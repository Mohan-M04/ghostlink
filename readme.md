# GhostLink — Mohan's Graph + MCP Module

**Contract:** GhostLink v1.0-draft. **Data:** synthetic only. No real threat intelligence is included.

## Ownership

This module owns the FalkorDB graph schema, deterministic data generator, idempotent loader, eight MCP tools, examples and graph tests. Inchara owns the agent/scoring/FastAPI layer; Jyothika owns the React UI.

## Architecture

```mermaid
flowchart LR
    analyst["Analyst"]

    subgraph browser["Browser · React / Vite"]
        ui["Investigation workspace<br/>alerts · graph · evidence · trace · review"]
        adapter["Backend adapter<br/>normalizes completed JSON report"]
        ui <--> adapter
    end

    subgraph backend["Python backend · FastAPI :8000"]
        api["/alerts · /investigate<br/>request validation and report assembly"]
        agent["Bounded investigation agent<br/>tool loop · 12-call / 90-second limits"]
        policy["Deterministic safety policy"]
        validator["Candidate validation<br/>only currently allowed tool IDs"]
        score["Scoring and guardrails<br/>provisional priority, not guilt"]
        api --> agent
        agent --> policy
        agent --> validator
        agent --> score
    end

    gemini["Optional Gemini function-calling planner<br/>selects one supplied candidate only"]

    subgraph mcp["MCP boundary · Streamable HTTP :8001"]
        client["MCP client"]
        server["FastMCP server"]
        tools["Read tools<br/>alert context · accounts on IP · shared devices<br/>paths · cycles · past cases"]
        writes["Bounded write tools<br/>open case · propose action"]
        service["ToolService<br/>fixed, validated, parameterized graph queries"]
        client <--> server
        server --> tools
        server --> writes
        tools --> service
        writes --> service
    end

    graph[("FalkorDB<br/>synthetic accounts · IPs · devices · transactions<br/>evidence · cases · pending actions")]
    loader["Dataset generator / graph loader"]

    analyst --> ui
    adapter -->|"POST /investigate · JSON report"| api
    api -->|"completed report + explainable trace"| adapter
    agent -. "candidate list + observed run state" .-> gemini
    gemini -. "candidate ID only" .-> validator
    policy -. "fallback candidate ID" .-> validator
    validator --> client
    service <--> graph
    loader --> graph
    score --> agent
    writes -. "manual review only<br/>PENDING_APPROVAL" .-> graph
```

**Control and safety boundaries:** Gemini can choose only from the agent's current candidate list; it does not receive database credentials, issue Cypher, call MCP directly, or authorize an action. If Gemini is unavailable or returns an invalid choice, the deterministic policy selects a candidate. The backend validates the choice, applies bounded graph tools, and accepts evidence citations only when the evidence was returned during that investigation. Write tools are reserved for saving a case and proposing a human-review action; they do not block or deactivate accounts.

**Demo behavior:** `/investigate` returns a completed JSON report, including the agent's plan/tool-result trace. The React adapter turns that returned trace into UI steps after the response arrives; the current backend does not stream each step live.

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

### Start the MCP server and API

With FalkorDB running, copy `.env.example` to `.env`, set the graph connection
values if needed, then start the MCP server in one PowerShell window:

```powershell
$env:TOOL_MODE='mcp'
$env:MCP_TRANSPORT='streamable-http'
python -m mcp_server.server
```

The HTTP MCP endpoint listens on `http://127.0.0.1:8001/mcp`. In a second
PowerShell window, start the FastAPI backend:

```powershell
python -m uvicorn api.main:app --reload --port 8000
```

The API agent plans bounded graph queries through MCP, checks returned evidence,
then saves the case and (when supported by returned evidence) proposes only a
`PENDING_APPROVAL` manual-review action. If both Gemini settings are present,
Gemini function calling selects among the currently allowed graph tools; without
them the deterministic policy planner is used. Keep `GEMINI_API_KEY` in the
backend-only, git-ignored `.env` file and never put it in the frontend environment.
Do not expose the MCP server publicly without authentication/network controls.

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
