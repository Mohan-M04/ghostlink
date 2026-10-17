"""Graph schema/index initialization for the ghostlink graph."""
SCHEMA_QUERIES = [
    "CREATE INDEX FOR (n:Account) ON (n.id)",
    "CREATE INDEX FOR (n:IP) ON (n.addr)",
    "CREATE INDEX FOR (n:Device) ON (n.id)",
    "CREATE INDEX FOR (n:Txn) ON (n.id)",
    "CREATE INDEX FOR (n:Txn) ON (n.ts)",
    "CREATE INDEX FOR (n:ThreatIndicator) ON (n.id)",
    "CREATE INDEX FOR (n:Evidence) ON (n.id)",
    "CREATE INDEX FOR (n:Case) ON (n.id)",
    "CREATE INDEX FOR (n:Action) ON (n.id)",
]
def ensure_schema(graph):
    """Create supported indexes; tolerate 'already exists' responses across versions."""
    results=[]
    for query in SCHEMA_QUERIES:
        try:
            graph.query(query)
            results.append({"query":query,"ok":True})
        except Exception as exc:
            # Index syntax/duplicate behavior varies by FalkorDB version; report rather than hide.
            if "already exists" in str(exc).lower() or "already indexed" in str(exc).lower():
                results.append({"query":query,"ok":True,"note":"already exists"})
            else:
                results.append({"query":query,"ok":False,"error":str(exc)})
    return results
