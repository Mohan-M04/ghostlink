"""Idempotent MERGE-based loader for generated synthetic data."""
import json
from pathlib import Path
from data.generate_dataset import generate_dataset
from graph.connection import connect_graph
from graph.schema import ensure_schema

def _query(graph, query, params=None):
    return graph.query(query, params or {})
def load_dataset(graph, dataset=None):
    dataset = dataset or generate_dataset()
    # MERGE by stable primary key; all dynamic values are parameters.
    node_queries = {
      "Account": ("MERGE (n:Account {id:$id}) SET n.created_at_ts=$created_at_ts", "id"),
      "IP": ("MERGE (n:IP {addr:$addr}) SET n.city=$city, n.is_public_network=$is_public_network, n.network_kind=$network_kind", "addr"),
      "Device": ("MERGE (n:Device {id:$id}) SET n.device_type=$device_type", "id"),
      "Txn": ("MERGE (n:Txn {id:$id}) SET n.amount=$amount, n.ts=$ts", "id"),
      "ThreatIndicator": ("MERGE (n:ThreatIndicator {id:$id}) SET n.feed=$feed, n.severity=$severity, n.seen_at_ts=$seen_at_ts, n.expires_at_ts=$expires_at_ts, n.reliability=$reliability, n.note=$note, n.simulated=true", "id"),
      "Case": ("MERGE (n:Case {id:$id}) SET n.score=$score, n.band=$band, n.status=$status, n.created_at_ts=$created_at_ts, n.outcome=$outcome, n.summary=$summary, n.simulated=true", "id"),
      "Evidence": ("MERGE (n:Evidence {id:$id}) SET n.tier=$tier, n.reliability=$reliability, n.ts=$ts, n.source=$source, n.relationship=$relationship, n.subject_ids=$subject_ids, n.simulated=true", "id"),
    }
    for label, rows in dataset["nodes"].items():
        query,_=node_queries[label]
        for row in rows: _query(graph,query,row)
    edge_queries = {
      "OBSERVED_FROM": "MATCH (a:Account {id:$from}),(b:IP {addr:$to}) MERGE (a)-[r:OBSERVED_FROM]->(b) SET r.first_seen_ts=$first_seen_ts,r.last_seen_ts=$last_seen_ts,r.count=$count,r.source=$source,r.tier=$tier,r.reliability=$reliability,r.evidence_id=$evidence_id",
      "USES_DEVICE": "MATCH (a:Account {id:$from}),(b:Device {id:$to}) MERGE (a)-[r:USES_DEVICE]->(b) SET r.first_seen_ts=$first_seen_ts,r.last_seen_ts=$last_seen_ts,r.source=$source,r.tier=$tier,r.reliability=$reliability,r.evidence_id=$evidence_id",
      "INITIATED": "MATCH (a:Account {id:$from}),(b:Txn {id:$to}) MERGE (a)-[r:INITIATED]->(b) SET r.tier=$tier,r.reliability=$reliability,r.evidence_id=$evidence_id",
      "SENDS_TO": "MATCH (a:Txn {id:$from}),(b:Account {id:$to}) MERGE (a)-[r:SENDS_TO]->(b) SET r.tier=$tier,r.reliability=$reliability,r.evidence_id=$evidence_id",
      "FLAGGED_BY": "MATCH (a:IP {addr:$from}),(b:ThreatIndicator {id:$to}) MERGE (a)-[r:FLAGGED_BY]->(b) SET r.observed_ts=$observed_ts,r.tier=$tier,r.reliability=$reliability,r.evidence_id=$evidence_id",
    }
    for edge in dataset["edges"]:
        q=edge_queries.get(edge["type"])
        if q: _query(graph,q,edge)
    # Add linked evidence for all existing entity/indicator relations based on subject IDs.
    for ev in dataset["nodes"]["Evidence"]:
        _query(graph,"MATCH (e:Evidence {id:$id}) WITH e UNWIND $subject_ids AS sid MATCH (n) WHERE (n:Account AND sid='acct:'+n.id) OR (n:IP AND sid='ip:'+n.addr) OR (n:Device AND sid='dev:'+n.id) OR (n:Txn AND sid='txn:'+n.id) OR (n:ThreatIndicator AND sid='ti:'+n.id) MERGE (e)-[:ABOUT]->(n)",ev)
    # Seeded past case association: connect public Wi-Fi prior case to the IP.
    _query(graph,"MATCH (c:Case {id:'case-publicwifi1'}),(ip:IP {addr:'198.51.100.77'}) MERGE (c)-[:ABOUT]->(ip)",{})
    counts={}
    for label in node_queries:
        try: counts[label]=graph.query(f"MATCH (n:{label}) RETURN count(n)").result_set[0][0]
        except Exception: counts[label]=None
    try: counts["relationships"]=graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    except Exception: counts["relationships"]=None
    return counts

def main():
    _,graph=connect_graph()
    print("Index results:",json.dumps(ensure_schema(graph),indent=2))
    print("Loaded counts:",json.dumps(load_dataset(graph),indent=2))
if __name__=="__main__": main()
