"""Deterministic, synthetic GhostLink dataset generator. No real intelligence."""
from __future__ import annotations
import json, os, random
from datetime import datetime, timezone, timedelta
from pathlib import Path

NOW = datetime.fromisoformat(os.getenv("GHOSTLINK_NOW", "2026-10-01T00:00:00+00:00").replace("Z", "+00:00")).astimezone(timezone.utc)
DOC_IPS = {"trigger": "203.0.113.45", "public_wifi": "198.51.100.77", "family": "192.0.2.150", "stale": "192.0.2.88"}
def iso(dt): return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
def ts(dt): return int(dt.timestamp())
def generate_dataset(seed: int = 26001, normal_accounts: int = 300) -> dict:
    rng = random.Random(seed)
    accounts, ips, devices, txns, indicators, edges, cases, evidence = [], [], [], [], [], [], [], []
    def add_evidence(eid, tier, rel, when, source, relationship, subject_ids):
        evidence.append({"id":eid,"tier":tier,"reliability":rel,"ts":ts(when),"timestamp":iso(when),"source":source,"relationship":relationship,"subject_ids":subject_ids,"simulated":True})
        return eid
    def account(aid, created=None): accounts.append({"id":aid,"created_at_ts":ts(created or (NOW-timedelta(days=60)))}); return aid
    def ip(addr, kind="unknown", city=None): ips.append({"addr":addr,"city":city,"is_public_network":kind=="public_wifi","network_kind":kind}); return addr
    def device(did, typ="mobile"): devices.append({"id":did,"device_type":typ}); return did
    def observed(aid, addr, when, source="auth_logs", tier="OBSERVED", count=1):
        eid=f"EV-{len(evidence)+1:03d}"; add_evidence(eid,tier,0.92,when,source,f"acct:{aid} -[OBSERVED_FROM]-> ip:{addr}",[f"acct:{aid}",f"ip:{addr}"])
        edges.append({"type":"OBSERVED_FROM","from":aid,"to":addr,"first_seen_ts":ts(when),"last_seen_ts":ts(when),"count":count,"source":source,"tier":tier,"reliability":0.92,"evidence_id":eid})
    def uses(aid,did,when,source="device_auth",tier="OBSERVED"):
        eid=f"EV-{len(evidence)+1:03d}"; add_evidence(eid,tier,0.9,when,source,f"acct:{aid} -[USES_DEVICE]-> dev:{did}",[f"acct:{aid}",f"dev:{did}"])
        edges.append({"type":"USES_DEVICE","from":aid,"to":did,"first_seen_ts":ts(when),"last_seen_ts":ts(when),"source":source,"tier":tier,"reliability":0.9,"evidence_id":eid})
    def txn(tid, src, dst, amount, when):
        txns.append({"id":tid,"amount":amount,"ts":ts(when)})
        e1=f"EV-{len(evidence)+1:03d}"; add_evidence(e1,"OBSERVED",0.98,when,"simulated_ledger",f"acct:{src} -[INITIATED]-> txn:{tid}",[f"acct:{src}",f"txn:{tid}"])
        edges.append({"type":"INITIATED","from":src,"to":tid,"tier":"OBSERVED","reliability":0.98,"evidence_id":e1})
        e2=f"EV-{len(evidence)+1:03d}"; add_evidence(e2,"OBSERVED",0.98,when,"simulated_ledger",f"txn:{tid} -[SENDS_TO]-> acct:{dst}",[f"txn:{tid}",f"acct:{dst}"])
        edges.append({"type":"SENDS_TO","from":tid,"to":dst,"tier":"OBSERVED","reliability":0.98,"evidence_id":e2})
    # Required scenario entities
    for i in range(1,6): account(f"A{i}", NOW-timedelta(days=90-i))
    for addr,kind in [(DOC_IPS['trigger'],'unknown'),(DOC_IPS['public_wifi'],'public_wifi'),(DOC_IPS['family'],'residential'),(DOC_IPS['stale'],'unknown')]: ip(addr,kind)
    for d in ["DEV-RING-1","DEV-RING-2","DEV-FAM-1"]: device(d)
    # Ring and shared-device pattern; the cycle is a stronger, separate signal.
    t0=NOW-timedelta(hours=42)
    for aid in ["A1","A2","A3","A4"]: observed(aid,DOC_IPS['trigger'],t0+timedelta(minutes=int(aid[1])*3))
    for aid,did in [("A1","DEV-RING-1"),("A2","DEV-RING-1"),("A3","DEV-RING-1"),("A3","DEV-RING-2"),("A4","DEV-RING-2"),("A5","DEV-RING-2")]: uses(aid,did,t0+timedelta(hours=1))
    txn("TX-0001","A1","A2",500,t0)
    txn("TX-0002","A2","A3",480,t0+timedelta(hours=12))
    txn("TX-0003","A3","A1",450,t0+timedelta(hours=24))
    # Contradictory simulated feeds on trigger IP.
    indicators.extend([
      {"id":"TI-001","feed":"FEED-ALPHA","severity":"high","seen_at_ts":ts(NOW-timedelta(days=1)),"expires_at_ts":None,"reliability":0.9,"note":"SIMULATED: suspicious activity reported"},
      {"id":"TI-002","feed":"FEED-BETA","severity":"low","seen_at_ts":ts(NOW-timedelta(hours=12)),"expires_at_ts":None,"reliability":0.65,"note":"SIMULATED: no abuse seen; contradicts other feed"},
      {"id":"TI-003","feed":"FEED-ALPHA","severity":"high","seen_at_ts":ts(NOW-timedelta(days=400)),"expires_at_ts":None,"reliability":0.9,"note":"SIMULATED: deliberately stale flag"}
    ])
    edges.append({"type":"FLAGGED_BY","from":DOC_IPS['trigger'],"to":"TI-001","observed_ts":ts(NOW-timedelta(days=1)),"tier":"OBSERVED","reliability":0.9,"evidence_id":add_evidence(f"EV-{len(evidence)+1:03d}","OBSERVED",0.9,NOW-timedelta(days=1),"FEED-ALPHA",f"ip:{DOC_IPS['trigger']} -[FLAGGED_BY]-> ti:TI-001",[f"ip:{DOC_IPS['trigger']}","ti:TI-001"] )})
    edges.append({"type":"FLAGGED_BY","from":DOC_IPS['trigger'],"to":"TI-002","observed_ts":ts(NOW-timedelta(hours=12)),"tier":"OBSERVED","reliability":0.65,"evidence_id":add_evidence(f"EV-{len(evidence)+1:03d}","OBSERVED",0.65,NOW-timedelta(hours=12),"FEED-BETA",f"ip:{DOC_IPS['trigger']} -[FLAGGED_BY]-> ti:TI-002",[f"ip:{DOC_IPS['trigger']}","ti:TI-002"] )})
    edges.append({"type":"FLAGGED_BY","from":DOC_IPS['stale'],"to":"TI-003","observed_ts":ts(NOW-timedelta(days=400),"" ) if False else ts(NOW-timedelta(days=400)),"tier":"OBSERVED","reliability":0.9,"evidence_id":add_evidence(f"EV-{len(evidence)+1:03d}","OBSERVED",0.9,NOW-timedelta(days=400),"FEED-ALPHA",f"ip:{DOC_IPS['stale']} -[FLAGGED_BY]-> ti:TI-003",[f"ip:{DOC_IPS['stale']}","ti:TI-003"] )})
    # Public Wi-Fi decoy: ~60 accounts; sharing alone is not evidence of wrongdoing.
    iptime=NOW-timedelta(days=2)
    for i in range(1,61):
        aid=f"P{i:03d}"; account(aid,NOW-timedelta(days=rng.randint(20,250)))
        observed(aid,DOC_IPS['public_wifi'],iptime+timedelta(minutes=i),source="simulated_public_wifi_logs")
    # A2 also seen once on the public Wi-Fi IP, to make the decoy more realistic.
    observed("A2",DOC_IPS['public_wifi'],NOW-timedelta(days=3),source="simulated_public_wifi_logs")
    cases.append({"id":"case-publicwifi1","score":12,"band":"monitor","status":"CLOSED","created_at_ts":ts(NOW-timedelta(days=20)),"outcome":"FALSE_POSITIVE","summary":"Simulated prior public Wi-Fi false positive"})
    # Family device and residential IP, no transactions for F1-F3.
    for aid in ["F1","F2","F3"]:
        account(aid,NOW-timedelta(days=180)); observed(aid,DOC_IPS['family'],NOW-timedelta(days=10),source="simulated_home_router"); uses(aid,"DEV-FAM-1",NOW-timedelta(days=10),source="simulated_device_log")
    # Old-flag IP already added above; create 300 normal accounts with non-scenario IPs.
    normal_ips=[]
    for i in range(1,21):
        addr=f"192.0.2.{(i%200)+20}"
        if addr not in [x['addr'] for x in ips]: ip(addr,"residential" if i%3 else "unknown")
        normal_ips.append(addr)
    for i in range(1,normal_accounts+1):
        aid=f"N{i:03d}"; account(aid,NOW-timedelta(days=rng.randint(1,600)))
        addr=rng.choice(normal_ips); observed(aid,addr,NOW-timedelta(days=rng.randint(1,60)),source="simulated_auth_logs")
        if i%4==0:
            did=f"DEV-N-{i//4:03d}"; device(did,"mobile"); uses(aid,did,NOW-timedelta(days=rng.randint(1,60)),source="simulated_device_log")
    # Evidence and all data clearly disclose simulated nature.
    return {"simulated":True,"seed":seed,"generated_at":iso(NOW),"nodes":{"Account":accounts,"IP":ips,"Device":devices,"Txn":txns,"ThreatIndicator":indicators,"Case":cases,"Evidence":evidence},"edges":edges,"alerts":[{"id":"alert-trigger","ip":DOC_IPS['trigger'],"severity":"high","source":"FEED-ALPHA","timestamp":iso(NOW-timedelta(days=1)),"simulated":True},{"id":"alert-wifi","ip":DOC_IPS['public_wifi'],"severity":"medium","source":"SIMULATED","timestamp":iso(NOW-timedelta(days=2)),"simulated":True},{"id":"alert-stale","ip":DOC_IPS['stale'],"severity":"low","source":"FEED-ALPHA","timestamp":iso(NOW-timedelta(days=400)),"simulated":True},{"id":"alert-family","ip":DOC_IPS['family'],"severity":"low","source":"SIMULATED","timestamp":iso(NOW-timedelta(days=10)),"simulated":True}]}
def main():
    out=Path(__file__).parent/'fixtures'/'dataset.json'; out.parent.mkdir(parents=True,exist_ok=True)
    data=generate_dataset(); out.write_text(json.dumps(data,indent=2),encoding='utf-8')
    print(f"Wrote {out}: simulated={data['simulated']}; accounts={len(data['nodes']['Account'])}; txns={len(data['nodes']['Txn'])}; evidence={len(data['nodes']['Evidence'])}; edges={len(data['edges'])}")
if __name__=='__main__': main()
