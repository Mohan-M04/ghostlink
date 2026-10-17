"""Graph-backed tool service. Inputs are validated before queries are constructed."""
import ipaddress, os, re, math, hashlib
from datetime import datetime, timezone
from graph.connection import connect_graph
from data.generate_dataset import generate_dataset

NODE_RE=re.compile(r"^(acct|ip|dev|txn|ti):[A-Za-z0-9_.:-]{1,64}$")
ACCOUNT_RE=re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ACTIONS={"MANUAL_REVIEW","STEP_UP_VERIFICATION","WATCHLIST","ESCALATE_TO_ANALYST"}

def _iso(epoch):
    if epoch is None: return None
    return datetime.fromtimestamp(int(epoch),timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
def _row_dict(row, keys): return {k:row[i] for i,k in enumerate(keys)}
def _props(node):
    try: return dict(node.properties)
    except Exception: return {}

class ToolService:
    def __init__(self, graph=None, mock=False):
        self.mock=mock; self.graph=graph; self.dataset=generate_dataset()
        self.evidence_by_id={e['id']:e for e in self.dataset['nodes']['Evidence']}
        self.actions={}; self.cases={c['id']:c for c in self.dataset['nodes']['Case']}
        if not mock and graph is None:
            _,self.graph=connect_graph()
    def _envelope(self,name,data=None,evidence=None,error=None,truncated=False):
        return {"ok":error is None,"tool":name,"simulated":True,"truncated":bool(truncated),"limits":{"max_nodes":50,"max_hops":4,"timeout_s":10},"data":data if error is None else None,"evidence":evidence or [],"error":error}
    def _error(self,name,code,message,details=None): return self._envelope(name,error={"code":code,"message":message,"details":details})
    def _validate_ip(self,ip):
        try: return str(ipaddress.ip_address(ip))
        except Exception: raise ValueError("ip must be a valid IPv4 or IPv6 address")
    def _validate_node(self,n):
        if not isinstance(n,str) or not NODE_RE.fullmatch(n): raise ValueError("node ID must use acct:, ip:, dev:, txn:, or ti: prefix")
    def _ev(self,eid):
        ev=self.evidence_by_id.get(eid)
        if not ev: return None
        return {"id":ev['id'],"tier":ev['tier'],"reliability":ev['reliability'],"timestamp":ev['timestamp'],"source":ev['source'],"relationship":ev['relationship'],"subject_ids":ev['subject_ids'],"simulated":True}
    def _result(self,name,data,eids=(),truncated=False):
        ev=[]
        for eid in dict.fromkeys(x for x in eids if x):
            item=self._ev(eid)
            if item: ev.append(item)
        return self._envelope(name,data,evidence=ev,truncated=truncated)
    def _q(self,q,params=None): return self.graph.query(q,params or {},timeout=int(os.getenv('QUERY_TIMEOUT_MS','5000')))
    def get_alert_context(self,ip):
        name='get_alert_context'
        try: ip=self._validate_ip(ip)
        except ValueError as e: return self._error(name,'INVALID_INPUT',str(e))
        try:
            if self.mock:
                d=next((x for x in self.dataset['nodes']['IP'] if x['addr']==ip),None)
                if not d: return self._error(name,'NOT_FOUND','IP not found')
                inds=[x for x in self.dataset['nodes']['ThreatIndicator'] if any(e['type']=='FLAGGED_BY' and e['from']==ip and e['to']==x['id'] for e in self.dataset['edges'])]
                degree=len({e['from'] for e in self.dataset['edges'] if e['type']=='OBSERVED_FROM' and e['to']==ip})
                times=[e['last_seen_ts'] for e in self.dataset['edges'] if e['type']=='OBSERVED_FROM' and e['to']==ip]
                data={"ip":ip,"city":d.get('city'),"is_public_network":d['is_public_network'],"network_kind":d['network_kind'],"degree":degree,"first_seen":_iso(min(times)) if times else None,"last_seen":_iso(max(times)) if times else None,"indicators":[{"id":i['id'],"feed":i['feed'],"severity":i['severity'],"seen_at":_iso(i['seen_at_ts']),"expires_at":_iso(i['expires_at_ts']),"reliability":i['reliability'],"note":i['note'],"note_is_untrusted":True} for i in inds]}
                eids=[e['evidence_id'] for e in self.dataset['edges'] if e['type']=='FLAGGED_BY' and e['from']==ip]
                return self._result(name,data,eids)
            rows=self._q("MATCH (i:IP {addr:$ip}) OPTIONAL MATCH (i)-[r:FLAGGED_BY]->(t:ThreatIndicator) WITH i,r,t OPTIONAL MATCH (a:Account)-[o:OBSERVED_FROM]->(i) RETURN i.city,i.is_public_network,i.network_kind,count(DISTINCT a) AS degree,min(o.first_seen_ts) AS first_seen,max(o.last_seen_ts) AS last_seen,collect({id:t.id,feed:t.feed,severity:t.severity,seen_at:t.seen_at_ts,expires_at:t.expires_at_ts,reliability:t.reliability,note:t.note,evidence_id:r.evidence_id}) AS inds", {"ip": ip})
            if not rows.result_set: return self._error(name,'NOT_FOUND','IP not found')
            r=rows.result_set[0]; inds=[]; eids=[]
            for i in r[6] or []:
                if i.get('id'):
                    inds.append({"id":i['id'],"feed":i.get('feed'),"severity":i.get('severity'),"seen_at":_iso(i.get('seen_at')),"expires_at":_iso(i.get('expires_at')),"reliability":i.get('reliability'),"note":i.get('note'),"note_is_untrusted":True}); eids.append(i.get('evidence_id'))
            return self._result(name,{"ip":ip,"city":r[0],"is_public_network":bool(r[1]),"network_kind":r[2],"degree":r[3] or 0,"first_seen":_iso(r[4]),"last_seen":_iso(r[5]),"indicators":inds},eids)
        except Exception as e: return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def accounts_on_ip(self,ip,since_days=30,max_nodes=50):
        name='accounts_on_ip'
        try:
            ip=self._validate_ip(ip)
            if not isinstance(since_days,int) or not 1<=since_days<=365: raise ValueError('since_days must be 1..365')
            if not isinstance(max_nodes,int) or not 1<=max_nodes<=200: raise ValueError('max_nodes must be 1..200')
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        now=int(datetime.fromisoformat(os.getenv('GHOSTLINK_NOW','2026-10-01T00:00:00Z').replace('Z','+00:00')).timestamp()); cutoff=now-since_days*86400
        try:
            if self.mock:
                matches=[]
                for e in self.dataset['edges']:
                    if e['type']=='OBSERVED_FROM' and e['to']==ip and e.get('last_seen_ts',0)>=cutoff:
                        a=next((x for x in self.dataset['nodes']['Account'] if x['id']==e['from']),None)
                        if a: matches.append({"id":a['id'],"created_at":_iso(a['created_at_ts']),"first_seen":_iso(e['first_seen_ts']),"last_seen":_iso(e['last_seen_ts']),"count":e.get('count',1),"evidence_id":e['evidence_id']})
                matches.sort(key=lambda x:x['id']); total=len(matches); out=matches[:max_nodes]
                return self._result(name,{"ip":ip,"total_matching":total,"returned":len(out),"accounts":out},[x['evidence_id'] for x in out],total>len(out))
            rows=self._q("MATCH (a:Account)-[r:OBSERVED_FROM]->(i:IP {addr:$ip}) WHERE r.last_seen_ts >= $cutoff RETURN a.id,a.created_at_ts,r.first_seen_ts,r.last_seen_ts,r.count,r.evidence_id ORDER BY a.id LIMIT $limit",{"ip":ip,"cutoff":cutoff,"limit":max_nodes+1}).result_set
            out=[{"id":r[0],"created_at":_iso(r[1]),"first_seen":_iso(r[2]),"last_seen":_iso(r[3]),"count":r[4] or 1,"evidence_id":r[5]} for r in rows[:max_nodes]]
            total=len(rows); return self._result(name,{"ip":ip,"total_matching":total,"returned":len(out),"accounts":out},[x['evidence_id'] for x in out],total>max_nodes)
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def shared_devices(self,account_id,max_nodes=50):
        name='shared_devices'
        try:
            if not isinstance(account_id,str) or not ACCOUNT_RE.fullmatch(account_id): raise ValueError('invalid account_id')
            if not isinstance(max_nodes,int) or not 1<=max_nodes<=200: raise ValueError('max_nodes must be 1..200')
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        threshold=int(os.getenv('HUB_DEGREE_THRESHOLD','25'))
        try:
            if self.mock:
                links=[e for e in self.dataset['edges'] if e['type']=='USES_DEVICE' and e['from']==account_id]; out=[]; eids=[]
                for l in links:
                    members=[e for e in self.dataset['edges'] if e['type']=='USES_DEVICE' and e['to']==l['to']]
                    accounts=sorted({e['from'] for e in members}); d=next(x for x in self.dataset['nodes']['Device'] if x['id']==l['to'])
                    acc=[{"id":a,"evidence_id":next(e['evidence_id'] for e in members if e['from']==a)} for a in accounts[:max_nodes]]
                    eids.extend(x['evidence_id'] for x in acc); out.append({"id":d['id'],"device_type":d['device_type'],"degree":len(accounts),"is_hub":len(accounts)>=threshold,"accounts":acc})
                return self._result(name,{"account_id":account_id,"devices":out},eids,any(len([e for e in self.dataset['edges'] if e['type']=='USES_DEVICE' and e['to']==x['id']])>max_nodes for x in out))
            rows=self._q("MATCH (a:Account {id:$id})-[r:USES_DEVICE]->(d:Device)<-[r2:USES_DEVICE]-(other:Account) WITH d,collect(DISTINCT {id:other.id,evidence_id:r2.evidence_id}) AS members,count(DISTINCT other) AS degree RETURN d.id,d.device_type,degree,members ORDER BY d.id",{"id":account_id}).result_set
            out=[]; eids=[]; truncated=False
            for r in rows:
                members=sorted(r[3] or [],key=lambda x:x['id']); truncated|=len(members)>max_nodes; members=members[:max_nodes]; eids.extend(x.get('evidence_id') for x in members)
                out.append({"id":r[0],"device_type":r[1],"degree":r[2],"is_hub":r[2]>=threshold,"accounts":members})
            return self._result(name,{"account_id":account_id,"devices":out},eids,truncated)
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def find_paths(self,src,dst,max_hops=4):
        name='find_paths'
        try:
            self._validate_node(src); self._validate_node(dst)
            if not isinstance(max_hops,int) or not 1<=max_hops<=4: raise ValueError('max_hops must be 1..4')
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        # The query shape is fixed; only a validated integer controls the hop bound.
        try:
            if self.mock:
                # Return deterministic direct paths from the synthetic edge list; never fabricate a path.
                adjacency={}
                for e in self.dataset['edges']:
                    a,b=self._edge_ids(e)
                    if a and b: adjacency.setdefault(a,[]).append((b,e)); adjacency.setdefault(b,[]).append((a,e))
                paths=[]; stack=[(src,[src],[])]
                while stack and len(paths)<5:
                    cur,nodes,edges=stack.pop()
                    if cur==dst and edges: paths.append((nodes,edges)); continue
                    if len(edges)>=max_hops: continue
                    for nxt,e in adjacency.get(cur,[]):
                        if nxt not in nodes: stack.append((nxt,nodes+[nxt],edges+[e]))
                paths.sort(key=lambda p:len(p[1])); formatted=[]; eids=[]
                for nodes,edges in paths[:5]:
                    nn=[]
                    for nid in nodes:
                        typ,label,degree=self._node_info(nid); nn.append({"id":nid,"type":typ,"label":label,"degree":degree})
                    ee=[]
                    for i,e in enumerate(edges):
                        a,b=self._edge_ids(e); ee.append({"from":nodes[i],"to":nodes[i+1],"type":e['type'],"tier":e.get('tier','OBSERVED'),"reliability":e.get('reliability',0.9),"evidence_id":e.get('evidence_id')}); eids.append(e.get('evidence_id'))
                    formatted.append({"hops":len(edges),"nodes":nn,"edges":ee})
                return self._result(name,{"src":src,"dst":dst,"paths":formatted},eids)
            # Use only supported node labels and validated IDs; relationship traversal is bounded.
            hops=int(max_hops)
            q=f"MATCH p=(s)-[*1..{hops}]-(t) WHERE (s.id=$srcraw OR s.addr=$srcraw) AND (t.id=$dstraw OR t.addr=$dstraw) RETURN p LIMIT 5"
            rows=self._q(q,{"srcraw":src.split(':',1)[1],"dstraw":dst.split(':',1)[1]}).result_set
            # Driver path object representations differ; return a safe, explicit empty result if serialization unavailable.
            paths=[]
            for row in rows:
                p=row[0]
                try:
                    nodes=p.nodes; rels=p.relationships
                    nn=[]
                    for n in nodes:
                        pr=_props(n); lab=getattr(n,'labels',[]); label=next(iter(lab),'Unknown'); raw=pr.get('id',pr.get('addr','?')); prefix={'Account':'acct','IP':'ip','Device':'dev','Txn':'txn','ThreatIndicator':'ti'}.get(label,'node'); nn.append({"id":f"{prefix}:{raw}","type":label,"label":str(raw),"degree":0})
                    ee=[]
                    for i,r in enumerate(rels):
                        rp=_props(r); typ=getattr(r,'relation',getattr(r,'type','RELATED_TO')); ee.append({"from":nn[i]['id'],"to":nn[i+1]['id'],"type":str(typ),"tier":rp.get('tier','OBSERVED'),"reliability":rp.get('reliability',0.9),"evidence_id":rp.get('evidence_id')})
                    paths.append({"hops":len(ee),"nodes":nn,"edges":ee})
                except Exception: continue
            return self._result(name,{"src":src,"dst":dst,"paths":paths},[e.get('evidence_id') for p in paths for e in p['edges']])
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def _edge_ids(self,e):
        t=e['type']; a=e['from']; b=e['to']
        return ({'OBSERVED_FROM':f'acct:{a}', 'USES_DEVICE':f'acct:{a}', 'INITIATED':f'acct:{a}', 'SENDS_TO':f'txn:{a}', 'FLAGGED_BY':f'ip:{a}'}.get(t), {'OBSERVED_FROM':f'ip:{b}', 'USES_DEVICE':f'dev:{b}', 'INITIATED':f'txn:{b}', 'SENDS_TO':f'acct:{b}', 'FLAGGED_BY':f'ti:{b}'}.get(t))
    def _node_info(self,nid):
        p,raw=nid.split(':',1); typ={'acct':'Account','ip':'IP','dev':'Device','txn':'Transaction','ti':'ThreatIndicator'}.get(p,'Unknown')
        degree=0
        if p=='ip': degree=len({e['from'] for e in self.dataset['edges'] if e['type']=='OBSERVED_FROM' and e['to']==raw})
        if p=='dev': degree=len({e['from'] for e in self.dataset['edges'] if e['type']=='USES_DEVICE' and e['to']==raw})
        return typ,raw,degree
    def detect_cycles(self,account_id,min_len=3,max_len=5,window_hours=72):
        name='detect_cycles'
        try:
            if not isinstance(account_id,str) or not ACCOUNT_RE.fullmatch(account_id): raise ValueError('invalid account_id')
            if not isinstance(min_len,int) or min_len<2 or not isinstance(max_len,int) or max_len>5 or min_len>max_len: raise ValueError('require 2 <= min_len <= max_len <= 5')
            if not isinstance(window_hours,int) or not 1<=window_hours<=720: raise ValueError('window_hours must be 1..720')
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        try:
            now=int(datetime.fromisoformat(os.getenv('GHOSTLINK_NOW','2026-10-01T00:00:00Z').replace('Z','+00:00')).timestamp()); cutoff=now-window_hours*3600
            if not self.mock:
                # Read transaction edges from graph; cycle assembly is performed in Python with bounded data.
                rows=self._q("MATCH (a:Account)-[r:INITIATED]->(t:Txn)-[s:SENDS_TO]->(b:Account) WHERE t.ts >= $cutoff RETURN a.id,t.id,t.amount,t.ts,r.evidence_id,s.evidence_id,b.id LIMIT 2000",{"cutoff":cutoff}).result_set
                txs=[{"from":r[0],"id":r[1],"amount":r[2],"ts":r[3],"evs":[r[4],r[5]],"to":r[6]} for r in rows]
            else:
                txs=[]
                for e in self.dataset['edges']:
                    if e['type']!='INITIATED': continue
                    tx=next((t for t in self.dataset['nodes']['Txn'] if t['id']==e['to']),None)
                    dest=next((x for x in self.dataset['edges'] if x['type']=='SENDS_TO' and x['from']==e['to']),None)
                    if tx and dest and tx['ts']>=cutoff: txs.append({"from":e['from'],"id":tx['id'],"amount":tx['amount'],"ts":tx['ts'],"evs":[e['evidence_id'],dest['evidence_id']],"to":dest['to']})
            adj={}
            for t in txs: adj.setdefault(t['from'],[]).append(t)
            cycles=[]
            def walk(start,cur,path,seen):
                if len(path)>=max_len:return
                for t in adj.get(cur,[]):
                    nxt=t['to']
                    if nxt==start and len(path)+1>=min_len:
                        cyc=path+[t]; stamps=[x['ts'] for x in cyc]; span=(max(stamps)-min(stamps))/3600
                        if span<=window_hours:
                            acc=[cyc[0]['from']]+[x['to'] for x in cyc]
                            cycles.append({"accounts":[f'acct:{x}' for x in acc[:-1]],"length":len(cyc),"span_hours":round(span,2),"txns":[{"id":x['id'],"from":f"acct:{x['from']}","to":f"acct:{x['to']}","amount":x['amount'],"timestamp":_iso(x['ts']),"evidence_id":x['evs'][0]} for x in cyc],"evidence_ids":[ev for x in cyc for ev in x['evs']]})
                    elif nxt not in seen and len(path)+1<max_len: walk(start,nxt,path+[t],seen|{nxt})
            walk(account_id,account_id,[],{account_id})
            unique=[]; seen_keys=set()
            for c in cycles:
                key=tuple(x['id'] for x in c['txns'])
                if key not in seen_keys: unique.append(c); seen_keys.add(key)
            unique=unique[:10]
            return self._result(name,{"account_id":account_id,"cycles":unique},[ev for c in unique for ev in c['evidence_ids']])
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def past_cases(self,entity_id):
        name='past_cases'
        try:self._validate_node(entity_id)
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        try:
            if self.mock:
                cases=[]
                for c in self.dataset['nodes']['Case']:
                    if entity_id=='ip:198.51.100.77': cases.append({"case_id":c['id'],"created_at":_iso(c['created_at_ts']),"band":c['band'],"status":c['status'],"outcome":c.get('outcome'),"summary":c.get('summary','')})
                return self._result(name,{"entity_id":entity_id,"cases":cases})
            raw=entity_id.split(':',1)[1]
            rows=self._q("MATCH (c:Case)-[:ABOUT]->(n) WHERE n.id=$raw OR n.addr=$raw RETURN c.id,c.created_at_ts,c.band,c.status,c.outcome,c.summary ORDER BY c.created_at_ts DESC LIMIT 50",{"raw":raw}).result_set
            cases=[{"case_id":r[0],"created_at":_iso(r[1]),"band":r[2],"status":r[3],"outcome":r[4],"summary":r[5] or ''} for r in rows]
            return self._result(name,{"entity_id":entity_id,"cases":cases})
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def open_case(self,summary,entity_ids,evidence_ids,score=None,band=None):
        name='open_case'
        try:
            if not isinstance(summary,str) or not summary.strip() or len(summary)>500: raise ValueError('summary must be 1..500 characters')
            if not isinstance(entity_ids,list) or not entity_ids or not isinstance(evidence_ids,list): raise ValueError('entity_ids must be a non-empty list and evidence_ids a list')
            for x in entity_ids:self._validate_node(x)
            if any(not isinstance(x,str) or not re.fullmatch(r'EV-\d{3,}',x) for x in evidence_ids): raise ValueError('invalid evidence ID')
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        case_id='case-'+hashlib.sha1((summary+'|'+'|'.join(sorted(entity_ids))).encode()).hexdigest()[:8]
        try:
            if self.mock:
                known_prefixes={'acct':'Account','ip':'IP','dev':'Device','txn':'Txn','ti':'ThreatIndicator'}
                for nid in entity_ids:
                    prefix,raw=nid.split(':',1); label=known_prefixes[prefix]
                    prop='addr' if label=='IP' else 'id'
                    if not any(item.get(prop)==raw for item in self.dataset['nodes'][label]):
                        return self._error(name,'NOT_FOUND',f'entity {nid} not found')
                for eid in evidence_ids:
                    if eid not in self.evidence_by_id:
                        return self._error(name,'NOT_FOUND',f'evidence {eid} not found')
                self.cases.setdefault(case_id,{"id":case_id,"status":"OPEN","score":score,"band":band,"summary":summary,"entity_ids":sorted(set(entity_ids)),"evidence_ids":sorted(set(evidence_ids))})
            else:
                for eid in evidence_ids:
                    found=self._q("MATCH (e:Evidence {id:$id}) RETURN count(e)",{"id":eid}).result_set
                    if not found or not found[0][0]: return self._error(name,'NOT_FOUND',f'evidence {eid} not found')
                for nid in entity_ids:
                    prefix,raw=nid.split(':',1); prop='addr' if prefix=='ip' else 'id'; label={'acct':'Account','ip':'IP','dev':'Device','txn':'Txn','ti':'ThreatIndicator'}[prefix]
                    found=self._q(f"MATCH (n:{label} {{{prop}:$raw}}) RETURN count(n)",{"raw":raw}).result_set
                    if not found or not found[0][0]: return self._error(name,'NOT_FOUND',f'entity {nid} not found')
                now=int(datetime.now(timezone.utc).timestamp())
                self._q("MERGE (c:Case {id:$id}) SET c.status='OPEN',c.score=$score,c.band=$band,c.summary=$summary,c.created_at_ts=$now,c.simulated=true",{"id":case_id,"score":score,"band":band,"summary":summary,"now":now})
                for nid in entity_ids:
                    prefix,raw=nid.split(':',1); label={'acct':'Account','ip':'IP','dev':'Device','txn':'Txn','ti':'ThreatIndicator'}[prefix]; prop='addr' if prefix=='ip' else 'id'
                    self._q(f"MATCH (c:Case {{id:$cid}}),(n:{label} {{{prop}:$raw}}) MERGE (c)-[:ABOUT]->(n)",{"cid":case_id,"raw":raw})
                for eid in evidence_ids:self._q("MATCH (c:Case {id:$cid}),(e:Evidence {id:$eid}) MERGE (c)-[:HAS_EVIDENCE]->(e)",{"cid":case_id,"eid":eid})
            c=self.cases.get(case_id,{})
            return self._result(name,{"case_id":case_id,"status":"OPEN","linked_entities":sorted(set(entity_ids)),"linked_evidence":sorted(set(evidence_ids))},evidence_ids)
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
    def propose_action(self,case_id,action_type,rationale=''):
        name='propose_action'
        try:
            if not isinstance(case_id,str) or not re.fullmatch(r'case-[A-Za-z0-9]{3,12}',case_id): raise ValueError('invalid case_id')
            if action_type not in ACTIONS: return self._error(name,'ACTION_NOT_ALLOWED','Unsupported action type')
            if not isinstance(rationale,str) or len(rationale)>500: raise ValueError('rationale must be at most 500 characters')
        except ValueError as e:return self._error(name,'INVALID_INPUT',str(e))
        if self.mock and case_id not in self.cases:return self._error(name,'NOT_FOUND','Case not found')
        action_id='act-'+hashlib.sha1(f'{case_id}|{action_type}|{rationale}'.encode()).hexdigest()[:8]
        try:
            if self.mock:self.actions.setdefault(action_id,{"id":action_id,"case_id":case_id,"type":action_type,"status":"PENDING_APPROVAL","rationale":rationale,"created_at_ts":int(datetime.now(timezone.utc).timestamp()),"decided_at_ts":None,"decided_by":None})
            else:
                found=self._q("MATCH (c:Case {id:$id}) RETURN count(c)",{"id":case_id}).result_set
                if not found or not found[0][0]: return self._error(name,'NOT_FOUND','Case not found')
                now=int(datetime.now(timezone.utc).timestamp())
                self._q("MERGE (a:Action {id:$id}) SET a.type=$type,a.status='PENDING_APPROVAL',a.rationale=$rationale,a.created_at_ts=$now,a.decided_at_ts=null,a.decided_by=null,a.simulated=true WITH a MATCH (c:Case {id:$cid}) MERGE (c)-[:PROPOSES]->(a)",{"id":action_id,"type":action_type,"rationale":rationale,"now":now,"cid":case_id})
            return self._result(name,{"action_id":action_id,"case_id":case_id,"type":action_type,"status":"PENDING_APPROVAL","rationale":rationale})
        except Exception as e:return self._error(name,'DB_UNAVAILABLE' if not self.mock else 'INTERNAL',str(e))
