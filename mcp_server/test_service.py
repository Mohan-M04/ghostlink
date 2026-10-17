"""Offline contract tests use the deterministic mock dataset; no DB needed."""
from mcp_server.service import ToolService
s=ToolService(mock=True)
def test_all_tool_envelopes():
    results=[s.get_alert_context('203.0.113.45'),s.accounts_on_ip('203.0.113.45'),s.shared_devices('A1'),s.find_paths('acct:A1','acct:A3'),s.detect_cycles('A1'),s.past_cases('ip:198.51.100.77'),s.open_case('Test case',['acct:A1'],[]),s.propose_action('case-publicwifi1','MANUAL_REVIEW')]
    for r in results:
        assert {'ok','tool','simulated','truncated','limits','data','evidence','error'} <= set(r)
        assert r['simulated'] is True

def test_invalid_input_and_limits():
    assert s.get_alert_context('not-an-ip')['error']['code']=='INVALID_INPUT'
    assert s.accounts_on_ip('203.0.113.45',since_days=999)['error']['code']=='INVALID_INPUT'
    assert s.shared_devices('A1',max_nodes=999)['error']['code']=='INVALID_INPUT'
    assert s.find_paths('acct:A1','acct:A2',max_hops=9)['error']['code']=='INVALID_INPUT'

def test_cycle_detects_ring():
    r=s.detect_cycles('A1',3,5,72)
    assert r['ok'] is True
    assert any(c['length']==3 for c in r['data']['cycles'])

def test_family_and_public_wifi_decoys():
    assert s.detect_cycles('F1')['data']['cycles']==[]
    r=s.get_alert_context('198.51.100.77')
    assert r['data']['is_public_network'] is True
    assert s.detect_cycles('P001')['data']['cycles']==[]

def test_stale_and_conflicting_flags():
    trigger=s.get_alert_context('203.0.113.45')['data']['indicators']
    assert {x['severity'] for x in trigger} >= {'high','low'}
    stale=s.get_alert_context('192.0.2.88')['data']['indicators']
    assert stale and stale[0]['id']=='TI-003'

def test_hub_metadata_and_pending_only_action():
    r=s.shared_devices('A1'); assert any('degree' in d and 'is_hub' in d for d in r['data']['devices'])
    c=s.open_case('Case for action',['acct:A1'],[]); cid=c['data']['case_id']
    a=s.propose_action(cid,'MANUAL_REVIEW'); assert a['data']['status']=='PENDING_APPROVAL'
    assert s.propose_action(cid,'DEACTIVATE_ACCOUNT')['error']['code']=='ACTION_NOT_ALLOWED'

def test_open_case_is_idempotent():
    a=s.open_case('Same',['acct:A1','acct:A2'],[]); b=s.open_case('Same',['acct:A2','acct:A1'],[])
    assert a['data']['case_id']==b['data']['case_id']
