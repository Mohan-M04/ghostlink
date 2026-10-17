from data.generate_dataset import generate_dataset

def test_dataset_is_deterministic_and_simulated():
    a=generate_dataset(seed=7,normal_accounts=300); b=generate_dataset(seed=7,normal_accounts=300)
    assert a==b
    assert a['simulated'] is True
    assert len([x for x in a['nodes']['Account'] if x['id'].startswith('N')])==300
    assert any(x['addr']=='203.0.113.45' for x in a['nodes']['IP'])
    assert any(x['addr']=='198.51.100.77' for x in a['nodes']['IP'])

def test_ring_cycle_and_decoys():
    d=generate_dataset()
    assert {e['from'] for e in d['edges'] if e['type']=='INITIATED'} >= {'A1','A2','A3'}
    tx={x['id']:x for x in d['nodes']['Txn']}
    assert {'TX-0001','TX-0002','TX-0003'} <= set(tx)
    fam={e['from'] for e in d['edges'] if e['type']=='USES_DEVICE' and e['to']=='DEV-FAM-1'}
    assert fam=={'F1','F2','F3'}
    assert not any(e['type']=='INITIATED' and e['from'] in fam for e in d['edges'])
    wifi={e['from'] for e in d['edges'] if e['type']=='OBSERVED_FROM' and e['to']=='198.51.100.77'}
    assert len(wifi)>=60

def test_conflicting_and_stale_indicators():
    d=generate_dataset(); by={x['id']:x for x in d['nodes']['ThreatIndicator']}
    assert by['TI-001']['severity']=='high' and by['TI-002']['severity']=='low'
    assert d['nodes']['ThreatIndicator'][-1]['seen_at_ts'] < d['nodes']['ThreatIndicator'][0]['seen_at_ts']
