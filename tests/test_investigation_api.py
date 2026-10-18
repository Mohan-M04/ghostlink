from api.main import InvestigateRequest, alerts, investigate


def test_network_alert_points_to_existing_decoy_scenario(monkeypatch):
    monkeypatch.setattr("api.main.MODE", "mock")
    network_alert = next(item for item in alerts() if item["id"] == "ALERT-002")
    report = investigate(InvestigateRequest(ip=network_alert["ip"]))

    assert network_alert["ip"] == "198.51.100.77"
    assert report["signals"]["shared_device"] == 0
    assert report["signals"]["txn_cycle"] == 0
    assert report["score"] < 40
    assert report["findings"] == []
    assert any("public network" in note.lower() for note in report["limitations"])
    assert report["actions"][0]["status"] == "PENDING_APPROVAL"


def test_ring_alert_keeps_correlated_graph_findings(monkeypatch):
    monkeypatch.setattr("api.main.MODE", "mock")
    report = investigate(InvestigateRequest(ip="203.0.113.45"))

    assert report["signals"]["shared_device"] > 0
    assert report["signals"]["txn_cycle"] > 0
    assert len(report["findings"]) >= 2
