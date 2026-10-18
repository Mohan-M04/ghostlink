from api.agent import (
    ToolCandidate,
    _collect_evidence,
    _policy_select,
    _remember_result,
)


def candidate(candidate_id, name):
    return ToolCandidate(candidate_id, name, {}, f"Check {name}.", [])


def test_policy_selects_only_available_tool():
    only_candidate = candidate("get_alert_context", "get_alert_context")

    assert _policy_select([only_candidate], {}) == "get_alert_context"


def test_policy_checks_past_cases_for_public_networks():
    candidates = [
        candidate("shared_devices:A1", "shared_devices"),
        candidate("past_cases", "past_cases"),
    ]

    selected = _policy_select(candidates, {"context": {"is_public_network": True}})

    assert selected == "past_cases"


def test_policy_explores_shared_devices_before_other_normal_network_checks():
    candidates = [
        candidate("shared_devices:A1", "shared_devices"),
        candidate("detect_cycles:A1", "detect_cycles"),
        candidate("past_cases", "past_cases"),
    ]

    selected = _policy_select(candidates, {"context": {}, "accounts": {"total_matching": 2}})

    assert selected == "shared_devices:A1"


def test_collect_evidence_accepts_only_simulated_ev_records():
    state = {"evidence_by_id": {}}
    result = {
        "evidence": [
            {"id": "EV-001", "simulated": True},
            {"id": "TI-001", "simulated": True},
            {"id": "EV-002", "simulated": False},
        ]
    }

    _collect_evidence(state, result)

    assert set(state["evidence_by_id"]) == {"EV-001"}


def test_accounts_tool_links_only_same_run_evidence():
    state = {
        "results": {},
        "evidence_by_id": {},
        "account_ids": [],
        "account_evidence_ids": [],
    }
    tool = ToolCandidate("accounts_on_ip", "accounts_on_ip", {}, "Resolve accounts.", [])
    result = {
        "data": {
            "total_matching": 1,
            "accounts": [{"id": "A1"}],
        },
        "evidence": [{"id": "EV-007", "simulated": True}],
    }

    _remember_result(state, tool, result)

    assert state["account_ids"] == ["A1"]
    assert state["account_evidence_ids"] == ["EV-007"]
