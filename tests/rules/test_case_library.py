"""Every scenario in cases/scenarios/index.json against its expected result.

Definition of done (docs/build-contract.md): the rules engine passes every hand-checked case in the library.

How expected results map to engine results:
    major / not_major / not_an_incident  -> exactly that
    depends, depends_on_gate, depends_on_human -> undetermined, with the deciding facts listed
    classify_overrun -> the overrun is classified (open question 8), not "not an incident"
"""

import pytest
from case_facts import AS_OF, CASES, build_facts, human, scenarios

from dora_agent.rules import Fact, classify

ALL = scenarios()
IDS = [s["scenario_id"] for s in ALL]
EXACT = {"major", "not_major", "not_an_incident"}
DEPENDS = {"depends", "depends_on_gate", "depends_on_human"}


def by_id(scenario_id):
    return next(s for s in ALL if s["scenario_id"] == scenario_id)


def test_every_scenario_has_a_fact_set():
    assert set(IDS) == set(CASES)


def test_every_expected_result_is_handled():
    assert {s["expected_result"] for s in ALL} <= EXACT | DEPENDS | {"classify_overrun"}


@pytest.mark.parametrize("scenario", ALL, ids=IDS)
def test_scenario_matches_expected_result(scenario):
    result = classify(build_facts(scenario), AS_OF)
    expected = scenario["expected_result"]
    if expected in EXACT:
        assert result.result == expected, f"{scenario['scenario_id']}: {result.summary}"
        if expected != "not_an_incident":
            assert result.missing == ()
    elif expected in DEPENDS:
        assert result.result == "undetermined", f"{scenario['scenario_id']}: {result.summary}"
        assert result.missing, "an undetermined result must say what is missing"
    else:  # classify_overrun
        assert result.overrun
        assert result.result != "not_an_incident"
        assert result.gate is not None


# ---------- the thresholds behind each result, as listed in the index "why" ----------


@pytest.mark.parametrize(
    "scenario_id, must_be_met",
    [
        ("C01", {"T1", "T2", "T3", "T6"}),
        ("C02", {"T2", "T3"}),
        ("C03", {"T3", "T4"}),
        ("C04", {"T2", "T3", "T6"}),
        ("C05", {"T2", "T3", "T4"}),
        ("C07", {"T2", "T3"}),
        ("C08", {"T2", "T3"}),
        ("C09", {"T2", "T3"}),
        ("C14", {"T2", "T3"}),
        ("C15", {"T2", "T3"}),
        ("C17-B", {"T3", "T4"}),
        ("N05", {"T2", "T6"}),
        ("B01", {"T1", "T3"}),
    ],
)
def test_thresholds_named_in_the_index_are_met(scenario_id, must_be_met):
    result = classify(build_facts(by_id(scenario_id)), AS_OF)
    assert must_be_met <= set(result.thresholds_met)


@pytest.mark.parametrize("scenario_id", ["C06", "C10", "C12"])
def test_attack_cases_are_major_through_t5b(scenario_id):
    result = classify(build_facts(by_id(scenario_id)), AS_OF)
    assert result.t5b.status == "met"
    assert "Art. 8(1)(a)" in result.summary


@pytest.mark.parametrize("scenario_id", ["C07", "C11", "C13"])
def test_supplier_breaches_are_not_t5b(scenario_id):
    # Open question 4.
    assert classify(build_facts(by_id(scenario_id)), AS_OF).t5b.status == "not_met"


def test_c08_ddos_is_not_t5b():
    assert classify(build_facts(by_id("C08")), AS_OF).t5b.status == "not_met"


def test_c10_duration_counts_from_the_log_time():
    # RTS-C Art. 3(1): logs show the start months before detection.
    result = classify(build_facts(by_id("C10")), AS_OF)
    t3a = next(c for c in result.other_thresholds[2].checks if c.check_id == "T3-a")
    assert t3a.measurement.start_basis == "earliest_log_at"


def test_c14_downtime_runs_until_the_backlog_is_cleared():
    result = classify(build_facts(by_id("C14")), AS_OF)
    t3b = next(c for c in result.other_thresholds[2].checks if c.check_id == "T3-b")
    assert t3b.measurement.end_basis == "backlog_cleared_at"


def test_n03_one_threshold_is_not_enough():
    result = classify(build_facts(by_id("N03")), AS_OF)
    assert result.thresholds_met == ("T3",)
    assert result.result == "not_major"


def test_n06_exactly_10_percent_is_not_met():
    result = classify(build_facts(by_id("N06")), AS_OF)
    t1a = next(c for c in result.other_thresholds[0].checks if c.check_id == "T1-a")
    assert t1a.status == "not_met"
    assert "40,000 of 400,000" in t1a.reason


@pytest.mark.parametrize("scenario_id", ["C17-A", "N01", "N04"])
def test_gate_fails(scenario_id):
    assert classify(build_facts(by_id(scenario_id)), AS_OF).gate.status == "not_met"


# ---------- "depends" cases: the right question, then the human's answer decides ----------


def test_c11_asks_only_about_the_gate_then_follows_the_answer():
    scenario = by_id("C11")
    open_result = classify(build_facts(scenario), AS_OF)
    assert open_result.missing == ("critical_or_important",)
    yes = classify(build_facts(scenario, {"critical_or_important": human(True)}), AS_OF)
    no = classify(build_facts(scenario, {"critical_or_important": human(False)}), AS_OF)
    assert (yes.result, no.result) == ("major", "not_major")


def test_c13_lists_what_is_missing_instead_of_guessing():
    result = classify(build_facts(by_id("C13")), AS_OF)
    assert "critical_or_important" in result.missing
    assert "affected_clients" in result.missing


def test_b03_waits_for_the_human_then_follows_the_answer():
    scenario = by_id("B03")
    waiting = classify(build_facts(scenario), AS_OF)
    assert "malicious_access" in waiting.missing
    assert "malicious_access" in waiting.pending_confirmations

    confirmed = {"malicious_access": Fact[bool](value=True, source="security_alerts", confirmed_by="test-human"),
                 "access_on_own_systems": human(True), "access_may_cause_data_loss": human(True)}
    assert classify(build_facts(scenario, confirmed), AS_OF).result == "major"
    # "No" rules out T5-b, but does not make it not major: the other thresholds are still unknown.
    denied = classify(build_facts(scenario, {"malicious_access": human(False)}), AS_OF)
    assert denied.t5b.status == "not_met"
    assert denied.result == "undetermined"
    assert "malicious_access" not in denied.missing


def test_c16b_overrun_is_measured_from_the_planned_end():
    result = classify(build_facts(by_id("C16-B")), AS_OF)
    t3b = next(c for c in result.other_thresholds[2].checks if c.check_id == "T3-b")
    assert t3b.status == "met"
    assert t3b.measurement.start_basis == "planned_window_end"
