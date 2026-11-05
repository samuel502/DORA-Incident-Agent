"""The major rule (docs/dora-rules.md section 1, RTS-C Art. 8(1)) and step 0 (DORA Art. 3(8), open questions 5, 8).

major = gate AND (T5-b OR at least 2 of T1, T2, T3, T4, T5-a, T6)
"""

from datetime import datetime, timedelta, timezone

import pytest

from dora_agent.rules import RULE_VERSION, Fact, IncidentFacts, classify

UTC = timezone.utc
AS_OF = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
START = datetime(2026, 5, 26, 7, 0, tzinfo=UTC)


def human(value):
    if isinstance(value, bool):
        return Fact[bool](value=value, source="human", confirmed_by="Sam")
    return Fact[int](value=value, source="human", confirmed_by="Sam")


def sys(value, source="client_data"):
    if isinstance(value, bool):
        return Fact[bool](value=value, source=source)
    if isinstance(value, datetime):
        return Fact[datetime](value=value, source=source)
    if isinstance(value, tuple):
        return Fact[tuple[str, ...]](value=value, source=source)
    return Fact[int](value=value, source=source)


# Building blocks: each sets one threshold to met or not met, with every point answered.

GATE_MET = dict(critical_or_important=sys(True, "service_list"))
GATE_NOT_MET = dict(critical_or_important=sys(False, "service_list"), regulated_service=sys(False, "service_list"),
                    malicious_access=human(False))
NO_T5B = dict(malicious_access=human(False))


def t1(met):
    return dict(affected_clients=sys(150_000 if met else 1_000), total_clients=sys(1_000_000),
                affected_counterparts=sys(0), affected_tx_count=sys(0), affected_tx_value_eur=sys(0),
                relevant_parties_affected=human(False))


def t2(met):
    return dict(media_coverage=human(met), repeated_complaints=human(False),
                regulatory_requirements_impact=human(False), client_loss_impact=human(False))


def t3(met):
    end = START + (timedelta(hours=3) if met else timedelta(minutes=40))
    return dict(incident_start=sys(START, "monitoring"), resolved_at=sys(end, "monitoring"),
                downtime_start=sys(START, "monitoring"), service_restored_at=sys(end, "monitoring"))


def t4(met):
    return dict(affected_member_states=sys(("DE", "AT") if met else ("DE",)))


def t5a(met):
    return dict(data_availability_impact=human(False), data_authenticity_impact=human(False),
                data_integrity_impact=human(met), data_confidentiality_impact=human(False),
                data_impact_adverse=human(True))


def t6(met):
    return dict(costs_eur=human(150_000 if met else 5_000))


def facts(*parts):
    merged = {}
    for part in parts:
        merged.update(part)
    return IncidentFacts(**merged)


def all_others(met_ids=()):
    builders = {"T1": t1, "T2": t2, "T3": t3, "T4": t4, "T5-a": t5a, "T6": t6}
    return [builder(name in met_ids) for name, builder in builders.items()]


# ---------- section 1: the major rule ----------


def test_gate_plus_two_thresholds_is_major():
    result = classify(facts(GATE_MET, NO_T5B, *all_others({"T2", "T6"})), AS_OF)
    assert result.result == "major"
    assert result.thresholds_met == ("T2", "T6")
    assert "RTS-C Art. 8(1)(b)" in result.summary


def test_gate_plus_one_threshold_is_not_major():
    # N03: the "any single threshold" trap.
    result = classify(facts(GATE_MET, NO_T5B, *all_others({"T3"})), AS_OF)
    assert result.result == "not_major"
    assert result.thresholds_met == ("T3",)
    assert result.missing == ()


def test_gate_plus_zero_thresholds_is_not_major():
    # N02.
    assert classify(facts(GATE_MET, NO_T5B, *all_others()), AS_OF).result == "not_major"


def test_gate_not_passed_beats_every_threshold():
    result = classify(facts(GATE_NOT_MET, *all_others({"T1", "T2", "T3", "T4", "T5-a", "T6"})), AS_OF)
    assert result.result == "not_major"
    assert "gate is not passed" in result.summary


@pytest.mark.parametrize("pair", [("T1", "T2"), ("T3", "T4"), ("T5-a", "T6"), ("T1", "T6"), ("T2", "T3")])
def test_any_two_other_thresholds_make_it_major(pair):
    assert classify(facts(GATE_MET, NO_T5B, *all_others(set(pair))), AS_OF).result == "major"


def test_t5b_alone_is_major_and_passes_the_gate_through_g_c():
    # C06, C10, C12: malicious access on the bank's own systems. G-c passes the gate even if
    # the service itself is not critical or regulated.
    attack = dict(malicious_access=human(True), access_on_own_systems=human(True),
                  access_may_cause_data_loss=human(True),
                  critical_or_important=sys(False, "service_list"), regulated_service=sys(False, "service_list"))
    result = classify(facts(*all_others(), attack), AS_OF)
    assert result.result == "major"
    assert result.thresholds_met == ()
    assert "RTS-C Art. 8(1)(a)" in result.summary


def test_supplier_breach_is_not_t5b_and_other_criteria_decide():
    # Open question 4 (C11 shape): supplier's systems breached, gate via critical service, T1 and T2 met.
    breach = dict(malicious_access=human(True), access_on_own_systems=human(False))
    result = classify(facts(GATE_MET, *all_others({"T1", "T2"}), breach), AS_OF)
    assert result.result == "major"
    assert result.t5b.status == "not_met"
    assert result.thresholds_met == ("T1", "T2")


def test_several_points_of_one_threshold_still_count_once():
    # Open question 1: T1-a and T1-b both met is still only one threshold.
    many_t1 = dict(affected_clients=sys(500_000), total_clients=sys(1_000_000))
    result = classify(facts(GATE_MET, NO_T5B, *all_others(), many_t1), AS_OF)
    assert result.thresholds_met == ("T1",)
    assert result.result == "not_major"


# ---------- unknown facts: undetermined, never guessed (section 7) ----------


def test_nothing_known_is_undetermined():
    result = classify(IncidentFacts(), AS_OF)
    assert result.result == "undetermined"
    assert "critical_or_important" in result.missing
    assert "Nothing has been guessed" in result.summary


def test_one_met_and_one_unknown_is_undetermined_and_names_the_unknown():
    parts = all_others({"T3"})
    parts[5] = {}  # T6 unknown
    result = classify(facts(GATE_MET, NO_T5B, *parts), AS_OF)
    assert result.result == "undetermined"
    assert result.missing == ("costs_eur",)


def test_two_met_is_major_even_with_unknowns_left():
    parts = all_others({"T2", "T3"})
    parts[0] = parts[3] = parts[5] = {}  # T1, T4, T6 unknown
    assert classify(facts(GATE_MET, NO_T5B, *parts), AS_OF).result == "major"


def test_zero_met_and_one_unknown_is_already_not_major():
    # Even if the unknown threshold were met, one is not enough.
    parts = all_others()
    parts[5] = {}
    result = classify(facts(GATE_MET, NO_T5B, *parts), AS_OF)
    assert result.result == "not_major"
    assert result.missing == ()


def test_gate_unknown_with_two_met_asks_only_about_the_gate():
    # C11: T1 and T2 met, gate unclear. The precise question is about the gate, nothing else.
    gate_open = dict(critical_or_important=Fact[bool](value=True, source="ai_suggestion"),
                     regulated_service=sys(False, "service_list"),
                     malicious_access=human(True), access_on_own_systems=human(False))
    result = classify(facts(*all_others({"T1", "T2"}), gate_open), AS_OF)
    assert result.result == "undetermined"
    assert result.missing == ("critical_or_important",)
    assert result.pending_confirmations == ("critical_or_important",)


def test_gate_not_met_makes_unknowns_irrelevant():
    result = classify(facts(GATE_NOT_MET), AS_OF)
    assert result.result == "not_major"
    assert result.missing == ()


def test_unconfirmed_t5b_is_undetermined_then_decided_by_the_human():
    # B03: SOC flags a large transfer. Major only if a human confirms successful malicious access.
    base = dict(critical_or_important=sys(True, "service_list"), access_on_own_systems=human(True),
                access_may_cause_data_loss=human(True))
    flagged = classify(facts(*all_others(), base,
                             dict(malicious_access=Fact[bool](value=True, source="security_alerts"))), AS_OF)
    assert flagged.result == "undetermined"
    assert flagged.missing == ("malicious_access",)
    assert flagged.pending_confirmations == ("malicious_access",)

    confirmed_yes = classify(facts(*all_others(), base, dict(malicious_access=Fact[bool](
        value=True, source="security_alerts", confirmed_by="Sam"))), AS_OF)
    assert confirmed_yes.result == "major"

    confirmed_no = classify(facts(*all_others(), base, dict(malicious_access=human(False))), AS_OF)
    assert confirmed_no.result == "not_major"


# ---------- step 0: planned or not (DORA Art. 3(8), open questions 5 and 8) ----------

WINDOW_START = datetime(2026, 9, 12, 16, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)
LATER = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def window(restored, resolved, planned=human(True)):
    return dict(
        planned_and_announced=planned, planned_window_end=sys(WINDOW_END, "monitoring"),
        incident_start=sys(WINDOW_START, "monitoring"), downtime_start=sys(WINDOW_START, "monitoring"),
        service_restored_at=sys(restored, "monitoring") if restored else Fact[datetime](),
        resolved_at=sys(resolved, "monitoring") if resolved else Fact[datetime](),
        critical_or_important=sys(True, "service_list"),
    )


def test_c16a_planned_and_back_inside_window_is_not_an_incident():
    back = datetime(2026, 9, 14, 3, 40, tzinfo=UTC)
    result = classify(facts(window(back, back)), LATER)
    assert result.result == "not_an_incident"
    assert "DORA Art. 3(8)" in result.summary
    assert result.gate is None


def test_c16b_overrun_is_classified_from_the_planned_end():
    overrun = facts(window(datetime(2026, 9, 14, 9, 30, tzinfo=UTC), datetime(2026, 9, 14, 10, 0, tzinfo=UTC)),
                    NO_T5B, t1(False), t2(False), t4(False), t5a(False), t6(False))
    result = classify(overrun, LATER)
    assert result.overrun
    assert result.thresholds_met == ("T3",)  # 5.5 h overrun downtime; 6 h duration is under 24 h
    assert result.result == "not_major"
    assert "overrun" in result.summary


def test_planned_window_on_record_but_no_human_answer_is_undetermined():
    back = datetime(2026, 9, 14, 3, 40, tzinfo=UTC)
    result = classify(facts(window(back, back, planned=Fact[bool]())), LATER)
    assert result.result == "undetermined"
    assert result.missing == ("planned_and_announced",)


def test_ai_saying_planned_is_not_enough():
    back = datetime(2026, 9, 14, 3, 40, tzinfo=UTC)
    suggestion = Fact[bool](value=True, source="ai_suggestion")
    result = classify(facts(window(back, back, planned=suggestion)), LATER)
    assert result.result == "undetermined"
    assert result.pending_confirmations == ("planned_and_announced",)


def test_human_says_not_planned_classifies_normally():
    result = classify(facts(GATE_MET, NO_T5B, *all_others({"T2", "T3"}),
                            dict(planned_and_announced=human(False))), AS_OF)
    assert result.result == "major"
    assert not result.overrun


def test_no_planned_window_on_record_is_treated_as_unplanned():
    result = classify(facts(GATE_MET, NO_T5B, *all_others({"T2", "T3"})), AS_OF)
    assert result.result == "major"
    assert "No planned window on record" in result.reasons[0]


def test_still_inside_window_is_undetermined():
    inside = datetime(2026, 9, 14, 2, 0, tzinfo=UTC)
    result = classify(facts(window(None, None)), inside)
    assert result.result == "undetermined"
    assert result.missing == ("service_restored_at",)


def test_planned_without_window_end_asks_for_it():
    data = window(None, None)
    data["planned_window_end"] = Fact[datetime]()
    result = classify(facts(data), LATER)
    assert result.result == "undetermined"
    assert result.missing == ("planned_window_end",)


# ---------- what the result carries (hard rule 9) ----------


def test_result_carries_rule_version_facts_and_time():
    data = facts(GATE_MET, NO_T5B, *all_others({"T2", "T6"}))
    result = classify(data, AS_OF)
    assert result.rule_version == RULE_VERSION
    assert result.as_of == AS_OF
    assert result.facts == data
    assert result.facts.costs_eur.confirmed_by == "Sam"


def test_reasons_cover_step_0_gate_t5b_and_all_six_with_articles():
    result = classify(facts(GATE_MET, NO_T5B, *all_others({"T2", "T6"})), AS_OF)
    assert len(result.reasons) == 9
    ids = ["gate", "T5-b", "T1", "T2", "T3", "T4", "T5-a", "T6"]
    for reason, threshold_id in zip(result.reasons[1:], ids):
        assert reason.startswith(threshold_id), reason
        assert "RTS-C Art." in reason


def test_as_of_must_be_utc():
    with pytest.raises(ValueError):
        classify(IncidentFacts(), datetime(2026, 6, 1, 12))


def test_classify_does_not_change_the_facts():
    data = facts(GATE_MET, *all_others({"T2"}))
    before = data.model_dump()
    classify(data, AS_OF)
    assert data.model_dump() == before


# ---------- open question 9: confirmed malicious access on own systems (RTS-C recital 10) ----------

THRESHOLD_IDS = ("T1", "T2", "T3", "T4", "T5-a", "T6")
EVERY_COMBINATION = [
    {tid for i, tid in enumerate(THRESHOLD_IDS) if mask >> i & 1} for mask in range(2 ** len(THRESHOLD_IDS))
]
SERVICE_NOT_CRITICAL = dict(critical_or_important=sys(False, "service_list"),
                            regulated_service=sys(False, "service_list"))
SERVICE_UNKNOWN: dict = {}
CONFIRMED_ATTACK = dict(malicious_access=human(True), access_on_own_systems=human(True))


@pytest.mark.parametrize("service", [SERVICE_NOT_CRITICAL, SERVICE_UNKNOWN], ids=["not-critical", "unknown"])
def test_confirmed_attack_on_own_systems_that_may_lose_data_is_always_major(service):
    # Open question 9: T5-b is checked on its own, with no "not covered by T5-a" exclusion,
    # and G-c passes the gate. So no combination of the other facts can make it anything but major.
    attack = dict(CONFIRMED_ATTACK, access_may_cause_data_loss=human(True))
    for met in EVERY_COMBINATION:
        result = classify(facts(service, *all_others(met), attack), AS_OF)
        assert result.result == "major", sorted(met)
        assert result.gate.status == "met" and result.t5b.status == "met"
    # Also with nothing else known at all.
    assert classify(facts(service, attack), AS_OF).result == "major"


@pytest.mark.parametrize("service", [SERVICE_NOT_CRITICAL, SERVICE_UNKNOWN], ids=["not-critical", "unknown"])
def test_confirmed_attack_with_data_loss_question_open_is_never_not_major(service):
    # Until a human answers "may it result in data losses?", the result is major or undetermined.
    for met in EVERY_COMBINATION:
        result = classify(facts(service, *all_others(met), CONFIRMED_ATTACK), AS_OF)
        assert result.result in ("major", "undetermined"), sorted(met)
        if result.result == "undetermined":
            assert "access_may_cause_data_loss" in result.missing
    assert classify(facts(service, CONFIRMED_ATTACK), AS_OF).result == "undetermined"


def test_confirmed_attack_that_cannot_lose_data_is_decided_by_the_other_thresholds():
    # Open question 9, last sentence (Sam, 5 November 2026): follow the wording of RTS-C Art. 9(5)(b).
    # "May not result in data losses" means T5-b is not met. The gate still passes through G-c.
    attack = dict(CONFIRMED_ATTACK, access_may_cause_data_loss=human(False))
    one = classify(facts(SERVICE_NOT_CRITICAL, *all_others({"T6"}), attack), AS_OF)
    assert (one.gate.status, one.t5b.status, one.result) == ("met", "not_met", "not_major")
    two = classify(facts(SERVICE_NOT_CRITICAL, *all_others({"T2", "T6"}), attack), AS_OF)
    assert two.result == "major"
