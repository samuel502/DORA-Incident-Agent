"""Gate, T1 to T6 and T5-b: each point, each boundary, and unknown handling.

Rules: docs/dora-rules.md sections 2 and 3, open question 4, section 7.
Boundary tests check just at and just above each limit: the rules say "more than", so "exactly" is not met.
"""

from datetime import datetime, timedelta, timezone

import pytest

from dora_agent.rules import Fact, IncidentFacts
from dora_agent.rules.thresholds import (
    MET,
    NOT_MET,
    UNKNOWN,
    all_of,
    any_of,
    check_gate,
    check_t1,
    check_t2,
    check_t3,
    check_t4,
    check_t5a,
    check_t5b,
    check_t6,
)

UTC = timezone.utc
AS_OF = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
START = datetime(2026, 5, 26, 7, 0, tzinfo=UTC)


def system(value, source="client_data"):
    if isinstance(value, bool):
        return Fact[bool](value=value, source=source)
    if isinstance(value, tuple):
        return Fact[tuple[str, ...]](value=value, source=source)
    if isinstance(value, datetime):
        return Fact[datetime](value=value, source=source)
    return Fact[int](value=value, source=source)


def human(value):
    return Fact[bool](value=value, source="human", confirmed_by="Sam")


def ai(value):
    return Fact[bool](value=value, source="ai_suggestion")


def point(threshold, check_id):
    return next(c for c in threshold.checks if c.check_id == check_id)


# ---------- three-valued logic ----------


@pytest.mark.parametrize(
    "statuses, expected",
    [
        ([MET, NOT_MET, UNKNOWN], MET),
        ([NOT_MET, NOT_MET], NOT_MET),
        ([NOT_MET, UNKNOWN], UNKNOWN),
        ([UNKNOWN], UNKNOWN),
        ([], UNKNOWN),
    ],
)
def test_any_of(statuses, expected):
    assert any_of(statuses) == expected


@pytest.mark.parametrize(
    "statuses, expected",
    [
        ([MET, MET], MET),
        ([MET, NOT_MET, UNKNOWN], NOT_MET),
        ([MET, UNKNOWN], UNKNOWN),
        ([], UNKNOWN),
    ],
)
def test_all_of(statuses, expected):
    assert all_of(statuses) == expected


# ---------- gate (section 2, RTS-C Art. 6) ----------


def test_gate_passed_by_critical_service():
    assert check_gate(IncidentFacts(critical_or_important=system(True, "service_list"))).status == MET


def test_gate_passed_by_regulated_service():
    assert check_gate(IncidentFacts(regulated_service=system(True, "service_list"))).status == MET


def test_gate_not_passed_when_all_three_are_no():
    # N01: HR portal, not critical, not regulated, no attack.
    facts = IncidentFacts(critical_or_important=system(False, "service_list"),
                          regulated_service=system(False, "service_list"), malicious_access=human(False))
    gate = check_gate(facts)
    assert gate.status == NOT_MET
    assert gate.missing == ()


def test_gate_unknown_lists_what_is_missing():
    facts = IncidentFacts(critical_or_important=system(False, "service_list"),
                          regulated_service=system(False, "service_list"))
    gate = check_gate(facts)
    assert gate.status == UNKNOWN
    assert gate.missing == ("malicious_access", "access_on_own_systems")


def test_gate_c_needs_access_on_own_systems():
    own = IncidentFacts(malicious_access=human(True), access_on_own_systems=human(True))
    assert point(check_gate(own), "G-c").status == MET
    # Open question 4 (C07, C11, C13): a supplier's systems were breached, not the bank's.
    supplier = IncidentFacts(malicious_access=human(True), access_on_own_systems=human(False))
    assert point(check_gate(supplier), "G-c").status == NOT_MET


def test_gate_c_from_security_alert_needs_human_confirmation():
    # B03: the SOC flags it, but a human must confirm before it counts (section 7).
    facts = IncidentFacts(malicious_access=Fact[bool](value=True, source="security_alerts"),
                          access_on_own_systems=human(True))
    g_c = point(check_gate(facts), "G-c")
    assert g_c.status == UNKNOWN
    assert "waiting for human confirmation" in g_c.reason


# ---------- T1 (RTS-C Art. 9(1)) ----------


def t1(**facts):
    return check_t1(IncidentFacts(**{k: system(v) for k, v in facts.items()}))


def test_t1a_exactly_10_percent_is_not_met():
    # N06: exactly 10.0% of clients.
    assert point(t1(affected_clients=8_000, total_clients=80_000), "T1-a").status == NOT_MET


def test_t1a_just_over_10_percent_is_met():
    assert point(t1(affected_clients=8_001, total_clients=80_000), "T1-a").status == MET


def test_t1b_exactly_100000_is_not_met():
    assert point(t1(affected_clients=100_000), "T1-b").status == NOT_MET


def test_t1b_100001_is_met_without_knowing_the_total():
    result = t1(affected_clients=100_001)
    assert point(result, "T1-b").status == MET
    assert result.status == MET  # T1-a is unknown, but one met point is enough


def test_t1c_exactly_30_percent_is_not_met():
    assert point(t1(affected_counterparts=30, total_counterparts=100), "T1-c").status == NOT_MET


def test_t1c_just_over_30_percent_is_met():
    assert point(t1(affected_counterparts=301, total_counterparts=1_000), "T1-c").status == MET


def test_t1d_number_of_transactions_boundary():
    assert point(t1(affected_tx_count=50_000, daily_avg_tx_count=500_000), "T1-d").status == NOT_MET
    assert point(t1(affected_tx_count=50_001, daily_avg_tx_count=500_000), "T1-d").status == MET


def test_t1e_value_of_transactions_boundary():
    assert point(t1(affected_tx_value_eur=1_000_000, daily_avg_tx_value_eur=10_000_000), "T1-e").status == NOT_MET
    assert point(t1(affected_tx_value_eur=1_000_001, daily_avg_tx_value_eur=10_000_000), "T1-e").status == MET


def test_t1f_relevant_parties_need_a_human():
    from_data = check_t1(IncidentFacts(relevant_parties_affected=system(True)))
    assert point(from_data, "T1-f").status == UNKNOWN
    confirmed = check_t1(IncidentFacts(relevant_parties_affected=human(True)))
    assert point(confirmed, "T1-f").status == MET


def test_t1_zero_affected_is_not_met_even_if_total_unknown():
    assert point(t1(affected_clients=0), "T1-a").status == NOT_MET


def test_t1_total_of_zero_cannot_give_a_share():
    check = point(t1(affected_clients=5, total_clients=0), "T1-a")
    assert check.status == UNKNOWN
    assert check.missing == ("total_clients",)


def test_t1_several_points_met_count_as_one_threshold():
    # Open question 1: T1 is one threshold, however many of its points are met.
    result = t1(affected_clients=200_000, total_clients=1_000_000)
    assert [c.check_id for c in result.checks if c.status == MET] == ["T1-a", "T1-b"]
    assert result.status == MET


def test_t1_not_met_needs_every_point_answered():
    # N02: 3% of clients, under 100,000, nothing else.
    result = check_t1(IncidentFacts(
        affected_clients=system(3_000), total_clients=system(100_000),
        affected_counterparts=system(0), affected_tx_count=system(0), affected_tx_value_eur=system(0),
        relevant_parties_affected=human(False),
    ))
    assert result.status == NOT_MET


def test_t1_unknown_lists_missing_facts():
    result = t1(affected_clients=3_000, total_clients=100_000)
    assert result.status == UNKNOWN
    assert "affected_counterparts" in result.missing
    assert "relevant_parties_affected" in result.missing
    assert "affected_clients" not in result.missing


def test_t1_reason_shows_the_numbers():
    reason = point(t1(affected_clients=8_000, total_clients=80_000), "T1-a").reason
    assert "8,000 of 80,000" in reason and "10.00%" in reason


# ---------- T2 (RTS-C Art. 9(2)) ----------


def test_t2_any_point_confirmed_is_met():
    for name in ("media_coverage", "repeated_complaints", "regulatory_requirements_impact", "client_loss_impact"):
        assert check_t2(IncidentFacts(**{name: human(True)})).status == MET, name


def test_t2_ai_suggestion_alone_does_not_count():
    result = check_t2(IncidentFacts(media_coverage=ai(True)))
    assert result.status == UNKNOWN
    assert "media_coverage" in result.missing


def test_t2_all_no_is_not_met():
    facts = IncidentFacts(media_coverage=human(False), repeated_complaints=human(False),
                          regulatory_requirements_impact=human(False), client_loss_impact=human(False))
    assert check_t2(facts).status == NOT_MET


# ---------- T3 (RTS-C Art. 9(3)) ----------


def t3(duration=None, downtime=None, critical=True, resolved=True, as_of=AS_OF):
    facts = {"critical_or_important": system(critical, "service_list")} if critical is not None else {}
    if duration is not None:
        facts["incident_start"] = system(START, "monitoring")
        if resolved:
            facts["resolved_at"] = system(START + duration, "monitoring")
    if downtime is not None:
        facts["downtime_start"] = system(START, "monitoring")
        if resolved:
            facts["service_restored_at"] = system(START + downtime, "monitoring")
    return check_t3(IncidentFacts(**facts), as_of)


def test_t3a_exactly_24_hours_is_not_met():
    assert point(t3(duration=timedelta(hours=24)), "T3-a").status == NOT_MET


def test_t3a_just_over_24_hours_is_met():
    assert point(t3(duration=timedelta(hours=24, seconds=1)), "T3-a").status == MET


def test_t3b_exactly_2_hours_is_not_met():
    assert point(t3(downtime=timedelta(hours=2)), "T3-b").status == NOT_MET


def test_t3b_just_over_2_hours_is_met():
    # N03: payments down 3 hours.
    assert point(t3(downtime=timedelta(hours=3)), "T3-b").status == MET


def test_t3b_only_counts_for_critical_services():
    assert point(t3(downtime=timedelta(hours=4), critical=False), "T3-b").status == NOT_MET


def test_t3b_unknown_criticality_with_long_downtime_is_unknown():
    check = point(t3(downtime=timedelta(hours=4), critical=None), "T3-b")
    assert check.status == UNKNOWN
    assert check.missing == ("critical_or_important",)


def test_t3b_short_downtime_is_not_met_even_if_criticality_unknown():
    assert point(t3(downtime=timedelta(minutes=40), critical=None), "T3-b").status == NOT_MET


def test_t3_ongoing_already_over_limit_is_met():
    as_of = START + timedelta(hours=3)
    assert point(t3(downtime=timedelta(0), resolved=False, as_of=as_of), "T3-b").status == MET


def test_t3_ongoing_under_limit_is_unknown_not_guessed():
    as_of = START + timedelta(hours=1)
    check = point(t3(downtime=timedelta(0), resolved=False, as_of=as_of), "T3-b")
    assert check.status == UNKNOWN
    assert check.missing == ("service_restored_at",)
    assert "still ongoing" in check.reason


def test_t3_no_times_lists_missing_start():
    result = check_t3(IncidentFacts(critical_or_important=system(True, "service_list")), AS_OF)
    assert result.status == UNKNOWN
    assert result.missing == ("incident_start", "detected_at", "downtime_start")


def test_t3_keeps_the_measurement_for_the_trace():
    check = point(t3(downtime=timedelta(hours=3)), "T3-b")
    assert check.measurement.length == timedelta(hours=3)
    assert check.measurement.start_basis == "downtime_start"


def test_t3_overrun_c16b():
    # C16-B (PRB-0029): window ends 04:00, restored 09:30, resolved 10:00. Open question 8.
    facts = IncidentFacts(
        planned_and_announced=human(True),
        planned_window_end=system(datetime(2026, 9, 14, 4, 0, tzinfo=UTC), "monitoring"),
        incident_start=system(datetime(2026, 9, 12, 16, 0, tzinfo=UTC), "monitoring"),
        downtime_start=system(datetime(2026, 9, 12, 16, 0, tzinfo=UTC), "monitoring"),
        service_restored_at=system(datetime(2026, 9, 14, 9, 30, tzinfo=UTC), "monitoring"),
        resolved_at=system(datetime(2026, 9, 14, 10, 0, tzinfo=UTC), "monitoring"),
        critical_or_important=system(True, "service_list"),
    )
    result = check_t3(facts, datetime(2026, 9, 14, 12, 0, tzinfo=UTC))
    assert point(result, "T3-a").status == NOT_MET  # 6 h overrun duration
    assert point(result, "T3-b").status == MET  # 5.5 h overrun downtime


def test_t3_planned_without_window_end_asks_for_it():
    facts = IncidentFacts(planned_and_announced=human(True), detected_at=system(START, "monitoring"),
                          critical_or_important=system(True, "service_list"))
    result = check_t3(facts, AS_OF)
    assert result.status == UNKNOWN
    assert result.missing == ("planned_window_end",)


# ---------- T4 (RTS-C Art. 9(4)) ----------


def t4(*states):
    return check_t4(IncidentFacts(affected_member_states=system(tuple(states))))


def test_t4_one_member_state_is_not_met():
    assert t4("DE").status == NOT_MET


def test_t4_two_member_states_is_met():
    # C17-B: Germany and Austria.
    assert t4("DE", "AT").status == MET


def test_t4_countries_outside_the_eea_do_not_count():
    result = t4("DE", "GB", "US")
    assert result.status == NOT_MET
    assert "GB, US" in result.checks[0].reason


@pytest.mark.parametrize("state", ["NO", "IS", "LI"])
def test_t4_eea_efta_states_count(state):
    # Open question 10: Iceland, Liechtenstein and Norway are EEA Member States (EEA JCD No 40/2025).
    result = t4("DE", state)
    assert result.status == MET
    assert state in result.checks[0].reason


def test_t4_switzerland_is_not_in_the_eea():
    result = t4("DE", "CH")
    assert result.status == NOT_MET
    assert "outside the EEA: CH" in result.checks[0].reason


def test_t4_list_is_the_30_eea_states():
    from dora_agent.rules.thresholds import EEA_MEMBER_STATES
    assert len(EEA_MEMBER_STATES - {"EL"}) == 30


def test_t4_greece_counted_once_under_either_code():
    assert t4("GR", "EL").status == NOT_MET
    assert t4("EL", "DE").status == MET


def test_t4_duplicates_count_once():
    assert t4("DE", "DE").status == NOT_MET


def test_t4_unknown():
    result = check_t4(IncidentFacts())
    assert result.status == UNKNOWN
    assert result.missing == ("affected_member_states",)


# ---------- T5-a (RTS-C Art. 9(5)(a), Art. 5) ----------


def test_t5a_needs_data_impact_and_adverse_impact():
    assert check_t5a(IncidentFacts(data_integrity_impact=human(True), data_impact_adverse=human(True))).status == MET
    assert check_t5a(IncidentFacts(data_integrity_impact=human(True), data_impact_adverse=human(False))).status == NOT_MET


def test_t5a_no_data_impact_at_all_is_not_met():
    facts = IncidentFacts(data_availability_impact=human(False), data_authenticity_impact=human(False),
                          data_integrity_impact=human(False), data_confidentiality_impact=human(False))
    assert check_t5a(facts).status == NOT_MET


def test_t5a_impact_known_but_adverse_unknown_asks_only_for_adverse():
    result = check_t5a(IncidentFacts(data_confidentiality_impact=human(True)))
    assert result.status == UNKNOWN
    assert result.missing == ("data_impact_adverse",)


# ---------- T5-b (RTS-C Art. 9(5)(b)) ----------


def t5b_facts(malicious=True, own=True, loss=True):
    return IncidentFacts(malicious_access=human(malicious), access_on_own_systems=human(own),
                         access_may_cause_data_loss=human(loss))


def test_t5b_met_when_all_three_confirmed():
    assert check_t5b(t5b_facts()).status == MET


def test_t5b_not_met_without_successful_access():
    # N04: phishing click, login attempt blocked.
    assert check_t5b(t5b_facts(malicious=False)).status == NOT_MET


def test_t5b_supplier_systems_do_not_count():
    # Open question 4 (C11, C13).
    assert check_t5b(t5b_facts(own=False)).status == NOT_MET


def test_t5b_unconfirmed_alert_is_unknown():
    facts = IncidentFacts(malicious_access=Fact[bool](value=True, source="security_alerts"),
                          access_on_own_systems=human(True), access_may_cause_data_loss=human(True))
    result = check_t5b(facts)
    assert result.status == UNKNOWN
    assert result.missing == ("malicious_access",)


# ---------- T6 (RTS-C Art. 9(6)) ----------


def costs(value, estimate=False):
    return IncidentFacts(costs_eur=Fact[int](value=value, source="human", confirmed_by="Sam", is_estimate=estimate))


def test_t6_exactly_100000_is_not_met():
    assert check_t6(costs(100_000)).status == NOT_MET


def test_t6_just_over_100000_is_met():
    assert check_t6(costs(100_001)).status == MET


def test_t6_estimate_counts_and_is_marked():
    # N05: about EUR 140,000. Art. 7(3): estimate if actual amounts are not known.
    result = check_t6(costs(140_000, estimate=True))
    assert result.status == MET
    assert "(estimate)" in result.checks[0].reason


def test_t6_unknown():
    assert check_t6(IncidentFacts()).missing == ("costs_eur",)


# ---------- every result cites its article ----------


def test_every_check_cites_an_rts_article():
    facts = IncidentFacts()
    results = [check_gate(facts), check_t1(facts), check_t2(facts), check_t3(facts, AS_OF),
               check_t4(facts), check_t5a(facts), check_t5b(facts), check_t6(facts)]
    for threshold in results:
        assert threshold.article.startswith("RTS-C Art."), threshold.threshold_id
        for check in threshold.checks:
            assert check.article.startswith("RTS-C Art."), check.check_id
            assert check.reason
