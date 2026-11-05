"""The facts model: unknown stays unknown, sources are required, judgment calls need a human.

Rules from docs/dora-rules.md section 7 and open question 2.
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from dora_agent.rules import HUMAN_CONFIRMED, Fact, IncidentFacts

UTC = timezone.utc


def yes(source="service_list", **extra):
    return Fact[bool](value=True, source=source, **extra)


# ---------- unknown by default ----------


def test_every_fact_starts_unknown():
    facts = IncidentFacts()
    for name in IncidentFacts.model_fields:
        if name == "service_id":
            continue
        assert facts.usable(name) is None, name


def test_zero_is_a_real_value_not_unknown():
    facts = IncidentFacts(affected_clients=Fact[int](value=0, source="client_data"))
    assert facts.usable("affected_clients") == 0


def test_false_is_a_real_value_not_unknown():
    facts = IncidentFacts(critical_or_important=Fact[bool](value=False, source="service_list"))
    assert facts.usable("critical_or_important") is False


# ---------- shape checks ----------


def test_known_value_needs_a_source():
    with pytest.raises(ValidationError):
        Fact[bool](value=True)


def test_unknown_value_cannot_be_an_estimate():
    with pytest.raises(ValidationError):
        Fact[int](is_estimate=True)


def test_human_answer_must_name_the_person():
    with pytest.raises(ValidationError):
        Fact[bool](value=True, source="human")


def test_negative_counts_and_costs_rejected():
    with pytest.raises(ValidationError):
        IncidentFacts(affected_clients=Fact[int](value=-1, source="client_data"))
    with pytest.raises(ValidationError):
        IncidentFacts(costs_eur=Fact[int](value=-5, source="human", confirmed_by="Sam"))


def test_times_must_be_utc():
    cet = timezone(timedelta(hours=1))
    with pytest.raises(ValidationError):
        IncidentFacts(detected_at=Fact[datetime](value=datetime(2026, 5, 26, 9, 10, tzinfo=cet), source="monitoring"))
    ok = IncidentFacts(detected_at=Fact[datetime](value=datetime(2026, 5, 26, 7, 10, tzinfo=UTC), source="monitoring"))
    assert ok.usable("detected_at").hour == 7


def test_times_without_timezone_rejected():
    with pytest.raises(ValidationError):
        IncidentFacts(detected_at=Fact[datetime](value=datetime(2026, 5, 26, 7, 10), source="monitoring"))


def test_member_states_must_be_two_letter_codes():
    with pytest.raises(ValidationError):
        IncidentFacts(affected_member_states=Fact[tuple[str, ...]](value=("Germany",), source="client_data"))


def test_unknown_fields_rejected():
    with pytest.raises(ValidationError):
        IncidentFacts(is_major=yes())


def test_facts_cannot_be_changed_after_creation():
    facts = IncidentFacts()
    with pytest.raises(ValidationError):
        facts.costs_eur = Fact[int](value=1, source="human", confirmed_by="Sam")


def test_absurdly_large_numbers_rejected():
    # Security review, block 4: a 5,000-digit number used to crash the engine when printing a reason.
    with pytest.raises(ValidationError):
        IncidentFacts(costs_eur=Fact[int](value=10**5000, source="human", confirmed_by="Sam"))
    with pytest.raises(ValidationError):
        IncidentFacts(affected_clients=Fact[int](value=10**15 + 1, source="client_data"))
    assert IncidentFacts(affected_clients=Fact[int](value=10**15, source="client_data")).usable("affected_clients")


@pytest.mark.parametrize("bad", ["Sam\n2026-11-05 RESULT=not_major", "Sam\rX", "Sam\tX", "Sam\x1b[31m", "Sam\x00"])
def test_control_characters_rejected_in_names_and_notes(bad):
    # Security review, block 4: a line break could fake an extra line in the decision log.
    with pytest.raises(ValidationError):
        Fact[bool](value=True, source="human", confirmed_by=bad)
    with pytest.raises(ValidationError):
        Fact[bool](value=True, source="service_list", note=bad)


def test_member_state_list_has_a_length_limit():
    with pytest.raises(ValidationError):
        IncidentFacts(affected_member_states=Fact[tuple[str, ...]](value=("DE",) * 61, source="client_data"))


def test_strict_types_no_text_for_numbers():
    with pytest.raises(ValidationError):
        Fact[int](value="150000", source="client_data")


def test_estimate_is_kept_and_marked():
    facts = IncidentFacts(costs_eur=Fact[int](value=140_000, source="human", confirmed_by="Sam", is_estimate=True))
    assert facts.usable("costs_eur") == 140_000
    assert facts.costs_eur.is_estimate


def test_misspelled_fact_name_raises():
    with pytest.raises(KeyError):
        IncidentFacts().usable("media_coverge")
    with pytest.raises(KeyError):
        IncidentFacts().usable("service_id")


# ---------- human confirmation (section 7) ----------


def test_human_confirmed_list_matches_section_7():
    # T1-f, all of T2, T5-a, malicious access (G-c, T5-b), and the planned question (open question 5).
    expected = {
        "relevant_parties_affected",
        "media_coverage", "repeated_complaints", "regulatory_requirements_impact", "client_loss_impact",
        "data_availability_impact", "data_authenticity_impact", "data_integrity_impact",
        "data_confidentiality_impact", "data_impact_adverse",
        "malicious_access", "access_on_own_systems", "access_may_cause_data_loss",
        "planned_and_announced",
    }
    assert HUMAN_CONFIRMED == expected
    assert HUMAN_CONFIRMED <= set(IncidentFacts.model_fields)


def test_ai_suggestion_is_not_used_until_confirmed():
    pending = IncidentFacts(costs_eur=Fact[int](value=200_000, source="ai_suggestion"))
    assert pending.usable("costs_eur") is None
    assert pending.pending_confirmations() == ["costs_eur"]

    confirmed = IncidentFacts(costs_eur=Fact[int](value=200_000, source="ai_suggestion", confirmed_by="Sam"))
    assert confirmed.usable("costs_eur") == 200_000
    assert confirmed.pending_confirmations() == []


@pytest.mark.parametrize("name", sorted(HUMAN_CONFIRMED))
def test_judgment_call_from_a_system_still_needs_a_human(name):
    # Example: security alerts say "malicious access", or client data says "relevant parties affected".
    # Section 7: the engine may not use it until a human confirms.
    unconfirmed = IncidentFacts(**{name: yes(source="security_alerts")})
    assert unconfirmed.usable(name) is None
    assert unconfirmed.pending_confirmations() == [name]

    confirmed = IncidentFacts(**{name: yes(source="security_alerts", confirmed_by="Sam")})
    assert confirmed.usable(name) is True


def test_system_fact_that_is_not_a_judgment_call_is_used_directly():
    facts = IncidentFacts(critical_or_important=yes(source="service_list"))
    assert facts.usable("critical_or_important") is True
    assert facts.pending_confirmations() == []


def test_confirmer_is_recorded():
    facts = IncidentFacts(media_coverage=Fact[bool](value=True, source="human", confirmed_by="Sam"))
    assert facts.media_coverage.confirmed_by == "Sam"
    assert facts.media_coverage.source == "human"
