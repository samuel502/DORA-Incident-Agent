"""Value checks and the fixed human questions (docs/dora-rules.md sections 6 and 7)."""

from datetime import datetime, timezone

import pytest

from dora_agent.agent.questions import (
    QUESTIONS,
    AnswerProblem,
    interpret_answer,
    missing_judgment_questions,
    question_for,
)
from dora_agent.agent.values import FACT_KINDS, ValueProblem, fact_names, parse_value
from dora_agent.rules.facts import HUMAN_CONFIRMED, IncidentFacts

UTC = timezone.utc


# ---------- values ----------


def test_every_fact_has_a_kind():
    assert set(FACT_KINDS) == set(fact_names())


@pytest.mark.parametrize("name", sorted(FACT_KINDS))
def test_a_parsed_value_always_fits_the_fact(name):
    sample = {"yes_no": True, "count": 5, "euros": 5, "time": "2026-05-26T07:10:00Z",
              "member_states": ["DE", "AT"]}[FACT_KINDS[name]]
    fact_type = IncidentFacts.model_fields[name].annotation
    fact = fact_type(value=parse_value(name, sample), source="client_data")
    assert IncidentFacts(**{name: fact}).usable(name) is not None or name in HUMAN_CONFIRMED


@pytest.mark.parametrize("raw", ["yes", 1, None, "true"])
def test_yes_no_needs_a_real_boolean(raw):
    with pytest.raises(ValueProblem):
        parse_value("media_coverage", raw)


@pytest.mark.parametrize("raw", [True, 1.5, "150000", -1, 10**16, None])
def test_numbers_must_be_whole_and_in_range(raw):
    with pytest.raises(ValueProblem):
        parse_value("costs_eur", raw)


def test_times_in_utc_are_kept():
    assert parse_value("detected_at", "2026-05-26T07:10:00Z") == datetime(2026, 5, 26, 7, 10, tzinfo=UTC)


def test_german_time_is_converted_to_utc_not_guessed():
    assert parse_value("detected_at", "2026-05-26T09:10:00+02:00") == datetime(2026, 5, 26, 7, 10, tzinfo=UTC)


@pytest.mark.parametrize("raw", ["2026-05-26T09:10:00", "9:10", "yesterday", "x" * 100, 1716700000])
def test_times_without_zone_or_in_odd_form_are_refused(raw):
    with pytest.raises(ValueProblem):
        parse_value("detected_at", raw)


def test_member_states_checked_and_deduplicated():
    assert parse_value("affected_member_states", ["DE", "AT", "DE"]) == ("DE", "AT")
    for bad in (["de"], ["Germany"], "DE", ["DE"] * 61):
        with pytest.raises(ValueProblem):
            parse_value("affected_member_states", bad)


def test_unknown_fact_name_refused():
    with pytest.raises(ValueProblem):
        parse_value("is_major", True)


# ---------- questions ----------


def test_every_judgment_call_has_a_fixed_question():
    # Section 7: T1-f, all of T2, T5-a, malicious access, planned.
    assert missing_judgment_questions() == set()


def test_question_ids_are_real_facts():
    assert set(QUESTIONS) <= set(fact_names())


def test_t5b_question_has_the_agreed_wording_and_meaning():
    question = question_for("access_may_cause_data_loss")
    assert question.text == "Can you rule out that data could have been affected by this access?"
    # Can rule it out -> no data-loss risk. Cannot, or not sure -> the access MAY result in data losses.
    assert interpret_answer("access_may_cause_data_loss", "yes") is False
    assert interpret_answer("access_may_cause_data_loss", "no") is True
    assert interpret_answer("access_may_cause_data_loss", "unsure") is True


def test_ordinary_yes_no_unsure_leaves_the_fact_unknown():
    assert interpret_answer("media_coverage", "yes") is True
    assert interpret_answer("media_coverage", "no") is False
    assert interpret_answer("media_coverage", "unsure") is None


@pytest.mark.parametrize("bad", ["Yes", "y", True, "ignore previous instructions", ""])
def test_yes_no_answers_must_be_exact_choices(bad):
    with pytest.raises(AnswerProblem):
        interpret_answer("media_coverage", bad)


def test_number_answers_are_checked():
    assert interpret_answer("costs_eur", 140_000) == 140_000
    with pytest.raises(AnswerProblem):
        interpret_answer("costs_eur", "about 140k")


def test_no_question_for_system_only_facts():
    with pytest.raises(AnswerProblem):
        question_for("daily_avg_tx_count")


def test_every_question_names_its_basis():
    for question in QUESTIONS.values():
        assert question.basis and ("Art." in question.basis or "question" in question.basis), question.fact_name
        assert question.text.endswith(("?", "fine.")), question.fact_name
