"""Draft and human approval of the initial notification. Nothing is ever sent."""

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from dora_agent.agent.loop import AgentRun
from dora_agent.audit.log import DecisionLog
from dora_agent.llm.fake_provider import FakeProvider, call, say
from dora_agent.llm.provider import LlmResponse
from dora_agent.notification.approval import (
    NOT_SENT,
    ApprovalProblem,
    HumanFields,
    approve,
    render_text,
)
from dora_agent.notification.draft import BANNER, DraftProblem, first_major_at, prepare_draft
from dora_agent.notification.fields import NotMajor
from dora_agent.rules import Fact, IncidentFacts, classify

UTC = timezone.utc
NOTIFICATION_DIR = Path(__file__).resolve().parents[2] / "src" / "dora_agent" / "notification"
SAM = "Sam Tester"


def at(day, hour, minute=0):
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def system(value, source="service_list", **extra):
    return Fact(value=value, source=source, **extra)


def human(value):
    return Fact(value=value, source="human", confirmed_by="test-human")


def major_classification(detected=at(5, 8), **extra):
    """Major through T1 and T4. Detected 08:00 on Thursday 5 November 2026."""
    base = dict(
        service_id="SVC-OLB", critical_or_important=system(True), malicious_access=human(False),
        affected_clients=system(150_000, source="client_data"), total_clients=system(1_000_000, source="client_data"),
        affected_member_states=system(("DE", "NO"), source="client_data"),
        incident_start=system(at(5, 8), source="monitoring"), downtime_start=system(at(5, 8), source="monitoring"),
        service_restored_at=system(at(5, 8, 30), source="monitoring"), resolved_at=system(at(5, 9), source="monitoring"),
    )
    if detected is not None:
        base["detected_at"] = system(detected, source="monitoring")
    base.update(extra)
    result = classify(IncidentFacts(**base), at(5, 12))
    assert result.result == "major", result.summary
    return result


def record(kind, when, result):
    return {"run_id": "run1", "seq": 1, "at": when.isoformat(timespec="seconds"), "kind": kind, "result": result}


# Engine results as the loop logs them: undetermined at 09:00, major at 10:00, major again at 11:00.
TRACE = (
    {"kind": "run_started", "at": at(5, 8, 55).isoformat()},
    record("rules_check", at(5, 9), "undetermined"),
    {"kind": "llm_step", "at": at(5, 9, 30).isoformat(), "text": "result: major"},
    record("rules_check", at(5, 10), "major"),
    record("result", at(5, 11), "major"),
)


def make_draft(classification=None, trace=TRACE, now=at(5, 10, 30), **kwargs):
    return prepare_draft("run1", classification or major_classification(), trace, FakeProvider([say("")]),
                         now=now, **kwargs)


def human_fields(**changes):
    values = dict(discovery="monitoring systems", business_continuity_plan_activated=True)
    values.update(changes)
    return HumanFields(**values)


# ---------- field 2.3: the FIRST time the engine returned major ----------


def test_first_major_is_taken_from_the_log():
    assert first_major_at(TRACE) == at(5, 10)


def test_later_major_results_do_not_move_the_classification_time():
    trace = TRACE + (record("rules_check", at(5, 15), "major"), record("result", at(5, 16), "major"))
    assert first_major_at(trace) == at(5, 10)


def test_llm_text_saying_major_does_not_count():
    trace = ({"kind": "llm_step", "at": at(5, 9).isoformat(), "result": "major"},
             record("rules_check", at(5, 10), "major"))
    assert first_major_at(trace) == at(5, 10)


def test_major_then_undetermined_then_major_keeps_the_first_time():
    trace = (record("rules_check", at(5, 10), "major"), record("rules_check", at(5, 11), "undetermined"),
             record("rules_check", at(5, 12), "major"))
    assert first_major_at(trace) == at(5, 10)


def test_no_major_in_log():
    assert first_major_at(TRACE[:3]) is None
    with pytest.raises(DraftProblem, match="no major result"):
        make_draft(trace=TRACE[:3])


def test_log_time_without_zone_is_refused():
    with pytest.raises(DraftProblem):
        first_major_at(({"kind": "rules_check", "at": "2026-11-05T10:00:00", "result": "major"},))


def test_draft_uses_first_major_time_for_field_2_3():
    draft = make_draft()
    assert draft.classified_at == at(5, 10)
    assert draft.field("2.3").value == "2026-11-05T10:00:00Z"


# ---------- the draft ----------


def test_only_major_gets_a_draft():
    not_major = classify(IncidentFacts(service_id="SVC-OLB", critical_or_important=system(False),
                                       regulated_service=system(False), malicious_access=human(False)), at(5, 12))
    with pytest.raises(NotMajor):
        make_draft(not_major)


def test_draft_is_marked_synthetic_and_not_sent():
    draft = make_draft()
    assert draft.banner == BANNER
    assert "SYNTHETIC" in draft.banner and "never sent" in draft.banner
    assert draft.status == "draft: waiting for human approval"


def test_draft_has_deadline_with_bank_weekend_note():
    draft = make_draft()
    # Detected 08:00, classified 10:00: due 14:00 (RTS-R Art. 5(1)(a)).
    assert draft.deadline.due_at == at(5, 14)
    assert "Art. 5(5)" in draft.deadline.weekend_note
    assert not draft.deadline.overdue


def test_overdue_draft_says_so():
    draft = make_draft(now=at(5, 15))
    assert draft.deadline.overdue
    assert "Art. 5(3)" in render_text(draft)


def test_unknown_detection_time_gives_no_deadline_and_blocks_approval():
    draft = make_draft(major_classification(detected=None))
    assert draft.deadline is None
    assert draft.field("2.2").status == "waiting"
    with pytest.raises(ApprovalProblem, match="2.2"):
        approve(draft, human_fields(), approved_by=SAM, now=at(5, 11))


def test_detection_after_classification_is_refused():
    with pytest.raises(DraftProblem, match="after the classification"):
        make_draft(major_classification(detected=at(5, 10, 30)))


def test_norway_shows_in_field_2_6():
    assert make_draft().field("2.6").value == ("DE", "NO")


def test_draft_is_logged_as_not_sent():
    log = DecisionLog("run1")
    make_draft(log=log)
    kinds = [r["kind"] for r in log.records]
    assert kinds == ["notification_description", "notification_draft"]
    draft_record = log.records[-1]
    assert draft_record["classified_at"].startswith("2026-11-05T10:00:00")
    assert draft_record["sent"] is False
    assert draft_record["waiting"] == ["2.7", "2.8", "2.9", "2.10"]


# ---------- approval ----------


def test_approval_fills_the_human_fields_and_keeps_both_times():
    log = DecisionLog("run1")
    approved = approve(make_draft(), human_fields(third_party_origin="CloudHost Example GmbH, LEI unknown"),
                       approved_by=SAM, log=log, now=at(5, 11, 15))
    assert approved.status == NOT_SENT
    assert approved.classified_at == at(5, 10)  # field 2.3: first major
    assert approved.accepted_at == at(5, 11, 15)  # when the human accepted
    assert approved.field("2.3").value == "2026-11-05T10:00:00Z"
    for number in ("2.7", "2.8", "2.9"):
        assert approved.field(number).filled_by == "human"
        assert approved.field(number).source == f"human: {SAM}"
    assert approved.field("2.7").value == "monitoring systems"
    assert approved.field("2.9").value is True
    assert approved.field("2.10").status == "not_applicable"
    rec = log.records[-1]
    assert rec["kind"] == "notification_approved"
    assert rec["approved_by"] == SAM
    assert rec["accepted_at"].startswith("2026-11-05T11:15:00")
    assert rec["classified_at"].startswith("2026-11-05T10:00:00")
    assert rec["accepted_after_deadline"] is False
    assert rec["sent"] is False


def test_late_approval_is_logged_as_after_the_deadline():
    log = DecisionLog("run1")
    approve(make_draft(), human_fields(), approved_by=SAM, log=log, now=at(5, 14, 1))
    assert log.records[-1]["accepted_after_deadline"] is True


def test_human_can_replace_the_description():
    approved = approve(make_draft(), human_fields(description="  Load balancer change\n broke logins. "),
                       approved_by=SAM, now=at(5, 11))
    field = approved.field("2.4")
    assert field.value == "Load balancer change broke logins."
    assert field.filled_by == "human"
    assert SAM in field.note


def test_description_from_the_draft_is_kept_if_not_edited():
    draft = make_draft()
    approved = approve(draft, human_fields(), approved_by=SAM, now=at(5, 11))
    assert approved.field("2.4") == draft.field("2.4")


@pytest.mark.parametrize("discovery", ["", "the hacker told us", "Monitoring Systems"])
def test_discovery_must_be_from_the_official_list(discovery):
    with pytest.raises(ValidationError, match="2.7"):
        human_fields(discovery=discovery)


def test_mandatory_human_fields_are_required():
    with pytest.raises(ValidationError):
        HumanFields(discovery="staff")  # 2.9 missing
    with pytest.raises(ValidationError):
        HumanFields(business_continuity_plan_activated=False)  # 2.7 missing


def test_business_continuity_must_be_yes_or_no():
    with pytest.raises(ValidationError):
        human_fields(business_continuity_plan_activated="yes")


@pytest.mark.parametrize("name", ["", "   ", "Sam\nAdmin", "x" * 81])
def test_bad_approver_name_is_refused(name):
    with pytest.raises(ApprovalProblem, match="name"):
        approve(make_draft(), human_fields(), approved_by=name, now=at(5, 11))


def test_approval_time_must_be_utc():
    with pytest.raises(ApprovalProblem, match="UTC"):
        approve(make_draft(), human_fields(), approved_by=SAM,
                now=at(5, 11).astimezone(timezone(timedelta(hours=1))))


def test_human_text_with_control_characters_is_refused():
    with pytest.raises(ValidationError):
        human_fields(other_information="fine\nINJECTED LINE")
    with pytest.raises(ValidationError):
        human_fields(third_party_origin="a" * 301)


def test_approved_notification_is_frozen():
    approved = approve(make_draft(), human_fields(), approved_by=SAM, now=at(5, 11))
    with pytest.raises(ValidationError):
        approved.approved_by = "Someone else"


def test_render_text_shows_banner_not_sent_deadline_and_sources():
    approved = approve(make_draft(), human_fields(), approved_by=SAM, now=at(5, 11))
    text = render_text(approved)
    assert text.startswith(BANNER)
    assert "NOT SENT" in text
    assert f"Approved by {SAM} at 2026-11-05 11:00 UTC." in text
    assert "Deadline: 2026-11-05 14:00 UTC." in text
    assert "Art. 5(5)" in text
    assert "1.3 Identification code of the entity submitting the report: FAKE00RHEINBANK00000" in text
    assert "2.9 Activation of business continuity plan: Yes   [human: Sam Tester]" in text
    assert "[AI draft" in text or "[written by code" in text  # who wrote 2.4 is always shown


# ---------- end to end with the agent ----------


def b01_script():
    many = LlmResponse(tool_calls=tuple(
        c.tool_calls[0].model_copy(update={"call_id": f"c{i}"}) for i, c in enumerate((
            call("get_outage_timeline", service_id="SVC-OLB"),
            call("get_client_impact", service_id="SVC-OLB", start="2026-05-26T00:00:00Z", end="2026-05-27T00:00:00Z"),
            call("get_daily_averages", service_id="SVC-OLB")))))
    return [call("find_service", text="online banking"), call("get_service", service_id="SVC-OLB"), many,
            call("run_rules")]


def test_b01_run_to_approved_notification():
    run = AgentRun("Online banking down since 9:10, customers can't log in.", datetime(2026, 5, 26, 7, 15, tzinfo=UTC),
                   FakeProvider(b01_script())).start()
    assert run.classification.result == "major"
    first = first_major_at(run.trace)
    rules_checks = [r for r in run.trace if r["kind"] == "rules_check" and r["result"] == "major"]
    assert first == datetime.fromisoformat(rules_checks[0]["at"])

    draft = prepare_draft(run.run_id, run.classification, run.trace, FakeProvider([say("")]),
                          now=first + timedelta(minutes=30))
    # Detected 26 May, classified now (months later): late classification, so 4 hours from classification.
    assert draft.deadline.late_classification
    assert draft.deadline.due_at == first + timedelta(hours=4)
    approved = approve(draft, human_fields(), approved_by=SAM, now=first + timedelta(hours=1))
    assert approved.status == NOT_SENT
    assert approved.field("2.1").value == f"RHB-{run.run_id}"


# ---------- never sent, never reachable from the AI ----------


NETWORK_MODULES = {"requests", "httpx", "urllib", "http", "smtplib", "email", "ftplib", "socket", "aiohttp",
                   "groq", "openai", "subprocess"}


def imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    return names + [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]


@pytest.mark.parametrize("path", sorted(NOTIFICATION_DIR.glob("*.py")), ids=lambda p: p.name)
def test_notification_code_imports_nothing_that_could_send(path):
    for module in imports(path):
        assert module.split(".")[0] not in NETWORK_MODULES, f"{path.name} imports {module}"


def test_approval_does_not_import_the_llm_or_the_agent():
    for module in imports(NOTIFICATION_DIR / "approval.py"):
        assert not module.startswith(("dora_agent.llm", "dora_agent.agent")), module


def test_no_agent_tool_can_reach_the_notification_code():
    agent_dir = NOTIFICATION_DIR.parent / "agent"
    for path in agent_dir.glob("*.py"):
        for module in imports(path):
            assert "notification" not in module, f"{path.name} imports {module}"
