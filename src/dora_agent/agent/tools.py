"""The agent's toolbox: what the LLM may ask for, and the plain code that runs it.

The LLM never holds an object from this file. It only sends a tool NAME and ARGUMENTS (a ToolCall).
`Toolbox.run` checks both before anything happens:
- unknown tool names are refused,
- arguments must match a fixed shape (no extra fields, right types, length limits),
- connector inputs are checked again by the connectors themselves.

What each kind of tool may change (security framework, section 2):
- Bank system tools: read-only. Results become facts only through plain-code mapping (mapping.py),
  and only for the incident's own service.
- suggest_facts: writes suggestions only, through AgentFactView. Never confirms anything.
- ask_human: only queues fixed questions (questions.py). It cannot answer them.
- run_rules: runs the rules engine. It is the only source of the classification (hard rule 1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from dora_agent import connectors
from dora_agent.agent import mapping
from dora_agent.agent.fact_store import FactStore
from dora_agent.agent.questions import QUESTIONS
from dora_agent.agent.values import ValueProblem
from dora_agent.connectors import InvalidQuery
from dora_agent.llm.provider import ToolCall, ToolSpec
from dora_agent.rules import Classification, classify

# Longest tool result (as JSON text) sent back to the LLM. Moves to config.toml [agent] in step 4.
MAX_TOOL_RESULT_CHARS = 8000

ServiceId = Field(pattern=r"^SVC-[A-Z]{2,8}$")
SupplierId = Field(pattern=r"^SUP-[A-Z]{2,8}$")
TimeText = Field(min_length=1, max_length=40, description="ISO 8601 time with zone, e.g. 2026-05-26T07:10:00Z")
RecordId = Field(pattern=r"^(PRB|IMP|ALR)-\d{4}$")


class Args(BaseModel):
    """Base for tool arguments: no extra fields, so nothing can be smuggled in (e.g. 'confirmed_by')."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class NoArgs(Args):
    pass


class FindServiceArgs(Args):
    text: str = Field(min_length=1, max_length=100, description="A few words naming the service, from the ticket")


class ServiceArgs(Args):
    service_id: str = ServiceId


class TimelineArgs(Args):
    service_id: str = ServiceId
    around: str | None = Field(default=None, min_length=1, max_length=40,
                               description="Time to search around (ISO 8601 with zone). Default: the reported time")
    window_hours: int = Field(default=24, ge=1, le=72)


class WindowArgs(Args):
    service_id: str = ServiceId
    start: str = TimeText
    end: str = TimeText


class AlertArgs(Args):
    start: str = TimeText
    end: str = TimeText
    service_id: str | None = Field(default=None, pattern=r"^SVC-[A-Z]{2,8}$")


class SupplierArgs(Args):
    supplier_id: str = SupplierId


class NoticeArgs(Args):
    supplier_id: str = SupplierId
    start: str = TimeText
    end: str = TimeText


class UseRecordArgs(Args):
    record_id: str = RecordId


class Suggestion(Args):
    fact: str = Field(min_length=1, max_length=60)
    value: bool | int | str | list[str] = Field(description="true/false, a whole number, an ISO time, or country codes")
    reason: str = Field(min_length=1, max_length=300, description="Short quote or reason from the ticket")


class SuggestArgs(Args):
    suggestions: list[Suggestion] = Field(min_length=1, max_length=30)


class AskArgs(Args):
    facts: list[str] = Field(min_length=1, max_length=20, description="Fact names whose fixed question to ask")


class ToolOutcome(BaseModel):
    """What one tool call did. `content` goes back to the LLM (as untrusted data); the rest goes to the log."""

    model_config = ConfigDict(frozen=True)

    tool: str
    ok: bool
    content: dict[str, Any]
    facts_recorded: tuple[str, ...] = ()
    error: str | None = None


@dataclass
class RunContext:
    """State of one run that tools may read and update. Held by plain code only."""

    reported_at: datetime  # when the incident was reported (from outside; Sam, block 5 answer 4)
    as_of: datetime  # time of the check, passed to the rules engine
    incident_service: str | None = None
    offered: dict[str, tuple[str, Any]] = field(default_factory=dict)  # record_id -> (kind, record)
    adopted: dict[str, str] = field(default_factory=dict)  # kind -> record_id (one record per kind)
    pending_questions: list[str] = field(default_factory=list)
    last_classification: Classification | None = None


@dataclass(frozen=True)
class _Tool:
    spec: ToolSpec
    args: type[Args]
    handler: Callable[["Toolbox", Any], ToolOutcome]


class Toolbox:
    def __init__(self, store: FactStore, context: RunContext):
        self._store = store
        self._view = store.agent_view()  # the only way suggestions get in
        self.context = context
        self._tools = {tool.spec.name: tool for tool in _TOOLS}

    def specs(self) -> list[ToolSpec]:
        return [tool.spec for tool in self._tools.values()]

    def run(self, call: ToolCall) -> ToolOutcome:
        tool = self._tools.get(call.name)
        if tool is None:
            return _refused(call.name[:60], "unknown tool")
        if not call.arguments_valid:
            return _refused(call.name, "arguments are not a JSON object")
        try:
            args = tool.args.model_validate(call.arguments)
        except ValidationError as error:
            # Field names only, never the input values, so hostile text does not travel back.
            fields = sorted({".".join(str(p) for p in e["loc"]) or "arguments" for e in error.errors()})
            return _refused(call.name, f"invalid arguments: {', '.join(fields)[:200]}")
        try:
            outcome = tool.handler(self, args)
        except (InvalidQuery, ValueProblem) as problem:
            return _refused(call.name, str(problem)[:300])
        text = json.dumps(outcome.content, default=str)
        if len(text) > MAX_TOOL_RESULT_CHARS:
            return _refused(call.name, "result too large; narrow the search")
        return outcome

    # ---------- helpers for handlers ----------

    def _is_incident_service(self, service_id: str | None) -> bool:
        return service_id is not None and service_id == self.context.incident_service

    def _offer_or_adopt(self, kind: str, records: list, record_id: Callable[[Any], str],
                        mapper: Callable[[FactStore, Any], list[str]], may_record: bool) -> tuple[list[str], str]:
        """One matching record: adopt it. Several: offer them; the LLM picks one with use_record."""
        if not may_record:
            return [], "information only: facts are recorded only for the incident service (call get_service first)"
        if kind in self.context.adopted:
            return [], f"information only: a {kind} record ({self.context.adopted[kind]}) is already in use"
        if len(records) == 1:
            self.context.adopted[kind] = record_id(records[0])
            return mapper(self._store, records[0]), f"record {record_id(records[0])} used for this incident"
        if not records:
            return [], "no records found"
        for record in records:
            self.context.offered[record_id(record)] = (kind, record)
        ids = ", ".join(record_id(r) for r in records)
        return [], f"several records ({ids}): call use_record with the one that matches this incident"


def _refused(tool: str, reason: str) -> ToolOutcome:
    return ToolOutcome(tool=tool, ok=False, content={"error": reason}, error=reason)


def _ok(tool: str, content: dict, recorded: list[str] = (), note: str | None = None) -> ToolOutcome:
    if note:
        content = {**content, "note": note}
    if recorded:
        content = {**content, "facts_recorded": list(recorded)}
    return ToolOutcome(tool=tool, ok=True, content=content, facts_recorded=tuple(recorded))


def _dump(model) -> dict:
    return model.model_dump(mode="json")


# ---------- handlers: bank systems (read-only) ----------


def _find_service(box: Toolbox, args: FindServiceArgs) -> ToolOutcome:
    return _ok("find_service", _dump(connectors.find_service(args.text)))


def _get_service(box: Toolbox, args: ServiceArgs) -> ToolOutcome:
    result = connectors.get_service(args.service_id)
    if not result.found:
        return _ok("get_service", _dump(result), note="service not found")
    if box.context.incident_service is None:
        box.context.incident_service = args.service_id
        recorded = mapping.map_service(box._store, result.service)
        return _ok("get_service", _dump(result), recorded, note=f"{args.service_id} is now the incident service")
    if box._is_incident_service(args.service_id):
        return _ok("get_service", _dump(result), note="already the incident service")
    return _ok("get_service", _dump(result),
               note=f"information only: the incident service is {box.context.incident_service}")


def _get_outage_timeline(box: Toolbox, args: TimelineArgs) -> ToolOutcome:
    around = args.around or box.context.reported_at
    result = connectors.get_outage_timeline(args.service_id, around, args.window_hours)
    recorded, note = box._offer_or_adopt("monitoring", list(result.problems), lambda p: p.problem_id,
                                         mapping.map_problem, box._is_incident_service(args.service_id))
    return _ok("get_outage_timeline", _dump(result), recorded, note)


def _get_client_impact(box: Toolbox, args: WindowArgs) -> ToolOutcome:
    result = connectors.get_client_impact(args.service_id, args.start, args.end)
    recorded, note = box._offer_or_adopt("client_impact", list(result.impacts), lambda i: i.impact_id,
                                         mapping.map_impact, box._is_incident_service(args.service_id))
    return _ok("get_client_impact", _dump(result), recorded, note)


def _get_daily_averages(box: Toolbox, args: ServiceArgs) -> ToolOutcome:
    # The date is chosen by plain code, not the LLM: the incident's earliest known time, else the reported time.
    facts = box._store.snapshot()
    start = facts.usable("incident_start") or facts.usable("detected_at") or box.context.reported_at
    result = connectors.get_daily_averages(args.service_id, start.date().isoformat())
    if not box._is_incident_service(args.service_id):
        return _ok("get_daily_averages", _dump(result), note="information only: not the incident service")
    return _ok("get_daily_averages", _dump(result), mapping.map_daily_averages(box._store, result))


def _get_security_alerts(box: Toolbox, args: AlertArgs) -> ToolOutcome:
    result = connectors.get_security_alerts(args.start, args.end, args.service_id)
    service = box.context.incident_service
    relevant = [a for a in result.alerts if service is None or service in a.service_ids]
    # Alerts may be adopted before the service is known (case B03 starts with the SOC alert).
    recorded, note = box._offer_or_adopt("security_alert", relevant, lambda a: a.alert_id, mapping.map_alert, True)
    return _ok("get_security_alerts", _dump(result), recorded, note)


def _get_suppliers_for_service(box: Toolbox, args: ServiceArgs) -> ToolOutcome:
    return _ok("get_suppliers_for_service", _dump(connectors.get_suppliers_for_service(args.service_id)),
               note="information only: supplier data is not turned into facts; suggest facts if needed")


def _get_supplier(box: Toolbox, args: SupplierArgs) -> ToolOutcome:
    return _ok("get_supplier", _dump(connectors.get_supplier(args.supplier_id)), note="information only")


def _get_supplier_notices(box: Toolbox, args: NoticeArgs) -> ToolOutcome:
    return _ok("get_supplier_notices", _dump(connectors.get_supplier_notices(args.supplier_id, args.start, args.end)),
               note="information only: supplier data is not turned into facts; suggest facts if needed")


def _use_record(box: Toolbox, args: UseRecordArgs) -> ToolOutcome:
    offered = box.context.offered.get(args.record_id)
    if offered is None:
        return _refused("use_record", "that record was not offered in this run")
    kind, record = offered
    if kind in box.context.adopted:
        return _refused("use_record", f"a {kind} record ({box.context.adopted[kind]}) is already in use")
    mapper = {"monitoring": mapping.map_problem, "client_impact": mapping.map_impact,
              "security_alert": mapping.map_alert}[kind]
    box.context.adopted[kind] = args.record_id
    return _ok("use_record", {"record_id": args.record_id}, mapper(box._store, record))


# ---------- handlers: suggestions, questions, rules ----------


def _suggest_facts(box: Toolbox, args: SuggestArgs) -> ToolOutcome:
    results = []
    for s in args.suggestions:
        try:
            results.append(box._view.suggest(s.fact, s.value, s.reason))
        except ValueProblem as problem:
            results.append(f"{s.fact[:60]}: not stored ({problem})")
    return _ok("suggest_facts", {"results": results,
                                 "note": "suggestions are not used until a human confirms them in one review"})


def _ask_human(box: Toolbox, args: AskArgs) -> ToolOutcome:
    unknown = [f[:60] for f in args.facts if f not in QUESTIONS]
    if unknown:
        return _refused("ask_human", f"no fixed question for: {', '.join(unknown)}")
    for name in args.facts:
        if name not in box.context.pending_questions:
            box.context.pending_questions.append(name)
    return _ok("ask_human", {"queued": [QUESTIONS[n].text for n in box.context.pending_questions],
                             "note": "the run pauses here; the human answers these and reviews all suggestions"})


def _run_rules(box: Toolbox, args: NoArgs) -> ToolOutcome:
    result = classify(box._store.snapshot(), box.context.as_of)
    box.context.last_classification = result
    return _ok("run_rules", {
        "result": result.result,
        "summary": result.summary,
        "thresholds_met": list(result.thresholds_met),
        "missing": list(result.missing),
        "waiting_for_human": list(result.pending_confirmations),
        "conflicts": [c.describe() for c in box._store.conflicts()],
    })


def _spec(name: str, description: str, args: type[Args]) -> ToolSpec:
    schema = args.model_json_schema()
    schema.pop("title", None)
    return ToolSpec(name=name, description=description, parameters=schema)


_TOOLS = [
    _Tool(_spec("find_service", "Find the bank service a ticket is about, from a few words.", FindServiceArgs),
          FindServiceArgs, _find_service),
    _Tool(_spec("get_service", "Look up one service: is it critical or important, is it regulated. "
                "The first service found becomes the incident service.", ServiceArgs), ServiceArgs, _get_service),
    _Tool(_spec("get_outage_timeline", "Monitoring: when the service went down and came back.", TimelineArgs),
          TimelineArgs, _get_outage_timeline),
    _Tool(_spec("get_client_impact", "Client data: affected clients, counterparts, transactions, countries.",
                WindowArgs), WindowArgs, _get_client_impact),
    _Tool(_spec("get_daily_averages", "Client data: totals and daily averages to compare the impact against.",
                ServiceArgs), ServiceArgs, _get_daily_averages),
    _Tool(_spec("get_security_alerts", "Security alerts: signs of hacking, malicious access or data loss.",
                AlertArgs), AlertArgs, _get_security_alerts),
    _Tool(_spec("get_suppliers_for_service", "Supplier register: outside companies that run a service.",
                ServiceArgs), ServiceArgs, _get_suppliers_for_service),
    _Tool(_spec("get_supplier", "Supplier register: one supplier by ID.", SupplierArgs), SupplierArgs, _get_supplier),
    _Tool(_spec("get_supplier_notices", "Messages from a supplier about an incident on its side.", NoticeArgs),
          NoticeArgs, _get_supplier_notices),
    _Tool(_spec("use_record", "When a lookup returned several records, pick the one about this incident.",
                UseRecordArgs), UseRecordArgs, _use_record),
    _Tool(_spec("suggest_facts", "Suggest facts read from the ticket. A human reviews all of them in one go; "
                "they are not used until confirmed.", SuggestArgs), SuggestArgs, _suggest_facts),
    _Tool(_spec("ask_human", "Queue fixed questions for facts only a human can answer.", AskArgs),
          AskArgs, _ask_human),
    _Tool(_spec("run_rules", "Run the DORA rules engine on the facts so far. Returns the result and what is "
                "still missing.", NoArgs), NoArgs, _run_rules),
]
