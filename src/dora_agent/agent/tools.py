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

What the LLM sees (C01 live test, approved by Sam on 13 November 2026): the bank lookups are not offered one by
one. The LLM lists the lookups it wants in ONE `lookups` call (the model made one tool call per answer even with
parallel calls switched on), and the loop runs each of them through `Toolbox.run`, checked like any other call.
The LLM still chooses every lookup and its arguments. run_rules is no longer a tool: after every step, plain
code runs the rules engine and adds a short status (`status` below). The engine is the only source of the
classification (hard rule 1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from dora_agent import connectors
from dora_agent.agent import mapping
from dora_agent.agent.fact_store import FactStore
from dora_agent.agent.questions import QUESTIONS, SERVICE_QUESTION, SERVICE_QUESTION_TEXT
from dora_agent.agent.values import ValueProblem
from dora_agent.config import agent_limits
from dora_agent.connectors import InvalidQuery
from dora_agent.llm.provider import ToolCall, ToolSpec
from dora_agent.rules import Classification, classify
from dora_agent.rules.thresholds import UNKNOWN


ServiceId = Field(pattern=r"^SVC-[A-Z]{2,8}$")
SupplierId = Field(pattern=r"^SUP-[A-Z]{2,8}$")
TimeText = Field(min_length=1, max_length=40, description="ISO 8601 with zone")
RecordId = Field(pattern=r"^(PRB|IMP|ALR)-\d{4}$")


class Args(BaseModel):
    """Base for tool arguments: no extra fields, so nothing can be smuggled in (e.g. 'confirmed_by')."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class FindServiceArgs(Args):
    text: str = Field(min_length=1, max_length=100, description="A few words from the ticket")


class ServiceArgs(Args):
    service_id: str = ServiceId


class TimelineArgs(Args):
    service_id: str = ServiceId
    around: str | None = Field(default=None, min_length=1, max_length=40,
                               description="ISO 8601 with zone. Default: reported time")
    window_hours: int = Field(default=24, ge=1, le=72)


class ImpactArgs(Args):
    """Window hardening (approved by Sam on 13 November 2026): start and end may be left out. Code then uses
    the known outage times (see _impact_window), so the search window follows the incident."""

    service_id: str = ServiceId
    start: str | None = Field(default=None, min_length=1, max_length=40,
                              description="ISO 8601 with zone. Leave out: code uses the known incident start")
    end: str | None = Field(default=None, min_length=1, max_length=40,
                            description="ISO 8601 with zone. Leave out: code uses the known restore time")


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
    value: bool | int | str | list[str] = Field(description="true/false, number, ISO time, or country codes")
    reason: str = Field(min_length=1, max_length=300, description="Short quote from the ticket")


class SuggestArgs(Args):
    suggestions: list[Suggestion] = Field(min_length=1, max_length=30)


class AskArgs(Args):
    facts: list[str] = Field(min_length=1, max_length=20, description="Fact names")


# The read-only bank lookups the LLM may list in one `lookups` call.
LookupName = Literal["find_service", "get_service", "get_outage_timeline", "get_client_impact",
                     "get_daily_averages", "get_security_alerts", "get_suppliers_for_service", "get_supplier",
                     "get_supplier_notices"]


class LookupItem(Args):
    tool: LookupName
    args: dict[str, Any] = Field(description="That lookup's arguments, see the tool description")


class LookupsArgs(Args):
    # The per-answer limit (config.toml [agent] max_tool_calls_per_step) is applied by the loop, per lookup.
    calls: list[LookupItem] = Field(min_length=1, max_length=20)


class ToolOutcome(BaseModel):
    """What one tool call did. `content` goes back to the LLM (as untrusted data); the rest goes to the log."""

    model_config = ConfigDict(frozen=True)

    tool: str
    ok: bool
    content: dict[str, Any]
    facts_recorded: tuple[str, ...] = ()
    error: str | None = None
    repeat: bool = False  # True if this was a repeated identical lookup, answered from memory
    # True if a lookup that records facts only for the incident service ran before that service was known,
    # so it recorded nothing. Logged, so an "ok" with no facts can be told apart in the decision log.
    before_service: bool = False


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
    alerts_checked: bool = False  # used by the gate check in loop.py
    # Services find_service returned in this run (ID -> name), the only choices of the service question.
    candidates: dict[str, str] = field(default_factory=dict)
    # Block 5 step 5 (approved by Sam): never ask the same question twice in one run.
    asked: set[str] = field(default_factory=set)
    # Lookups that ran successfully: (tool, service_id or None). Used to tell when only a human can help.
    lookups_done: set[tuple[str, str | None]] = field(default_factory=set)
    # Earlier results of read-only lookups, by tool and exact arguments (repeated calls).
    remembered: dict[str, dict[str, Any]] = field(default_factory=dict)
    repeats: int = 0
    # The facts (and conflicts) the LLM's last FULL status was based on. If nothing changed since, the status
    # is short (block 6, C01 live test, approved by Sam on 11 November 2026).
    status_seen: str | None = None

    def queue_question(self, name: str) -> bool:
        """Queue a fixed question unless it was already asked in this run. True if it was queued."""
        if name in self.asked:
            return False
        self.asked.add(name)
        self.pending_questions.append(name)
        return True

    def lookup_done(self, tool: str) -> bool:
        """Has this system lookup already run for the incident? Security alerts count for any service."""
        if tool == "get_security_alerts":
            return self.alerts_checked
        if tool == "get_service":
            return self.incident_service is not None
        return self.incident_service is not None and (tool, self.incident_service) in self.lookups_done


@dataclass(frozen=True)
class _Tool:
    spec: ToolSpec
    args: type[Args]
    handler: Callable[["Toolbox", Any], ToolOutcome]


class Toolbox:
    def __init__(self, store: FactStore, context: RunContext, max_result_chars: int | None = None,
                 impact_default_days: int | None = None):
        self._store = store
        self._view = store.agent_view()  # the only way suggestions get in
        self.context = context
        # Longest tool result (as JSON text) sent back to the LLM: config.toml [agent].
        self._max_result_chars = max_result_chars or agent_limits().max_tool_result_chars
        # get_client_impact without a window: days around the reported time if outage times are not known.
        self.impact_default_days = impact_default_days or agent_limits().client_impact_default_days
        self._tools = {tool.spec.name: tool for tool in _TOOLS}

    def specs(self) -> list[ToolSpec]:
        """What the LLM is offered: one `lookups` tool for all bank lookups, plus use_record, suggest_facts
        and ask_human. The single lookups stay callable (by name, checked the same way), but are not listed."""
        return [LOOKUPS_SPEC] + [self._tools[name].spec for name in OFFERED]

    def expand(self, call: ToolCall) -> list[ToolCall] | ToolOutcome:
        """Turn one `lookups` call into the single lookups it lists, or a refusal if it is malformed.

        Only the outer shape is checked here; each lookup's own arguments are checked by `run`, like any call.
        """
        if not call.arguments_valid:
            return _refused("lookups", "arguments are not a JSON object")
        try:
            args = LookupsArgs.model_validate(call.arguments)
        except ValidationError as error:
            fields = sorted({".".join(str(p) for p in e["loc"]) or "arguments" for e in error.errors()})
            return _refused("lookups", f"invalid arguments: {', '.join(fields)[:200]}")
        return [ToolCall(call_id=f"{call.call_id}-{i}", name=item.tool, arguments=item.args,
                         raw_arguments=json.dumps(item.args, default=str)[:500])
                for i, item in enumerate(args.calls)]

    def run(self, call: ToolCall) -> ToolOutcome:
        tool = self._tools.get(call.name)
        if tool is None:
            if call.name == "run_rules":
                return _refused("run_rules", RUN_RULES_GONE)
            return _refused(call.name[:60], "unknown tool")
        if not call.arguments_valid:
            return _refused(call.name, "arguments are not a JSON object")
        try:
            args = tool.args.model_validate(call.arguments)
        except ValidationError as error:
            # Field names only, never the input values, so hostile text does not travel back.
            fields = sorted({".".join(str(p) for p in e["loc"]) or "arguments" for e in error.errors()})
            return _refused(call.name, f"invalid arguments: {', '.join(fields)[:200]}")
        key = self._memory_key(call.name, args)
        if key is not None and key in self.context.remembered:
            # Same lookup, same arguments: the bank data has not changed, so give back the earlier result
            # instead of calling the system again. Counted in the loop and in the decision log.
            self.context.repeats += 1
            return ToolOutcome(tool=call.name, ok=True, repeat=True,
                               content={**self.context.remembered[key], "note": REPEAT_NOTE})
        # Checked before the handler runs: get_service is the only tool that sets the incident service.
        before_service = call.name in SERVICE_BOUND and self.context.incident_service is None
        try:
            outcome = tool.handler(self, args)
        except (InvalidQuery, ValueProblem) as problem:
            return _refused(call.name, str(problem)[:300])
        text = json.dumps(outcome.content, default=str)
        if len(text) > self._max_result_chars:
            return _refused(call.name, "result too large; narrow the search")
        if before_service:
            # Bug fix (C01 live test, approved by Sam on 11 November 2026): this result recorded nothing
            # only because the service was not known yet. So it is not remembered and does not count as
            # done: the same call after get_service runs again and records the facts.
            return outcome.model_copy(update={"before_service": True})
        if outcome.ok and call.name in LOOKUPS:
            self.context.lookups_done.add((call.name, getattr(args, "service_id", None)))
            if key is not None:
                self.context.remembered[key] = {k: v for k, v in outcome.content.items()
                                                if k not in ("note", "facts_recorded")}
        return outcome

    def _memory_key(self, name: str, args: Args) -> str | None:
        """Key for remembering a read-only lookup: tool name plus exact arguments. None = never remembered."""
        if name not in LOOKUPS:
            return None
        extra = None
        if name == "get_daily_averages":
            extra = _daily_averages_date(self)  # the date is chosen by code and can change during a run
        return json.dumps([name, args.model_dump(mode="json"), extra], sort_keys=True, default=str)

    # ---------- helpers for handlers ----------

    def _is_incident_service(self, service_id: str | None) -> bool:
        return service_id is not None and service_id == self.context.incident_service

    def _offer_or_adopt(self, kind: str, records: list, record_id: Callable[[Any], str],
                        mapper: Callable[[FactStore, Any], list[str]], may_record: bool) -> tuple[list[str], str]:
        """One matching record: adopt it. Several: offer them; the LLM picks one with use_record."""
        if not may_record:
            return [], NOT_YET_NOTE
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


# Read-only bank lookups. Only these are remembered for repeats; run_rules, ask_human, suggest_facts
# and use_record always run, because their result can change during a run.
LOOKUPS = frozenset({
    "find_service", "get_service", "get_outage_timeline", "get_client_impact", "get_daily_averages",
    "get_security_alerts", "get_suppliers_for_service", "get_supplier", "get_supplier_notices",
})
# Lookups that record facts only for the incident service (see _offer_or_adopt and _get_daily_averages).
# Security alerts are not here: they may be used before the service is known (case B03).
SERVICE_BOUND = frozenset({"get_outage_timeline", "get_client_impact", "get_daily_averages"})
NOT_YET_NOTE = "information only: facts are recorded only for the incident service (call get_service first)"
REPEAT_NOTE = ("repeated call: same result as before, nothing new. Choose another tool from where_to_find, "
               "or ask_human.")
RUN_RULES_GONE = ("run_rules is not a tool: the rules engine runs after every step, and its result comes to you "
                  "as the status")
# Run order inside one answer (loop.py): get_service first, because lookups only record facts for the incident
# service, which get_service sets (C01 live test, 11 November 2026). Then the outage timeline, so a client
# impact search without a window can follow the outage times it records (13 November 2026). Then the rest.
RUN_FIRST = {"get_service": 0, "get_outage_timeline": 1}


def _refused(tool: str, reason: str) -> ToolOutcome:
    return ToolOutcome(tool=tool, ok=False, content={"error": reason}, error=reason)


def _ok(tool: str, content: dict, recorded: list[str] = (), note: str | None = None) -> ToolOutcome:
    if note:
        content = {**content, "note": note}
    if recorded:
        content = {**content, "facts_recorded": list(recorded)}
    return ToolOutcome(tool=tool, ok=True, content=content, facts_recorded=tuple(recorded))


# Parts of a connector result the LLM does not need to choose its next tool (shorter prompts, approved by Sam
# on 11 November 2026). "source" names the system and record IDs: record IDs are still in each record, and
# where every fact came from is written to the decision log by the fact store. "method" is a fixed text.
# "event_id" is internal to monitoring (the record to pick is the problem_id). Fields with no value (null)
# are left out too: a field that is not there means the system does not know it.
_NOT_FOR_LLM = frozenset({"source", "method", "event_id"})


def _dump(model) -> dict:
    return _for_llm(model.model_dump(mode="json"))


def _for_llm(node):
    if isinstance(node, dict):
        return {k: _for_llm(v) for k, v in node.items() if k not in _NOT_FOR_LLM and v is not None}
    if isinstance(node, list):
        return [_for_llm(v) for v in node]
    return node


# ---------- handlers: bank systems (read-only) ----------


SEVERAL_NOTE = ("several services match. Before get_service, check each of them in one lookups call "
                "(get_outage_timeline and get_client_impact for each). Then call get_service for the service whose "
                "records show this incident. If the records do not tell them apart, call ask_human with "
                f'["{SERVICE_QUESTION}"].')


def _find_service(box: Toolbox, args: FindServiceArgs) -> ToolOutcome:
    result = connectors.find_service(args.text)
    for match in result.matches:
        box.context.candidates.setdefault(match.service_id, match.name)
    several = len(result.matches) > 1 and box.context.incident_service is None
    return _ok("find_service", _dump(result), note=SEVERAL_NOTE if several else None)


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


def _get_client_impact(box: Toolbox, args: ImpactArgs) -> ToolOutcome:
    start, end = _impact_window(box, args)
    result = connectors.get_client_impact(args.service_id, start, end)
    recorded, note = box._offer_or_adopt("client_impact", list(result.impacts), lambda i: i.impact_id,
                                         mapping.map_impact, box._is_incident_service(args.service_id))
    content = _dump(result)
    if args.start is None or args.end is None:
        # The window code chose, so the LLM and the decision log can see where it looked.
        content["window_used"] = {"start": _iso(start), "end": _iso(end)}
    return _ok("get_client_impact", content, recorded, note)


# The longest window get_client_impact accepts (config.toml [connectors] max_impact_window_days is 366).
_MAX_DEFAULT_WINDOW = timedelta(days=366)


def _iso(value: Any) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def _impact_window(box: Toolbox, args: ImpactArgs) -> tuple[Any, Any]:
    """The search window: what the LLM gave, else the known outage times (window hardening, Sam, 13 Nov 2026).

    Start: the earliest known of incident start and downtime start. End: the latest known of service restored
    and resolved. If one is not known yet: the reported time minus client_impact_default_days, or the later of
    the reported time and the time of the check plus that many days. Plain code; it only picks where to look,
    never what a record means. A window the LLM gives is used as it is (the connector checks it).
    """
    facts = box._store.snapshot()
    days = timedelta(days=box.impact_default_days)
    starts = [t for t in (facts.usable("incident_start"), facts.usable("downtime_start")) if t is not None]
    ends = [t for t in (facts.usable("service_restored_at"), facts.usable("resolved_at")) if t is not None]
    if args.start is not None:
        start = args.start
    else:
        start = min(starts) if starts else box.context.reported_at - days
    if args.end is not None:
        return start, args.end
    end = max(ends) if ends else max(box.context.reported_at, box.context.as_of) + days
    begin = _as_time(start)  # a start the LLM gave is text; if it is not a valid time, the connector refuses it
    if begin is not None:
        # Never empty, never longer than the connector allows (a record overlapping the start is still found).
        end = min(max(end, begin + timedelta(hours=1)), begin + _MAX_DEFAULT_WINDOW)
    return start, end


def _as_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _get_daily_averages(box: Toolbox, args: ServiceArgs) -> ToolOutcome:
    # The date is chosen by plain code, not the LLM: the incident's earliest known time, else the reported time.
    result = connectors.get_daily_averages(args.service_id, _daily_averages_date(box))
    if box.context.incident_service is None:
        return _ok("get_daily_averages", _dump(result), note=NOT_YET_NOTE)
    if not box._is_incident_service(args.service_id):
        return _ok("get_daily_averages", _dump(result), note="information only: not the incident service")
    return _ok("get_daily_averages", _dump(result), mapping.map_daily_averages(box._store, result))


def _daily_averages_date(box: Toolbox) -> str:
    facts = box._store.snapshot()
    start = facts.usable("incident_start") or facts.usable("detected_at") or box.context.reported_at
    return start.date().isoformat()


def _get_security_alerts(box: Toolbox, args: AlertArgs) -> ToolOutcome:
    result = connectors.get_security_alerts(args.start, args.end, args.service_id)
    box.context.alerts_checked = True
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


HELD_NOTE = "refused: already known from a system or a person (see known in the status)"


def _suggest_facts(box: Toolbox, args: SuggestArgs) -> ToolOutcome:
    results, refused = [], []
    for s in args.suggestions:
        if box._store.has_value(s.fact):
            # Already held from a system or a person: refused before anything is stored (approved by Sam on
            # 13 November 2026). The fact store would ignore it too; this says so plainly.
            refused.append(s.fact[:60])
            continue
        try:
            results.append(box._view.suggest(s.fact, s.value, s.reason))
        except ValueProblem as problem:
            results.append(f"{s.fact[:60]}: not stored ({problem})")
    if not results:
        return _refused("suggest_facts", f"{HELD_NOTE}: {', '.join(refused)}"[:300])
    content = {"results": results, "note": "suggestions are not used until a human confirms them in one review"}
    if refused:
        content["refused"] = refused
        content["refused_note"] = HELD_NOTE
    return _ok("suggest_facts", content)


def _ask_human(box: Toolbox, args: AskArgs) -> ToolOutcome:
    # Bug fix (C01 live test, approved by Sam on 11 November 2026): facts with a fixed question are queued
    # even if the same call also names facts without one. Those are listed back, never asked.
    names = list(dict.fromkeys(args.facts))
    service_problem = _service_question_problem(box.context) if SERVICE_QUESTION in names else None
    unknown = [f[:60] for f in names if f not in QUESTIONS and f != SERVICE_QUESTION]
    askable = [f for f in names if f in QUESTIONS or (f == SERVICE_QUESTION and service_problem is None)]
    if not askable:
        reasons = [f"no fixed question for: {', '.join(unknown)}"] if unknown else []
        reasons += [service_problem] if service_problem else []
        return _refused("ask_human", "; ".join(reasons)[:300])
    for name in askable:
        if name not in box.context.pending_questions:
            box.context.queue_question(name)
    pending = box.context.pending_questions
    already = [n for n in askable if n in box.context.asked and n not in pending]
    content = {"queued": [question_text(n) for n in box.context.pending_questions],
               "note": "the run pauses here; the human answers these and reviews all suggestions"}
    if already:
        content["already_asked"] = already  # never asked twice in one run
    if unknown:
        content["no_fixed_question"] = unknown
        content["no_fixed_question_note"] = NO_QUESTION_NOTE
    if service_problem:
        content["service_question_not_asked"] = service_problem
    if not box.context.pending_questions:
        content["note"] = "nothing new to ask: these were already asked in this run"
    return _ok("ask_human", content)


def _service_question_problem(context: RunContext) -> str | None:
    """Why the service question can't be asked now, or None if it can (C01 live test, Sam, 13 November 2026)."""
    if context.incident_service is not None:
        return f"{SERVICE_QUESTION} not asked: the incident service is already {context.incident_service}"
    if len(context.candidates) < 2:
        return (f"{SERVICE_QUESTION} not asked: it is only asked when find_service returned several services; "
                "use find_service, or get_service for the one service")
    return None


def question_text(name: str) -> str:
    """The fixed wording of a queued question (a fact question, or the service question)."""
    return SERVICE_QUESTION_TEXT if name == SERVICE_QUESTION else QUESTIONS[name].text


NO_QUESTION_NOTE = ("not asked: no fixed question exists. These come only from a bank system, or from the "
                    "ticket with suggest_facts.")


# Where the agent can find each fact: docs/dora-rules.md section 6, "Where Rheinbank keeps it".
# It guides the search only and decides nothing (hard rule 1). "ask_human" means a human answers or
# confirms (section 7); "suggest_facts" means the ticket may say it. A test checks every fact is covered.
_ALERTS_THEN_HUMAN = ("get_security_alerts", "ask_human")
WHERE_TO_FIND: dict[str, tuple[str, ...]] = {
    "planned_and_announced": ("get_outage_timeline", "ask_human"),  # open question 5
    "planned_window_end": ("get_outage_timeline",),  # open question 8
    "critical_or_important": ("get_service", "ask_human"),  # service list
    "regulated_service": ("get_service", "ask_human"),  # service list
    "malicious_access": _ALERTS_THEN_HUMAN,  # security alerts, human confirms
    "access_on_own_systems": _ALERTS_THEN_HUMAN,  # open question 4
    "access_may_cause_data_loss": ("ask_human",),  # T5-b
    "affected_clients": ("get_client_impact", "ask_human"),  # client data
    "total_clients": ("get_daily_averages",),
    "affected_counterparts": ("get_client_impact", "ask_human"),
    "total_counterparts": ("get_daily_averages",),
    "affected_tx_count": ("get_client_impact",),
    "daily_avg_tx_count": ("get_daily_averages",),
    "affected_tx_value_eur": ("get_client_impact",),
    "daily_avg_tx_value_eur": ("get_daily_averages",),
    "relevant_parties_affected": ("get_client_impact", "ask_human"),  # client data, human confirms
    "media_coverage": ("ask_human",),  # T2: human
    "repeated_complaints": ("ask_human",),
    "regulatory_requirements_impact": ("ask_human",),
    "client_loss_impact": ("ask_human",),
    "incident_start": ("get_outage_timeline", "suggest_facts"),  # monitoring, ticket
    "detected_at": ("get_outage_timeline", "suggest_facts"),
    "earliest_log_at": ("get_security_alerts",),  # RTS-C Art. 3(1)
    "resolved_at": ("get_outage_timeline", "ask_human"),
    "downtime_start": ("get_outage_timeline",),  # monitoring
    "service_restored_at": ("get_outage_timeline",),
    "backlog_cleared_at": ("get_outage_timeline",),
    # Client data, supplier register (section 6). Supplier data is never turned into facts (mapping.py), so
    # the register feeds a suggestion: get_suppliers_for_service, then suggest_facts. Pointing at the register
    # tool itself made the human-only check wait for a lookup that can never record this fact (C01 live test).
    "affected_member_states": ("get_client_impact", "suggest_facts"),
    "data_availability_impact": _ALERTS_THEN_HUMAN,  # T5-a: security alerts, human confirms
    "data_authenticity_impact": _ALERTS_THEN_HUMAN,
    "data_integrity_impact": _ALERTS_THEN_HUMAN,
    "data_confidentiality_impact": _ALERTS_THEN_HUMAN,
    "data_impact_adverse": ("ask_human",),  # T5-a: human
    "costs_eur": ("ask_human",),  # T6: human
}

# Step 0 (is it an incident at all?) comes before the gate: open questions 5 and 8, DORA Art. 3(8).
_INCIDENT_FACTS = ("planned_and_announced", "planned_window_end")


def check_first(result: Classification) -> list[str]:
    """Missing facts that can settle the case on their own, in the order the engine uses them.

    Step 0 facts first (an event that is not an incident is never classified), then the gate facts,
    because major = gate AND thresholds (RTS-C Art. 8(1)): if the gate fails, no threshold matters.
    Read from the engine's own result; no rule is repeated here.
    """
    first = [name for name in result.missing if name in _INCIDENT_FACTS]
    if result.gate is not None and result.gate.status == UNKNOWN:
        first += [name for name in result.gate.missing if name not in first]
    return first


def where_to_find(missing: tuple[str, ...]) -> dict[str, list[str]]:
    """For each tool, the missing facts it can supply (grouped by tool: shorter, and easy to act on)."""
    grouped: dict[str, list[str]] = {}
    for name in missing:
        for tool in WHERE_TO_FIND.get(name, ("suggest_facts",)):
            grouped.setdefault(tool, []).append(name)
    return grouped


UNCHANGED_NOTE = ("no fact changed since the last status: same result, same missing facts. Use that "
                  "status's where_to_find, or ask_human, or stop.")


def status(store: FactStore, context: RunContext, result: Classification | None = None) -> dict[str, Any]:
    """The short status plain code adds after every step (approved by Sam on 13 November 2026).

    It replaces the run_rules tool: the LLM no longer spends a step to see the engine's result. The result
    comes only from the rules engine (hard rule 1); this only reports it, with where to look next.
    """
    facts = store.snapshot()
    result = result or classify(facts, context.as_of)
    context.last_classification = result
    conflicts = [c.describe() for c in store.conflicts()]
    # Same facts and conflicts in, same result out: the engine is plain code (hard rule 1). So the full
    # status, which the LLM already has, is not sent again. The result word is always sent.
    seen = json.dumps([facts.model_dump(mode="json"), conflicts, context.incident_service],
                      sort_keys=True, default=str)
    if seen == context.status_seen:
        return {"result": result.result, "unchanged": True, "note": UNCHANGED_NOTE}
    context.status_seen = seen
    content = {
        "result": result.result,
        "incident_service": context.incident_service or "not chosen yet: get_service",
        "thresholds_met": list(result.thresholds_met),
        "check_first": check_first(result),
        # Every missing fact is in where_to_find (a test checks), so a separate "missing" list is not sent.
        # The full list stays in the code (last_classification) and in the decision log.
        "where_to_find": where_to_find(result.missing),
        "waiting_for_human": list(result.pending_confirmations),
        # Facts already held from a system or a person, by name only: nothing to look up or suggest for them.
        "known": [name for name, fact in _facts_held(facts) if fact.source != "ai_suggestion"],
        "conflicts": conflicts,
    }
    # Empty lists are left out (shorter prompts); "result" and "where_to_find" are always sent.
    return {k: v for k, v in content.items() if v or k in ("result", "where_to_find")}


def _facts_held(facts) -> list[tuple[str, Any]]:
    return [(name, getattr(facts, name)) for name in type(facts).model_fields
            if name != "service_id" and getattr(facts, name).known]


def _spec(name: str, description: str, args: type[Args]) -> ToolSpec:
    # The schema is sent with every LLM call, so it is slimmed (shorter prompts, block 5 step 5):
    # pydantic's "title" labels and the length/count limits are left out of the copy the LLM sees.
    # The limits are NOT dropped: Toolbox.run checks every call against the full model (`args`) above.
    schema = args.model_json_schema()
    return ToolSpec(name=name, description=description, parameters=_slim(schema, schema.get("$defs", {})))


# Also left out of the copy the LLM sees (approved by Sam on 11 November 2026): "additionalProperties"
# (extra fields are still refused, Args has extra="forbid") and "default" (the defaults still apply in code).
_NOT_SENT = frozenset({"title", "minLength", "maxLength", "minItems", "maxItems", "additionalProperties",
                       "default"})


def _slim(node, defs: dict):
    if isinstance(node, dict):
        if "$ref" in node:  # put the shared part in place: one schema, no "$defs" section
            return _slim(defs[node["$ref"].rsplit("/", 1)[-1]], defs)
        options = node.get("anyOf")
        if isinstance(options, list) and {"type": "null"} in options and len(options) == 2:
            # "text or null" -> "text": the field is optional anyway (not in "required").
            other = next(o for o in options if o != {"type": "null"})
            node = {**{k: v for k, v in node.items() if k != "anyOf"}, **other}
        return {k: _slim(v, defs) for k, v in node.items()
                if k != "$defs" and not (k in _NOT_SENT and not isinstance(v, dict))}
    if isinstance(node, list):
        return [_slim(v, defs) for v in node]
    return node


# Short descriptions: the whole list is sent with every LLM call (approved by Sam on 11 November 2026).
_TOOLS = [
    _Tool(_spec("find_service", "Find the service a ticket is about.", FindServiceArgs),
          FindServiceArgs, _find_service),
    _Tool(_spec("get_service", "Critical? Regulated? The first one becomes the incident service.", ServiceArgs),
          ServiceArgs, _get_service),
    _Tool(_spec("get_outage_timeline", "Monitoring: outage times.", TimelineArgs),
          TimelineArgs, _get_outage_timeline),
    _Tool(_spec("get_client_impact", "Affected clients, transactions, countries.", ImpactArgs),
          ImpactArgs, _get_client_impact),
    _Tool(_spec("get_daily_averages", "Client totals and daily averages.", ServiceArgs),
          ServiceArgs, _get_daily_averages),
    _Tool(_spec("get_security_alerts", "Security alerts: malicious access, data impact.", AlertArgs),
          AlertArgs, _get_security_alerts),
    _Tool(_spec("get_suppliers_for_service", "Suppliers of a service.", ServiceArgs),
          ServiceArgs, _get_suppliers_for_service),
    _Tool(_spec("get_supplier", "One supplier.", SupplierArgs), SupplierArgs, _get_supplier),
    _Tool(_spec("get_supplier_notices", "A supplier's incident notices.", NoticeArgs),
          NoticeArgs, _get_supplier_notices),
    _Tool(_spec("use_record", "Pick one of several records offered.", UseRecordArgs), UseRecordArgs, _use_record),
    _Tool(_spec("suggest_facts", "Suggest facts from the ticket; a human confirms.", SuggestArgs),
          SuggestArgs, _suggest_facts),
    _Tool(_spec("ask_human", "Queue fixed questions for a human.", AskArgs), AskArgs, _ask_human),
]

# The tools listed for the LLM besides `lookups` (the single lookups are reached through `lookups`).
OFFERED = ("use_record", "suggest_facts", "ask_human")

# One line per lookup: its arguments ("?" = may be left out). Short, because it is sent with every LLM call.
LOOKUPS_SPEC = ToolSpec(
    name="lookups",
    description=(
        "Read-only bank lookups. List ALL you need now in one call (up to 6); they run in one step. "
        "find_service {text}; get_service {service_id}; get_outage_timeline {service_id, around?, window_hours?}; "
        "get_client_impact {service_id, start?, end?} (leave the window out: code uses the outage times); "
        "get_daily_averages {service_id}; get_security_alerts {start, end, service_id?}; "
        "get_suppliers_for_service {service_id}; get_supplier {supplier_id}; "
        "get_supplier_notices {supplier_id, start, end}. Times: ISO 8601 with zone."),
    parameters={
        "type": "object",
        "properties": {"calls": {"type": "array", "items": {
            "type": "object",
            "properties": {"tool": {"type": "string", "enum": list(LookupName.__args__)},
                           "args": {"type": "object"}},
            "required": ["tool", "args"]}}},
        "required": ["calls"],
    },
)
