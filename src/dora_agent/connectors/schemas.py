"""Fixed shapes for Rheinbank data records and connector results.

Every model is frozen (cannot be changed after creation) and rejects unknown fields.
Data files are checked against these shapes when loaded, and connectors can only
return these shapes (security framework, section 1: "checked against a fixed schema").
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

YesNoUnknown = Literal["yes", "no", "unknown"]
MemberState = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
ServiceId = Annotated[str, StringConstraints(pattern=r"^SVC-[A-Z]{2,8}$")]
SupplierId = Annotated[str, StringConstraints(pattern=r"^SUP-[A-Z]{2,8}$")]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=120)]
NoteText = Annotated[str, StringConstraints(min_length=1, max_length=2000)]


def _must_be_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("stored times must be UTC (ending in Z)")
    return value


UtcTime = Annotated[AwareDatetime, AfterValidator(_must_be_utc)]

EventType = Literal[
    "incident_start",  # when the incident happened (RTS-C Art. 3(1))
    "detected",  # when it was detected; used if the start is unknown (RTS-C Art. 3(1), 3(2))
    "unavailable_full",  # service fully unavailable: downtime starts (RTS-C Art. 3(2))
    "unavailable_partial",  # service partly unavailable: downtime starts too (RTS-C Art. 3(2))
    "restored",  # normal service restored
    "backlog_cleared",  # delayed service fully provided: downtime ends here if later (RTS-C Art. 3(2))
    "resolved",  # incident resolved: duration ends (RTS-C Art. 3(1))
    "planned_maintenance_start",  # planned window; DORA Art. 3(8), open question 5
    "planned_maintenance_end",
]


class Frozen(BaseModel):
    """Base for all models: immutable, strict types, no extra fields."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


# ---------- Records as stored in data/rheinbank/ ----------


class ServiceRecord(Frozen):
    """One entry in services.json (the simulated CMDB)."""

    service_id: ServiceId
    name: ShortText
    function_supported: ShortText
    aliases: tuple[ShortText, ...]
    # Feeds G-a and T3-b: does it support critical or important functions? (RTS-C Art. 6(a), Art. 9(3)(b))
    critical_or_important: YesNoUnknown
    criticality_note: NoteText | None
    # Feeds G-b: financial service that needs authorisation or registration? (RTS-C Art. 6(b))
    regulated_service: YesNoUnknown
    client_facing: bool
    member_states_served: tuple[MemberState, ...]
    supplier_ids: tuple[SupplierId, ...]
    owner_team: ShortText


class ServicesFile(Frozen):
    about: str
    services: tuple[ServiceRecord, ...]


class MonitoringEvent(Frozen):
    event_id: Annotated[str, StringConstraints(pattern=r"^EVT-\d{4}$")]
    event_type: EventType
    timestamp: UtcTime
    # Only for planned maintenance events: was the window announced to clients?
    announced: bool | None
    note: NoteText | None

    @model_validator(mode="after")
    def _announced_only_on_planned_events(self):
        planned = self.event_type.startswith("planned_")
        if planned and self.announced is None:
            raise ValueError(f"{self.event_id}: planned events must say if they were announced")
        if not planned and self.announced is not None:
            raise ValueError(f"{self.event_id}: only planned events carry 'announced'")
        return self


class MonitoringProblem(Frozen):
    """One outage or maintenance window: a group of events on one service, in time order."""

    problem_id: Annotated[str, StringConstraints(pattern=r"^PRB-\d{4}$")]
    service_id: ServiceId
    title: ShortText
    events: tuple[MonitoringEvent, ...]

    @model_validator(mode="after")
    def _events_in_time_order(self):
        if not self.events:
            raise ValueError(f"{self.problem_id}: needs at least one event")
        times = [event.timestamp for event in self.events]
        if times != sorted(times):
            raise ValueError(f"{self.problem_id}: events must be in time order")
        return self

    @property
    def first_time(self) -> datetime:
        return self.events[0].timestamp

    @property
    def last_time(self) -> datetime:
        return self.events[-1].timestamp


class MonitoringFile(Frozen):
    about: str
    problems: tuple[MonitoringProblem, ...]


Count = Annotated[int, Field(ge=0)]
Month = Annotated[str, StringConstraints(pattern=r"^\d{4}-(0[1-9]|1[0-2])$")]


class Branch(Frozen):
    city: ShortText
    member_state: MemberState


class BankProfile(Frozen):
    """Basic entity facts. Branches in other Member States matter for T4 (RTS-C Art. 4)."""

    name: ShortText
    entity_type: Literal["credit_institution"]
    microenterprise: bool  # open question 3: Rheinbank is not a microenterprise
    home_member_state: MemberState
    head_office_city: ShortText
    branches: tuple[Branch, ...]
    total_clients: Count
    as_of: date


class BankProfileFile(Frozen):
    about: str
    profile: BankProfile


class ClientBaseSnapshot(Frozen):
    """Who uses a service: the denominators for T1-a and T1-c (RTS-C Art. 9(1)(a), (c))."""

    snapshot_id: Annotated[str, StringConstraints(pattern=r"^CLB-\d{4}$")]
    service_id: ServiceId
    as_of: date
    total_clients_using_service: Count | None
    active_counterparts: Count | None


class ClientBaseFile(Frozen):
    about: str
    snapshots: tuple[ClientBaseSnapshot, ...]


class DailyAverage(Frozen):
    """Daily averages for one service over one calendar month: the base for T1-d and T1-e
    (RTS-C Art. 9(1)(d), (e)). Method: docs/dora-rules.md open question 6."""

    average_id: Annotated[str, StringConstraints(pattern=r"^AVG-\d{4}$")]
    service_id: ServiceId
    month: Month
    days_counted: Annotated[int, Field(ge=28, le=31)]
    daily_avg_tx_count: Count
    daily_avg_tx_value_eur: Count


class DailyAveragesFile(Frozen):
    about: str
    averages: tuple[DailyAverage, ...]


class ClientImpact(Frozen):
    """What an incident did to clients, counterparts and transactions in one time window.

    null (None) means the system does not know. It never means zero.
    """

    impact_id: Annotated[str, StringConstraints(pattern=r"^IMP-\d{4}$")]
    service_id: ServiceId
    window_start: UtcTime
    window_end: UtcTime
    affected_clients: Count | None  # T1-a, T1-b (RTS-C Art. 1(1))
    affected_counterparts: Count | None  # T1-c (RTS-C Art. 1(2))
    affected_tx_count: Count | None  # T1-d (RTS-C Art. 1(4))
    affected_tx_value_eur: Count | None  # T1-e (RTS-C Art. 1(4))
    accounts_with_balance_errors: Count | None  # integrity signal for T5-a (RTS-C Art. 5)
    relevant_parties_affected: YesNoUnknown  # T1-f (RTS-C Art. 1(3)); a human must confirm
    affected_member_states: tuple[MemberState, ...] | None  # T4 (RTS-C Art. 4)
    is_estimate: bool  # RTS-C Art. 1(5)
    estimate_basis: NoteText | None

    @model_validator(mode="after")
    def _check(self):
        if self.window_end < self.window_start:
            raise ValueError(f"{self.impact_id}: window ends before it starts")
        if self.is_estimate and not self.estimate_basis:
            raise ValueError(f"{self.impact_id}: an estimate must say what it is based on")
        return self


class ClientImpactFile(Frozen):
    about: str
    impacts: tuple[ClientImpact, ...]


CountryCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2}$")]
ImpactLevel = Literal["none", "suspected", "confirmed", "unknown"]
AlertType = Literal[
    "ransomware",
    "data_exfiltration",
    "ddos",
    "phishing",
    "supplier_compromise",
    "unauthorised_login",
    "endpoint_anomaly",
    "malware",
]


class DataImpact(Frozen):
    """The four data impacts of RTS-C Art. 5, feeding T5-a (RTS-C Art. 9(5)(a))."""

    availability: ImpactLevel
    authenticity: ImpactLevel
    integrity: ImpactLevel
    confidentiality: ImpactLevel


class SecurityAlert(Frozen):
    """One SIEM alert. Signals only: a human confirms G-c and T5-b (docs/dora-rules.md section 7)."""

    alert_id: Annotated[str, StringConstraints(pattern=r"^ALR-\d{4}$")]
    detected_at: UtcTime
    # Earliest sign in the logs; duration can start here (RTS-C Art. 3(1)).
    first_evidence_at: UtcTime | None
    severity: Literal["low", "medium", "high", "critical"]
    alert_type: AlertType
    service_ids: tuple[ServiceId, ...]
    # Own systems or a supplier's: open question 4 (G-c and T5-b only for the bank's own systems).
    where: Literal["own_systems", "supplier_systems", "unknown"]
    supplier_id: SupplierId | None
    # Feeds G-c (RTS-C Art. 6(c)) and T5-b (RTS-C Art. 9(5)(b)): was the access successful?
    access_successful: Literal["yes", "no", "blocked", "unknown"]
    malicious_suspected: YesNoUnknown
    data_impact: DataImpact
    data_volume_mb: Count | None
    destination_country: CountryCode | None
    status: Literal["open", "closed", "false_positive"]
    analyst_note: NoteText | None

    @model_validator(mode="after")
    def _check(self):
        if self.first_evidence_at is not None and self.first_evidence_at > self.detected_at:
            raise ValueError(f"{self.alert_id}: first evidence can't be after detection")
        if (self.where == "supplier_systems") != (self.supplier_id is not None):
            raise ValueError(f"{self.alert_id}: supplier_id is needed exactly when where is supplier_systems")
        if not self.service_ids:
            raise ValueError(f"{self.alert_id}: needs at least one service")
        return self


class SecurityAlertsFile(Frozen):
    about: str
    alerts: tuple[SecurityAlert, ...]


class SupplierRecord(Frozen):
    """One entry in the register of ICT third-party providers (DORA Art. 28(3))."""

    supplier_id: SupplierId
    name: ShortText
    function_provided: ShortText
    country: CountryCode
    services_provided: tuple[ServiceId, ...]
    # Background only: where it serves financial entities. Impact in other Member States comes
    # from the notice (member_states_affected), not from this list (T4, RTS-C Art. 4(c)).
    member_states_served: tuple[MemberState, ...]
    is_market_infrastructure: bool  # RTS-C Art. 4(c)
    supports_critical_function: YesNoUnknown
    contract_ref: ShortText  # kept in the register, never returned to the agent


class SuppliersFile(Frozen):
    about: str
    suppliers: tuple[SupplierRecord, ...]


class SupplierNotice(Frozen):
    """A message from a supplier about an incident on its side."""

    notice_id: Annotated[str, StringConstraints(pattern=r"^NTC-\d{4}$")]
    supplier_id: SupplierId
    received_at: UtcTime
    start: UtcTime
    end: UtcTime | None  # None: still ongoing, or the supplier hasn't said
    notice_type: Literal["outage", "breach", "cyber_attack", "faulty_update"]
    cyber_attack: YesNoUnknown
    bank_data_involved: YesNoUnknown  # T5-a signal (RTS-C Art. 5); a human confirms
    member_states_affected: tuple[MemberState, ...] | None  # T4 signal (RTS-C Art. 4(c)); None: not stated
    note: NoteText | None

    @model_validator(mode="after")
    def _check(self):
        if self.end is not None and self.end < self.start:
            raise ValueError(f"{self.notice_id}: ends before it starts")
        if self.received_at < self.start:
            raise ValueError(f"{self.notice_id}: received before the incident started")
        return self


class SupplierNoticesFile(Frozen):
    about: str
    notices: tuple[SupplierNotice, ...]


# ---------- Results returned to the agent ----------


class Source(Frozen):
    """Where a result came from, for the decision log (CLAUDE.md hard rule 9)."""

    system: str
    record_ids: tuple[str, ...]


class ServiceMatch(Frozen):
    service_id: ServiceId
    name: str


class FindServiceResult(Frozen):
    matches: tuple[ServiceMatch, ...]
    more_available: bool
    source: Source


class ServiceView(Frozen):
    """What get_service returns. Owner team and aliases are left out on purpose (data minimisation)."""

    service_id: ServiceId
    name: str
    function_supported: str
    critical_or_important: YesNoUnknown
    criticality_note: str | None
    regulated_service: YesNoUnknown
    client_facing: bool
    member_states_served: tuple[MemberState, ...]
    supplier_ids: tuple[SupplierId, ...]


class GetServiceResult(Frozen):
    found: bool
    service: ServiceView | None
    source: Source


class EventView(Frozen):
    event_id: str
    event_type: EventType
    timestamp: datetime
    announced: bool | None
    note: str | None


class ProblemView(Frozen):
    problem_id: str
    title: str
    events: tuple[EventView, ...]


class OutageTimelineResult(Frozen):
    """Raw event times only. Durations are worked out by the rules engine, not here."""

    service_known: bool
    problems: tuple[ProblemView, ...]
    more_available: bool
    searched_from: datetime
    searched_to: datetime
    source: Source


class BankProfileResult(Frozen):
    profile: BankProfile
    source: Source


class ImpactView(Frozen):
    impact_id: str
    window_start: datetime
    window_end: datetime
    affected_clients: int | None
    affected_counterparts: int | None
    affected_tx_count: int | None
    affected_tx_value_eur: int | None
    accounts_with_balance_errors: int | None
    relevant_parties_affected: YesNoUnknown
    affected_member_states: tuple[str, ...] | None
    is_estimate: bool
    estimate_basis: str | None


class ClientImpactResult(Frozen):
    service_known: bool
    impacts: tuple[ImpactView, ...]
    more_available: bool
    source: Source


class AlertView(Frozen):
    alert_id: str
    detected_at: datetime
    first_evidence_at: datetime | None
    severity: str
    alert_type: AlertType
    service_ids: tuple[str, ...]
    where: Literal["own_systems", "supplier_systems", "unknown"]
    supplier_id: str | None
    access_successful: Literal["yes", "no", "blocked", "unknown"]
    malicious_suspected: YesNoUnknown
    data_impact: DataImpact
    data_volume_mb: int | None
    destination_country: str | None
    status: Literal["open", "closed", "false_positive"]
    analyst_note: str | None


class SecurityAlertsResult(Frozen):
    """service_known is None when no service filter was given."""

    service_known: bool | None
    alerts: tuple[AlertView, ...]
    more_available: bool
    source: Source


class SupplierView(Frozen):
    """What the agent sees about a supplier. The contract reference is left out (data minimisation)."""

    supplier_id: str
    name: str
    function_provided: str
    country: str
    services_provided: tuple[str, ...]
    member_states_served: tuple[str, ...]
    is_market_infrastructure: bool
    supports_critical_function: YesNoUnknown


class SuppliersForServiceResult(Frozen):
    service_known: bool
    suppliers: tuple[SupplierView, ...]
    source: Source


class GetSupplierResult(Frozen):
    found: bool
    supplier: SupplierView | None
    source: Source


class NoticeView(Frozen):
    notice_id: str
    supplier_id: str
    received_at: datetime
    start: datetime
    end: datetime | None
    notice_type: str
    cyber_attack: YesNoUnknown
    bank_data_involved: YesNoUnknown
    member_states_affected: tuple[str, ...] | None
    note: str | None


class SupplierNoticesResult(Frozen):
    supplier_known: bool
    notices: tuple[NoticeView, ...]
    more_available: bool
    source: Source


class DailyAveragesResult(Frozen):
    """Baseline for one service, for the incident date given. None means not held for this service."""

    service_known: bool
    month_used: str
    method: str
    days_counted: int | None
    daily_avg_tx_count: int | None
    daily_avg_tx_value_eur: int | None
    client_base_as_of: date | None
    total_clients_using_service: int | None
    active_counterparts: int | None
    source: Source
