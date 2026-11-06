"""The gate (section 2), the six thresholds (section 3) and T5-b, from docs/dora-rules.md.

Every check answers "met", "not_met" or "unknown". Unknown is never turned into yes or no
(section 7). Comparisons are strict "more than" wherever the rule says ">" (section 3, T1 note).
Shares are compared with whole numbers (part * 100 > whole * 10), so no rounding can tip a boundary.

How the overall major / not major decision combines these is in engine.py (section 1, RTS-C Art. 8(1)).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from dora_agent.rules.facts import Frozen, IncidentFacts
from dora_agent.rules.measure import Measurement, measure_downtime, measure_duration

Status = Literal["met", "not_met", "unknown"]
MET: Status = "met"
NOT_MET: Status = "not_met"
UNKNOWN: Status = "unknown"

# ---------- Limits. Each one is a line in docs/dora-rules.md section 3. ----------

T1_CLIENT_SHARE = (10, 100)  # T1-a: > 10% of clients using the service. RTS-C Art. 9(1)(a)
T1_CLIENT_COUNT = 100_000  # T1-b: > 100,000 clients. RTS-C Art. 9(1)(b)
T1_COUNTERPART_SHARE = (30, 100)  # T1-c: > 30% of counterparts. RTS-C Art. 9(1)(c)
T1_TX_SHARE = (10, 100)  # T1-d, T1-e: > 10% of the daily average number / value. RTS-C Art. 9(1)(d), (e)
T3_DURATION = timedelta(hours=24)  # T3-a: longer than 24 hours. RTS-C Art. 9(3)(a)
T3_DOWNTIME = timedelta(hours=2)  # T3-b: longer than 2 hours. RTS-C Art. 9(3)(b)
T4_MIN_STATES = 2  # T4: two or more Member States. RTS-C Art. 9(4)
T6_COSTS_EUR = 100_000  # T6: more than EUR 100,000. RTS-C Art. 9(6)

# T4 counts the 30 EEA Member States (section 3, T4, open question 10): the 27 EU Member States
# plus Iceland, Liechtenstein and Norway (DORA in the EEA Agreement: EEA Joint Committee Decision No 40/2025).
# Greece is "GR" in ISO and "EL" in EU usage; both are accepted.
EEA_MEMBER_STATES = frozenset(
    {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "EL", "HU", "IE",
        "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
        "IS", "LI", "NO",  # EEA EFTA States, open question 10
    }
)


class Check(Frozen):
    """One point of a threshold, for example T1-a."""

    check_id: str
    status: Status
    article: str
    reason: str  # plain words, shown to the user and logged
    missing: tuple[str, ...] = ()  # facts that would decide it, if unknown
    measurement: Measurement | None = None  # T3 only: how the time was measured


class Threshold(Frozen):
    """The gate, one of T1 to T6, or T5-b, with all its points."""

    threshold_id: str
    name: str
    article: str
    status: Status
    checks: tuple[Check, ...]

    @property
    def missing(self) -> tuple[str, ...]:
        """Facts that would decide this threshold. Empty if it is already decided."""
        if self.status != UNKNOWN:
            return ()
        names: list[str] = []
        for check in self.checks:
            if check.status == UNKNOWN:
                names += [n for n in check.missing if n not in names]
        return tuple(names)


# ---------- Three-valued logic: unknown stays unknown ----------


def any_of(statuses) -> Status:
    """Met if any point is met. Not met only if every point is not met. Otherwise unknown."""
    statuses = list(statuses)
    if MET in statuses:
        return MET
    if statuses and all(s == NOT_MET for s in statuses):
        return NOT_MET
    return UNKNOWN


def all_of(statuses) -> Status:
    """Met only if every point is met. Not met if any point is not met. Otherwise unknown."""
    statuses = list(statuses)
    if NOT_MET in statuses:
        return NOT_MET
    if statuses and all(s == MET for s in statuses):
        return MET
    return UNKNOWN


def _combine(threshold_id, name, article, checks, rule=any_of) -> Threshold:
    return Threshold(
        threshold_id=threshold_id, name=name, article=article,
        status=rule(c.status for c in checks), checks=tuple(checks),
    )


# ---------- Building blocks ----------


def _waiting(facts: IncidentFacts, name: str) -> str:
    """Why a fact is unknown: not found yet, or found but waiting for a human (section 7)."""
    if getattr(facts, name).known:
        return f"{name} is waiting for human confirmation"
    return f"{name} is unknown"


def _yes_no(facts, name, check_id, article, label) -> Check:
    value = facts.usable(name)
    if value is None:
        return Check(check_id=check_id, status=UNKNOWN, article=article,
                     reason=f"{label}: {_waiting(facts, name)}", missing=(name,))
    return Check(check_id=check_id, status=MET if value else NOT_MET, article=article,
                 reason=f"{label}: {'yes' if value else 'no'}")


def _share_above(facts, check_id, article, part_name, whole_name, share, label) -> Check:
    """Met if part / whole is strictly more than share (given as a fraction num / den)."""
    num, den = share
    part, whole = facts.usable(part_name), facts.usable(whole_name)
    limit = f"more than {num * 100 // den}%"
    if part == 0:
        return Check(check_id=check_id, status=NOT_MET, article=article,
                     reason=f"{label}: none affected, so not {limit}")
    if part is None or whole is None:
        missing = tuple(n for n, v in ((part_name, part), (whole_name, whole)) if v is None)
        return Check(check_id=check_id, status=UNKNOWN, article=article,
                     reason=f"{label}: " + "; ".join(_waiting(facts, n) for n in missing), missing=missing)
    if whole == 0:
        return Check(check_id=check_id, status=UNKNOWN, article=article,
                     reason=f"{label}: {whole_name} is 0, so no share can be worked out", missing=(whole_name,))
    met = part * den > whole * num
    return Check(check_id=check_id, status=MET if met else NOT_MET, article=article,
                 reason=f"{label}: {part:,} of {whole:,} ({part / whole:.2%}), "
                        f"{'which is' if met else 'not'} {limit}")


def _amount_above(facts, check_id, article, name, limit, label, unit="") -> Check:
    value = facts.usable(name)
    if value is None:
        return Check(check_id=check_id, status=UNKNOWN, article=article,
                     reason=f"{label}: {_waiting(facts, name)}", missing=(name,))
    met = value > limit
    estimate = " (estimate)" if getattr(facts, name).is_estimate else ""
    return Check(check_id=check_id, status=MET if met else NOT_MET, article=article,
                 reason=f"{label}: {unit}{value:,}{estimate}, {'more than' if met else 'not more than'} {unit}{limit:,}")


def _hours(length: timedelta) -> str:
    return f"{length.total_seconds() / 3600:.2f} h"


def _time_above(facts, m: Measurement, limit: timedelta, check_id, article, label, start_facts, end_facts) -> Check:
    """Met if the measured length is strictly more than the limit.

    Ongoing: the length so far is a minimum. Above the limit already: met. Otherwise unknown,
    because it may still grow (RTS-C Art. 3(1): estimate the end if it is not known).
    """
    if m.length is None:
        if m.problem == "start time unknown":
            missing = ("planned_window_end",) if facts.usable("planned_and_announced") is True else start_facts
        else:
            missing = tuple(n for n in (m.start_basis, m.end_basis) if n and n != "as_of")
        return Check(check_id=check_id, status=UNKNOWN, article=article,
                     reason=f"{label}: cannot be measured ({m.problem})", missing=missing, measurement=m)
    so_far = " so far (still ongoing)" if m.ongoing else ""
    estimate = " (estimate)" if m.is_estimate else ""
    if m.length > limit:
        return Check(check_id=check_id, status=MET, article=article, measurement=m,
                     reason=f"{label}: {_hours(m.length)}{so_far}{estimate}, more than {_hours(limit)}")
    if m.ongoing:
        return Check(check_id=check_id, status=UNKNOWN, article=article, measurement=m, missing=end_facts,
                     reason=f"{label}: {_hours(m.length)} so far and still ongoing, "
                            f"not yet more than {_hours(limit)}; end time or an estimate needed")
    return Check(check_id=check_id, status=NOT_MET, article=article, measurement=m,
                 reason=f"{label}: {_hours(m.length)}{estimate}, not more than {_hours(limit)}")


def _malicious_access_on_own_systems(facts, check_id, article) -> list[Check]:
    """Successful, malicious and unauthorised access to the bank's OWN systems.

    Open question 4: an access to a supplier's systems does not count (RTS-C Art. 6(c)).
    """
    return [
        _yes_no(facts, "malicious_access", check_id, article, "Successful, malicious, unauthorised access"),
        _yes_no(facts, "access_on_own_systems", check_id, article,
                "Access was to Rheinbank's own systems (open question 4)"),
    ]


# ---------- Gate: section 2 ----------


def check_gate(facts: IncidentFacts) -> Threshold:
    """Critical services affected. RTS-C Art. 6, DORA Art. 18(1)(e). Passed if any of G-a, G-b, G-c."""
    g_a = _yes_no(facts, "critical_or_important", "G-a", "RTS-C Art. 6(a)",
                  "Service supports critical or important functions")
    g_b = _yes_no(facts, "regulated_service", "G-b", "RTS-C Art. 6(b)",
                  "Financial service needing authorisation or registration")
    parts = _malicious_access_on_own_systems(facts, "G-c", "RTS-C Art. 6(c)")
    g_c = Check(
        check_id="G-c", status=all_of(p.status for p in parts), article="RTS-C Art. 6(c)",
        reason="; ".join(p.reason for p in parts),
        missing=tuple(n for p in parts if p.status == UNKNOWN for n in p.missing),
    )
    return _combine("gate", "Critical services affected", "RTS-C Art. 6", [g_a, g_b, g_c])


# ---------- T1: section 3 ----------


def check_t1(facts: IncidentFacts) -> Threshold:
    """Clients, financial counterparts and transactions. RTS-C Art. 9(1), Art. 1, DORA Art. 18(1)(a)."""
    checks = [
        _share_above(facts, "T1-a", "RTS-C Art. 9(1)(a)", "affected_clients", "total_clients",
                     T1_CLIENT_SHARE, "Share of clients of the service affected"),
        _amount_above(facts, "T1-b", "RTS-C Art. 9(1)(b)", "affected_clients", T1_CLIENT_COUNT,
                      "Clients affected"),
        _share_above(facts, "T1-c", "RTS-C Art. 9(1)(c)", "affected_counterparts", "total_counterparts",
                     T1_COUNTERPART_SHARE, "Share of financial counterparts affected"),
        _share_above(facts, "T1-d", "RTS-C Art. 9(1)(d)", "affected_tx_count", "daily_avg_tx_count",
                     T1_TX_SHARE, "Transactions affected vs daily average number"),
        _share_above(facts, "T1-e", "RTS-C Art. 9(1)(e)", "affected_tx_value_eur", "daily_avg_tx_value_eur",
                     T1_TX_SHARE, "Transaction value affected vs daily average value"),
        _yes_no(facts, "relevant_parties_affected", "T1-f", "RTS-C Art. 9(1), Art. 1(3)",
                "Relevant clients or counterparts affected"),
    ]
    return _combine("T1", "Clients, counterparts and transactions", "RTS-C Art. 9(1)", checks)


# ---------- T2: section 3 ----------


def check_t2(facts: IncidentFacts) -> Threshold:
    """Reputational impact. RTS-C Art. 9(2), Art. 2, DORA Art. 18(1)(a). All points need a human (section 7)."""
    checks = [
        _yes_no(facts, "media_coverage", "T2-a", "RTS-C Art. 9(2), Art. 2", "Reported in the media"),
        _yes_no(facts, "repeated_complaints", "T2-b", "RTS-C Art. 9(2), Art. 2",
                "Repeated complaints from different clients or counterparts"),
        _yes_no(facts, "regulatory_requirements_impact", "T2-c", "RTS-C Art. 9(2), Art. 2",
                "Cannot or likely cannot meet regulatory requirements"),
        _yes_no(facts, "client_loss_impact", "T2-d", "RTS-C Art. 9(2), Art. 2",
                "Will or likely will lose clients or counterparts, with material impact"),
    ]
    return _combine("T2", "Reputational impact", "RTS-C Art. 9(2)", checks)


# ---------- T3: section 3 ----------


def check_t3(facts: IncidentFacts, as_of: datetime) -> Threshold:
    """Duration and service downtime. RTS-C Art. 9(3), Art. 3, DORA Art. 18(1)(b).

    as_of: the time of the check (UTC). Used only for incidents that are still ongoing.
    """
    t3_a = _time_above(
        facts, measure_duration(facts, as_of), T3_DURATION, "T3-a", "RTS-C Art. 9(3)(a), Art. 3(1)",
        "Incident duration", start_facts=("incident_start", "detected_at"), end_facts=("resolved_at",),
    )
    downtime = _time_above(
        facts, measure_downtime(facts, as_of), T3_DOWNTIME, "T3-b", "RTS-C Art. 9(3)(b), Art. 3(2)",
        "Service downtime", start_facts=("downtime_start", "detected_at"), end_facts=("service_restored_at",),
    )
    # T3-b counts only for ICT services supporting critical or important functions.
    critical = _yes_no(facts, "critical_or_important", "T3-b", "RTS-C Art. 9(3)(b)",
                       "Service supports critical or important functions")
    t3_b = Check(
        check_id="T3-b", status=all_of([downtime.status, critical.status]), article=downtime.article,
        reason=f"{downtime.reason}; {critical.reason}",
        missing=tuple(n for c in (downtime, critical) if c.status == UNKNOWN for n in c.missing),
        measurement=downtime.measurement,
    )
    return _combine("T3", "Duration and service downtime", "RTS-C Art. 9(3)", [t3_a, t3_b])


# ---------- T4: section 3 ----------


def check_t4(facts: IncidentFacts) -> Threshold:
    """Geographical spread: impact in two or more EEA Member States (open question 10). RTS-C Art. 9(4), Art. 4, DORA Art. 18(1)(c)."""
    article = "RTS-C Art. 9(4)"
    states = facts.usable("affected_member_states")
    if states is None:
        check = Check(check_id="T4", status=UNKNOWN, article=article,
                      reason=f"Member States affected: {_waiting(facts, 'affected_member_states')}",
                      missing=("affected_member_states",))
    else:
        eea = sorted({"GR" if s == "EL" else s for s in states if s in EEA_MEMBER_STATES})
        other = sorted({s for s in states if s not in EEA_MEMBER_STATES})
        met = len(eea) >= T4_MIN_STATES
        outside = f" (not counted, outside the EEA: {', '.join(other)})" if other else ""
        check = Check(check_id="T4", status=MET if met else NOT_MET, article=article,
                      reason=f"EEA Member States affected: {', '.join(eea) or 'none'} ({len(eea)}), "
                             f"{'at least' if met else 'fewer than'} {T4_MIN_STATES}{outside}")
    return _combine("T4", "Geographical spread", article, [check])


# ---------- T5-a and T5-b: section 3 ----------


def check_t5a(facts: IncidentFacts) -> Threshold:
    """Data losses with adverse impact. RTS-C Art. 9(5)(a), Art. 5, DORA Art. 18(1)(d).

    Met if there is an impact on data availability, authenticity, integrity or confidentiality
    AND it has or will have an adverse impact on business objectives or regulatory requirements.
    """
    impacts = [
        _yes_no(facts, "data_availability_impact", "T5-a", "RTS-C Art. 5", "Data availability impact"),
        _yes_no(facts, "data_authenticity_impact", "T5-a", "RTS-C Art. 5", "Data authenticity impact"),
        _yes_no(facts, "data_integrity_impact", "T5-a", "RTS-C Art. 5", "Data integrity impact"),
        _yes_no(facts, "data_confidentiality_impact", "T5-a", "RTS-C Art. 5", "Data confidentiality impact"),
    ]
    adverse = _yes_no(facts, "data_impact_adverse", "T5-a", "RTS-C Art. 9(5)(a)",
                      "Adverse impact on business objectives or regulatory requirements")
    any_impact = any_of(c.status for c in impacts)
    status = all_of([any_impact, adverse.status])
    missing = []
    if any_impact == UNKNOWN:
        missing += [n for c in impacts if c.status == UNKNOWN for n in c.missing]
    if adverse.status == UNKNOWN:
        missing += list(adverse.missing)
    check = Check(check_id="T5-a", status=status, article="RTS-C Art. 9(5)(a), Art. 5",
                  reason="; ".join(c.reason for c in [*impacts, adverse]), missing=tuple(missing))
    return _combine("T5-a", "Data losses", "RTS-C Art. 9(5)(a)", [check])


def check_t5b(facts: IncidentFacts) -> Threshold:
    """Successful, malicious, unauthorised access that may result in data losses. RTS-C Art. 9(5)(b).

    Alone makes the incident major if the gate is passed (section 1, RTS-C Art. 8(1)(a)).
    Open question 4: only the bank's own systems count.
    """
    parts = [
        *_malicious_access_on_own_systems(facts, "T5-b", "RTS-C Art. 9(5)(b)"),
        _yes_no(facts, "access_may_cause_data_loss", "T5-b", "RTS-C Art. 9(5)(b)", "Access may result in data losses"),
    ]
    check = Check(
        check_id="T5-b", status=all_of(p.status for p in parts), article="RTS-C Art. 9(5)(b)",
        reason="; ".join(p.reason for p in parts),
        missing=tuple(n for p in parts if p.status == UNKNOWN for n in p.missing),
    )
    return _combine("T5-b", "Malicious access that may cause data losses", "RTS-C Art. 9(5)(b)", [check])


# ---------- T6: section 3 ----------


def check_t6(facts: IncidentFacts) -> Threshold:
    """Economic impact: costs and losses more than EUR 100,000. RTS-C Art. 9(6), Art. 7, DORA Art. 18(1)(f).

    costs_eur is the gross total (Art. 7(1)): recoveries are not subtracted. An estimate is allowed (Art. 7(3)).
    """
    check = _amount_above(facts, "T6", "RTS-C Art. 9(6), Art. 7", "costs_eur", T6_COSTS_EUR,
                          "Costs and losses", unit="EUR ")
    return _combine("T6", "Economic impact", "RTS-C Art. 9(6)", [check])
