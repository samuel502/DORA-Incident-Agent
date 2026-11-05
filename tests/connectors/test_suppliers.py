"""Supplier register lookups: get_suppliers_for_service, get_supplier, get_supplier_notices."""

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from dora_agent.config import connector_limits
from dora_agent.connectors import (
    InvalidQuery,
    get_security_alerts,
    get_supplier,
    get_supplier_notices,
    get_suppliers_for_service,
)
from dora_agent.connectors.schemas import SupplierView


def supplier_ids(service_id):
    return [s.supplier_id for s in get_suppliers_for_service(service_id).suppliers]


def one_notice(supplier_id, around, days=7):
    centre = datetime.fromisoformat(around)
    result = get_supplier_notices(supplier_id, centre - timedelta(days=days), centre + timedelta(days=days))
    assert result.supplier_known is True
    assert len(result.notices) == 1, [n.notice_id for n in result.notices]
    return result.notices[0]


# ---------- who runs which service ----------


def test_c03_large_value_payments_run_through_a_market_infrastructure():
    [supplier] = get_suppliers_for_service("SVC-HVP").suppliers
    assert supplier.is_market_infrastructure is True  # RTS-C Art. 4(c)
    assert len(supplier.member_states_served) >= 2


def test_c14_c15_outsourcer_runs_payments_online_banking_and_email():
    for service_id in ("SVC-SEPA", "SVC-OLB", "SVC-MAIL"):
        assert supplier_ids(service_id) == ["SUP-RITS"]


def test_c17_same_vendor_on_office_laptops_and_payment_workstations():
    assert supplier_ids("SVC-OFFICE") == supplier_ids("SVC-PAYOPS") == ["SUP-SHLD"]


def test_c11_c13_file_transfer_has_two_suppliers_with_unknown_criticality():
    suppliers = get_suppliers_for_service("SVC-MFT").suppliers
    assert [s.supplier_id for s in suppliers] == ["SUP-FNSW", "SUP-SDRP"]
    assert all(s.supports_critical_function == "unknown" for s in suppliers)


def test_brief_night_transfer_path_reaches_the_cloud_host():
    # Brief: security alerts -> service list -> supplier register.
    assert supplier_ids("SVC-LOAN") == ["SUP-NMBS"]


def test_services_run_in_house_have_no_suppliers():
    for service_id in ("SVC-HR", "SVC-SEC"):  # N01, C06
        result = get_suppliers_for_service(service_id)
        assert result.service_known is True
        assert result.suppliers == ()


def test_unknown_service():
    result = get_suppliers_for_service("SVC-NOPE")
    assert result.service_known is False
    assert result.suppliers == ()


def test_supplier_named_in_an_alert_can_be_looked_up():
    alert = get_security_alerts("2026-06-01T00:00:00Z", "2026-06-10T00:00:00Z", "SVC-MFT").alerts[0]
    result = get_supplier(alert.supplier_id)
    assert result.found is True
    assert result.supplier.name == "SecureDrop Transfer Inc."
    assert result.source.record_ids == ("SUP-SDRP",)


def test_unknown_supplier_returns_not_found():
    result = get_supplier("SUP-NOPE")
    assert result.found is False
    assert result.supplier is None


def test_contract_reference_is_never_returned():
    assert "contract_ref" not in SupplierView.model_fields
    assert "RIS-2021-004" not in get_supplier("SUP-RITS").model_dump_json()


# ---------- notices ----------


def test_c03_settlement_outage_hits_many_member_states_not_cyber():
    notice = one_notice("SUP-EUSET", "2026-02-26T09:00:00Z")
    assert notice.notice_type == "outage" and notice.cyber_attack == "no"
    assert len(notice.member_states_affected) >= 2  # T4 signal


def test_c05_card_processor_fault_across_member_states():
    notice = one_notice("SUP-CNET", "2026-06-01T13:00:00Z")
    assert notice.cyber_attack == "no"
    assert {"DE", "AT"} <= set(notice.member_states_affected)


def test_c07_vendor_ransomware_bank_data_unknown():
    notice = one_notice("SUP-CLRP", "2026-02-02T07:00:00Z")
    assert notice.notice_type == "cyber_attack" and notice.cyber_attack == "yes"
    assert notice.bank_data_involved == "unknown"
    assert notice.member_states_affected is None  # T4 unknown, as in the case library


def test_c11_vendor_breach_bank_data_involved():
    notice = one_notice("SUP-SDRP", "2026-06-05T09:00:00Z")
    assert notice.notice_type == "breach" and notice.bank_data_involved == "yes"
    assert notice.received_at > notice.end  # bank heard about it after it happened


def test_c13_vendor_breach_bank_data_unknown():
    assert one_notice("SUP-FNSW", "2026-10-07T08:00:00Z").bank_data_involved == "unknown"


def test_c14_outsourcer_fault_cyber_attack_ruled_out():
    notice = one_notice("SUP-RITS", "2026-10-01T09:00:00Z")
    assert notice.notice_type == "outage" and notice.cyber_attack == "no"


def test_c15_outsourcer_fault_three_weeks_later_is_a_separate_notice():
    notice = one_notice("SUP-RITS", "2026-10-21T12:00:00Z")
    assert notice.start == datetime.fromisoformat("2026-10-21T10:00:00Z")


def test_c17_faulty_update_not_an_attack():
    notice = one_notice("SUP-SHLD", "2026-07-16T05:00:00Z")
    assert notice.notice_type == "faulty_update" and notice.cyber_attack == "no"


def test_quiet_window_returns_no_notices():
    result = get_supplier_notices("SUP-NMBS", "2026-08-25T00:00:00Z", "2026-09-10T00:00:00Z")
    assert result.supplier_known is True
    assert result.notices == ()


def test_window_overlap_counts_at_the_edge():
    assert len(get_supplier_notices("SUP-CNET", "2026-06-01T22:45:00Z", "2026-06-02T00:00:00Z").notices) == 1
    assert get_supplier_notices("SUP-CNET", "2026-06-01T22:46:00Z", "2026-06-02T00:00:00Z").notices == ()


def test_notice_without_end_counts_as_still_running(monkeypatch):
    from dora_agent.connectors import _store

    notice = _store.supplier_notices()[0]
    ongoing = notice.model_copy(update={"end": None})
    monkeypatch.setattr(_store, "supplier_notices", lambda: (ongoing,))
    result = get_supplier_notices("SUP-CLRP", "2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z")
    assert len(result.notices) == 1


def test_number_of_notices_is_capped(monkeypatch):
    from dora_agent.connectors import _store, suppliers

    notice = _store.supplier_notices()[0]
    copies = tuple(notice.model_copy(update={"notice_id": f"NTC-99{n:02d}"}) for n in range(3))
    monkeypatch.setattr(_store, "supplier_notices", lambda: copies)
    monkeypatch.setattr(suppliers, "connector_limits", lambda: replace(connector_limits(), max_results=2))
    result = get_supplier_notices("SUP-CLRP", "2026-02-01T00:00:00Z", "2026-02-10T00:00:00Z")
    assert len(result.notices) == 2
    assert result.more_available is True


def test_unknown_supplier_notices():
    result = get_supplier_notices("SUP-NOPE", "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")
    assert result.supplier_known is False


# ---------- bad inputs ----------


@pytest.mark.parametrize("bad_id", ["", "sup-rits", "SUP-R", "Rhein IT Services", "SVC-OLB", None, 3])
def test_rejects_bad_supplier_ids(bad_id):
    with pytest.raises(InvalidQuery):
        get_supplier(bad_id)
    with pytest.raises(InvalidQuery):
        get_supplier_notices(bad_id, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z")


@pytest.mark.parametrize(
    "start, end",
    [
        ("2025-01-01T00:00:00Z", "2026-01-03T00:00:00Z"),  # longer than 366 days
        ("2026-02-02T00:00:00Z", "2026-02-01T00:00:00Z"),  # end before start
        ("2026-02-01", "2026-02-02"),  # dates without times and zones
    ],
)
def test_rejects_bad_windows(start, end):
    with pytest.raises(InvalidQuery):
        get_supplier_notices("SUP-RITS", start, end)


def test_suppliers_for_service_rejects_bad_id():
    with pytest.raises(InvalidQuery):
        get_suppliers_for_service("payments")
