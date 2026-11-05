"""Checks on the supplier files, and checks that run across all Rheinbank data files."""

import json
import re

import pytest

from dora_agent.config import DATA_DIR
from dora_agent.connectors import _store
from dora_agent.connectors.schemas import SupplierNoticesFile, SuppliersFile

CASE_ID = re.compile(r"\b[CN]\d{2}\b")
ALL_DATA_FILES = sorted(DATA_DIR.glob("*.json"))


def test_supplier_files_load():
    assert len(_store.suppliers()) == 8
    assert len(_store.supplier_notices()) == 8


@pytest.mark.parametrize("path", ALL_DATA_FILES, ids=lambda p: p.name)
def test_no_real_company_names_in_any_data_file(path, real_names):
    text = path.read_text(encoding="utf-8")
    for name in real_names:
        assert re.search(rf"\b{re.escape(name)}\b", text) is None, f"{path.name} mentions {name}"


@pytest.mark.parametrize("path", ALL_DATA_FILES, ids=lambda p: p.name)
def test_every_data_file_is_marked_synthetic_and_has_no_case_ids(path):
    text = path.read_text(encoding="utf-8")
    assert "SYNTHETIC DATA" in text
    assert CASE_ID.search(text) is None


def test_every_supplier_id_used_anywhere_exists():
    known = _store.supplier_ids()
    used = {s for record in _store.services() for s in record.supplier_ids}
    used |= {a.supplier_id for a in _store.security_alerts() if a.supplier_id}
    used |= {n.supplier_id for n in _store.supplier_notices()}
    assert used <= known


def test_every_supplier_is_used_by_a_service():
    used = {s for record in _store.services() for s in record.supplier_ids}
    assert used == _store.supplier_ids()


def test_register_and_service_list_must_agree(monkeypatch):
    # Remove one link from the service list only: the register must refuse to load.
    real = _store.services()
    changed = tuple(
        r.model_copy(update={"supplier_ids": ()}) if r.service_id == "SVC-HVP" else r for r in real
    )
    monkeypatch.setattr(_store, "services", lambda: changed)
    with pytest.raises(ValueError, match="disagree"):
        _store.suppliers.__wrapped__()  # bypass the cache


def test_exactly_one_market_infrastructure():
    assert [s.supplier_id for s in _store.suppliers() if s.is_market_infrastructure] == ["SUP-EUSET"]


def _broken(file_name, key, change):
    doc = json.loads((DATA_DIR / file_name).read_text(encoding="utf-8"))
    change(doc[key][0])
    return json.dumps(doc)


@pytest.mark.parametrize(
    "change",
    [
        lambda n: n.update(end="2020-01-01T00:00:00Z"),  # ends before it starts
        lambda n: n.update(received_at="2020-01-01T00:00:00Z"),  # received before it started
        lambda n: n.update(notice_type="rumour"),
        lambda n: n.update(bank_data_involved="maybe"),
        lambda n: n.update(member_states_affected=["Germany"]),
        lambda n: n.update(contact_email="x@example.com"),  # unknown field
    ],
)
def test_notice_schema_rejects_broken_data(change):
    with pytest.raises(ValueError):
        SupplierNoticesFile.model_validate_json(_broken("supplier_notices.json", "notices", change))


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.update(supplier_id="RITS"),
        lambda s: s.update(country="Germany"),
        lambda s: s.update(services_provided=["online banking"]),
        lambda s: s.update(is_market_infrastructure="yes"),
    ],
)
def test_supplier_schema_rejects_broken_data(change):
    with pytest.raises(ValueError):
        SuppliersFile.model_validate_json(_broken("suppliers.json", "suppliers", change))
