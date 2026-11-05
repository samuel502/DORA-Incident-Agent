"""Read-only guarantees for every connector (CLAUDE.md hard rule 3)."""

import ast
import hashlib
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from dora_agent.config import DATA_DIR
from dora_agent.connectors import (
    _store,
    find_service,
    get_bank_profile,
    get_client_impact,
    get_daily_averages,
    get_outage_timeline,
    get_security_alerts,
    get_service,
    get_supplier,
    get_supplier_notices,
    get_suppliers_for_service,
)
from dora_agent.connectors._guards import cap_text

CONNECTORS_DIR = Path(__file__).resolve().parents[2] / "src" / "dora_agent" / "connectors"

# Anything in connector code that could write, change or delete files.
# (open() calls are checked separately below, by reading the code's structure.)
WRITE_PATTERNS = [
    r"\.write\(",
    r"write_text",
    r"write_bytes",
    r"\.unlink\(",
    r"\.rename\(",
    r"os\.replace",
    r"rmdir",
    r"os\.remove",
    r"shutil\.",
    r"json\.dump\(",
    r"\.touch\(",
    r"mkdir",
]


def fingerprints():
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(DATA_DIR.glob("*"))}


def test_data_files_unchanged_after_many_calls():
    before = fingerprints()
    for _ in range(200):
        for match in find_service("payments").matches:
            get_service(match.service_id)
        get_service("SVC-NOPE")
        get_outage_timeline("SVC-OLB", "2026-05-26T07:10:00Z", 72)
        get_outage_timeline("SVC-SEPA", "2026-10-01T07:30:00Z", 24)
        get_client_impact("SVC-OLB", "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z")
        get_daily_averages("SVC-HVP", "2026-02-26")
        get_bank_profile()
        get_security_alerts("2026-07-01T00:00:00Z", "2026-07-31T00:00:00Z")
        get_security_alerts("2026-05-01T00:00:00Z", "2026-05-31T00:00:00Z", "SVC-SEC")
        get_suppliers_for_service("SVC-MFT")
        get_supplier("SUP-RITS")
        get_supplier_notices("SUP-RITS", "2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z")
    assert fingerprints() == before


def test_supplier_results_cannot_be_changed():
    supplier = get_supplier("SUP-EUSET").supplier
    with pytest.raises(ValidationError):
        supplier.is_market_infrastructure = False
    assert get_supplier("SUP-EUSET").supplier.is_market_infrastructure is True


def test_security_results_cannot_be_changed():
    alert = get_security_alerts("2026-05-12T00:00:00Z", "2026-05-13T00:00:00Z").alerts[0]
    with pytest.raises(ValidationError):
        alert.access_successful = "no"
    with pytest.raises(ValidationError):
        alert.data_impact.confidentiality = "none"


def test_client_data_results_cannot_be_changed():
    result = get_client_impact("SVC-OLB", "2026-05-26T00:00:00Z", "2026-05-27T00:00:00Z")
    with pytest.raises(ValidationError):
        result.impacts[0].affected_clients = 0
    profile = get_bank_profile().profile
    with pytest.raises(ValidationError):
        profile.microenterprise = True
    assert get_bank_profile().profile.microenterprise is False


def test_monitoring_results_cannot_be_changed():
    result = get_outage_timeline("SVC-OLB", "2026-05-26T07:10:00Z")
    with pytest.raises(ValidationError):
        result.problems[0].events[0].event_type = "resolved"
    with pytest.raises(TypeError):
        result.problems[0].events[0] = None  # tuples can't be changed


def test_connector_code_has_no_write_operations():
    for path in CONNECTORS_DIR.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for pattern in WRITE_PATTERNS:
            assert re.search(pattern, source) is None, f"{path.name} matches {pattern}"


def open_modes(source):
    """Yield the mode of every open(...) / x.open(...) call. None means no mode was given."""
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_builtin = isinstance(func, ast.Name) and func.id == "open"
        is_method = isinstance(func, ast.Attribute) and func.attr == "open"
        if not (is_builtin or is_method):
            continue
        positional = node.args[1:] if is_builtin else node.args
        mode = positional[0] if positional else next((k.value for k in node.keywords if k.arg == "mode"), None)
        yield mode


def test_connector_code_opens_files_for_reading_only():
    for path in CONNECTORS_DIR.glob("*.py"):
        for mode in open_modes(path.read_text(encoding="utf-8")):
            # The mode must be written out, and be plain read mode.
            assert isinstance(mode, ast.Constant), f"{path.name}: open() without a fixed mode"
            assert mode.value in ("r", "rb", "rt"), f"{path.name}: open() with mode {mode.value!r}"


def test_cached_records_cannot_be_changed():
    record = _store.services()[0]
    with pytest.raises(ValidationError):
        record.critical_or_important = "no"
    with pytest.raises(AttributeError):
        record.aliases.append("hacked")  # tuples have no append


def test_results_cannot_be_changed():
    result = get_service("SVC-OLB")
    with pytest.raises(ValidationError):
        result.service.critical_or_important = "no"
    assert get_service("SVC-OLB").service.critical_or_important == "yes"


def test_long_notes_are_cut_to_the_limit():
    assert len(cap_text("x" * 5000, 500)) == 500
    assert cap_text("short", 500) == "short"
    assert cap_text(None, 500) is None
