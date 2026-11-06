"""Rheinbank's reporting details: synthetic only, and the fake LEI can never match a real one."""

import json

import pytest
from pydantic import ValidationError

from dora_agent.config import DATA_DIR
from dora_agent.notification import entity as entity_module
from dora_agent.notification.entity import (
    ENTITY_FILE,
    Contact,
    ReportingEntityFile,
    lei_check_passes,
    mod97_remainder,
    reporting_entity,
)

def _with_valid_check_digits(base18):
    """Give a made-up 18-character base the check digits a real LEI would have (ISO 7064 MOD 97-10)."""
    remainder = int("".join(str(int(c, 36)) for c in base18 + "00")) % 97
    return f"{base18}{98 - remainder:02d}"


# Made-up codes that pass the check, so they look like real LEIs. No real company identifiers are used
# (hard rule 6). They only prove that the loader refuses anything that could be real.
REAL_FORMAT_LEIS = [_with_valid_check_digits("TESTONLY0000000000"), _with_valid_check_digits("TESTONLY0000000001")]


def test_check_matches_the_iso_7064_standard_example():
    # ISO 7064 MOD 97-10 is the same check IBANs use. The fictional example IBAN from the IBAN standard,
    # GB82 WEST 1234 5698 7654 32, moved into check order, must give remainder 1. One changed digit must not.
    assert mod97_remainder("WEST12345698765432GB82") == 1
    assert mod97_remainder("WEST12345698765433GB82") != 1


def raw():
    return json.loads((DATA_DIR / ENTITY_FILE).read_text(encoding="utf-8"))


def test_file_loads_and_is_marked_synthetic():
    data = raw()
    assert data["synthetic"] is True
    assert "SYNTHETIC DATA" in data["about"]
    loaded = reporting_entity()
    assert loaded.legal_name == "Rheinbank AG"
    assert loaded.reporting_currency == "EUR"


def test_fake_lei_fails_the_iso_7064_check():
    lei = reporting_entity().lei
    assert len(lei) == 20
    assert lei.startswith("FAKE")
    assert lei.endswith("00")  # check digits 00 never occur in a real LEI (valid ones are 02 to 98)
    assert mod97_remainder(lei) != 1
    assert not lei_check_passes(lei)


@pytest.mark.parametrize("lei", REAL_FORMAT_LEIS)
def test_check_recognises_real_leis(lei):
    assert lei_check_passes(lei)


@pytest.mark.parametrize("lei", REAL_FORMAT_LEIS)
def test_file_with_a_valid_lei_is_refused(lei):
    data = raw()
    data["entity"]["lei"] = lei
    with pytest.raises(ValidationError, match="real company"):
        ReportingEntityFile.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("lei", ["FAKE", "fake00rheinbank00000", "FAKE00RHEINBANK000AB", "FAKE00RHEINBANK0000000"])
def test_lei_with_wrong_shape_is_refused(lei):
    data = raw()
    data["entity"]["lei"] = lei
    with pytest.raises(ValidationError, match="20 characters"):
        ReportingEntityFile.model_validate_json(json.dumps(data))


def test_valid_parent_lei_is_refused_too():
    data = raw()
    data["entity"]["parent_undertaking"] = {"name": "Some Group", "lei": REAL_FORMAT_LEIS[0]}
    with pytest.raises(ValidationError, match="real company"):
        ReportingEntityFile.model_validate_json(json.dumps(data))


def test_file_not_marked_synthetic_is_refused():
    data = raw()
    data["synthetic"] = False
    with pytest.raises(ValidationError):
        ReportingEntityFile.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("email", ["someone@rheinbank.de", "a@example.com", "a@rheinbank.example.de", "x\n@a.example"])
def test_email_outside_reserved_domain_is_refused(email):
    with pytest.raises(ValidationError, match=".example"):
        Contact(name="Test", email=email, telephone="+49 0000 000001")


@pytest.mark.parametrize("phone", ["+49 211 1234567", "+49 30 000000", "+43 0000 000001", "0211 123456"])
def test_phone_that_could_exist_is_refused(phone):
    with pytest.raises(ValidationError, match="cannot exist"):
        Contact(name="Test", email="a@rheinbank.example", telephone=phone)


def test_contacts_in_file_use_fake_numbers_and_reserved_domain():
    e = reporting_entity()
    for contact in (e.primary_contact, e.second_contact):
        assert contact.email.endswith(".example")
        assert contact.telephone.startswith("+49 0")
        assert "(fictional)" in contact.name


def test_name_must_match_bank_profile(monkeypatch, tmp_path):
    data = raw()
    data["entity"]["legal_name"] = "Other Bank AG"
    (tmp_path / ENTITY_FILE).write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(entity_module, "DATA_DIR", tmp_path)
    entity_module.reporting_entity.cache_clear()
    try:
        with pytest.raises(ValueError, match="bank_profile"):
            entity_module.reporting_entity()
    finally:
        entity_module.reporting_entity.cache_clear()


def test_entity_is_frozen():
    with pytest.raises(ValidationError):
        reporting_entity().lei = "X"


def test_entity_module_never_writes():
    source = (entity_module.__file__)
    text = open(source, encoding="utf-8").read()
    for pattern in (".write(", "write_text", "write_bytes", "unlink", "rename", "shutil", '"w"', "'w'"):
        assert pattern not in text, pattern
