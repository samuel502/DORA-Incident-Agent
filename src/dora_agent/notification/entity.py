"""Rheinbank's reporting details for the initial notification (ITS-R Annex II, fields 1.2 to 1.15).

Read-only (CLAUDE.md hard rule 3): the file is only opened for reading, checked once and cached as a
frozen object. Synthetic only (hard rule 6): loading fails unless the file is marked synthetic and
every identifier is one that cannot belong to a real company or person:

- LEI: 20 characters (ISO 17442), but it must FAIL the ISO 7064 MOD 97-10 check that every real LEI
  passes. So it can never match a real LEI. A valid-looking LEI is refused.
- Telephone: +49 followed by 0. No German number starts with 0 after the country code.
- Email: the reserved .example domain (RFC 2606), which can never receive mail.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from ..config import DATA_DIR
from ..connectors import get_bank_profile

ENTITY_FILE = "reporting_entity.json"

# Shown with field 1.3 and on every draft, so nobody mistakes the draft for a real report.
SYNTHETIC_LEI_NOTE = "SYNTHETIC: fake LEI with invalid check digits. Rheinbank AG is a fictional bank."

_LEI_SHAPE = re.compile(r"^[A-Z0-9]{18}[0-9]{2}$")
_FAKE_PHONE = re.compile(r"^\+49 0[0-9 ]{4,20}$")
_FAKE_EMAIL = re.compile(r"^[a-z0-9.\-]{1,64}@[a-z0-9\-]{1,63}\.example$")
_NO_CONTROL = r"^[^\x00-\x1f\x7f]+$"
Text = Annotated[str, StringConstraints(min_length=1, max_length=120, pattern=_NO_CONTROL)]


def mod97_remainder(code: str) -> int:
    """ISO 7064 MOD 97-10, the check LEIs (ISO 17442) and IBANs use: letters become 10 to 35."""
    return int("".join(str(int(c, 36)) for c in code)) % 97


def lei_check_passes(lei: str) -> bool:
    """True if `lei` has the LEI shape and passes the check (remainder 1), as every real LEI does."""
    return bool(_LEI_SHAPE.match(lei)) and mod97_remainder(lei) == 1


def _synthetic_lei(value: str) -> str:
    if not _LEI_SHAPE.match(value):
        raise ValueError("LEI must be 20 characters: 18 letters or digits, then 2 check digits (ISO 17442)")
    if lei_check_passes(value):
        raise ValueError("LEI passes the ISO 7064 check, so it could belong to a real company. Use a fake one.")
    return value


class Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


class Contact(Frozen):
    """Fields 1.7 to 1.9 (primary) and 1.10 to 1.12 (second contact or team)."""

    name: Text
    email: str
    telephone: str

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        if not _FAKE_EMAIL.match(value):
            raise ValueError("email must use the reserved .example domain")
        return value

    @field_validator("telephone")
    @classmethod
    def _telephone(cls, value: str) -> str:
        if not _FAKE_PHONE.match(value):
            raise ValueError("telephone must be +49 followed by 0, a number that cannot exist")
        return value


class ParentUndertaking(Frozen):
    """Fields 1.13 and 1.14, only if the bank belongs to a group."""

    name: Text
    lei: str

    @field_validator("lei")
    @classmethod
    def _lei(cls, value: str) -> str:
        return _synthetic_lei(value)


class ReportingEntity(Frozen):
    legal_name: Text  # field 1.2
    lei: str  # field 1.3
    reporting_currency: Literal["EUR"]  # field 1.15, ISO 4217
    parent_undertaking: ParentUndertaking | None  # fields 1.13, 1.14
    primary_contact: Contact  # fields 1.7 to 1.9
    second_contact: Contact  # fields 1.10 to 1.12

    @field_validator("lei")
    @classmethod
    def _lei(cls, value: str) -> str:
        return _synthetic_lei(value)


class ReportingEntityFile(Frozen):
    about: str
    synthetic: Literal[True]
    entity: ReportingEntity


@lru_cache(maxsize=1)
def reporting_entity() -> ReportingEntity:
    """Load and check the file once. Raises ValueError if anything is wrong."""
    with (DATA_DIR / ENTITY_FILE).open("r", encoding="utf-8") as handle:
        parsed = ReportingEntityFile.model_validate_json(handle.read())
    if "SYNTHETIC DATA" not in parsed.about:
        raise ValueError(f"{ENTITY_FILE} must say SYNTHETIC DATA")
    profile = get_bank_profile().profile
    if parsed.entity.legal_name != profile.name:
        raise ValueError(f"{ENTITY_FILE} legal_name does not match bank_profile.json")
    return parsed.entity
