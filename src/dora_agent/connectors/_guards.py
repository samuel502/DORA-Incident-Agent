"""Input checks and output caps shared by all connectors.

Security framework, section 2: tools take fixed, validated parameters, not free text queries.
Every check runs before any data is touched. Error messages never repeat the input,
so hostile text can't travel back to the agent through an error.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

SERVICE_ID_PATTERN = re.compile(r"SVC-[A-Z]{2,8}")
SUPPLIER_ID_PATTERN = re.compile(r"SUP-[A-Z]{2,8}")
# Letters (any language), digits, spaces and a few harmless punctuation marks.
# Not allowed: < > { } [ ] ; " ` $ \ | and similar characters used in markup, code or injections.
_QUERY_ALLOWED = re.compile(r"[\w .,:!?'&()/\-]+")


class InvalidQuery(ValueError):
    """A connector input failed validation. The agent gets this instead of data."""


def check_service_id(value: object) -> str:
    if not isinstance(value, str) or SERVICE_ID_PATTERN.fullmatch(value) is None:
        raise InvalidQuery("service_id must look like SVC-ABC (SVC- plus 2 to 8 capital letters)")
    return value


def check_supplier_id(value: object) -> str:
    if not isinstance(value, str) or SUPPLIER_ID_PATTERN.fullmatch(value) is None:
        raise InvalidQuery("supplier_id must look like SUP-ABC (SUP- plus 2 to 8 capital letters)")
    return value


def check_query_text(value: object, max_chars: int) -> str:
    """Short search text. Length is checked before any other work on it."""
    if not isinstance(value, str):
        raise InvalidQuery("query must be text")
    if len(value) > max_chars:
        raise InvalidQuery(f"query is longer than {max_chars} characters")
    text = " ".join(value.split())
    if not text:
        raise InvalidQuery("query is empty")
    if _QUERY_ALLOWED.fullmatch(text) is None:
        raise InvalidQuery("query contains characters that are not allowed")
    return text


_EARLIEST = datetime(2000, 1, 1, tzinfo=timezone.utc)
_LATEST = datetime(2100, 1, 1, tzinfo=timezone.utc)


def check_time(value: object, name: str) -> datetime:
    """A point in time with a time zone, as a datetime or ISO 8601 text. Returned in UTC.

    A time without a zone is refused: '09:10' means different things in Frankfurt and UTC.
    """
    if isinstance(value, str):
        if len(value) > 40:
            raise InvalidQuery(f"{name} is too long to be a time")
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            raise InvalidQuery(f"{name} must be an ISO 8601 time, e.g. 2026-05-26T07:10:00Z") from None
    if not isinstance(value, datetime):
        raise InvalidQuery(f"{name} must be a time")
    if value.tzinfo is None or value.utcoffset() is None:
        raise InvalidQuery(f"{name} must include a time zone, e.g. Z or +02:00")
    try:
        value = value.astimezone(timezone.utc)
    except OverflowError:  # e.g. year 9999 with a -14:00 zone runs past the end of the calendar
        raise InvalidQuery(f"{name} is outside the supported years 2000 to 2099") from None
    if not _EARLIEST <= value < _LATEST:
        raise InvalidQuery(f"{name} is outside the supported years 2000 to 2099")
    return value


def check_date(value: object, name: str) -> date:
    """A calendar date, as a date or exactly 'YYYY-MM-DD'. A full time is refused: pass the date only."""
    if isinstance(value, str):
        if len(value) != 10:
            raise InvalidQuery(f"{name} must be a date like 2026-05-26")
        try:
            value = date.fromisoformat(value)
        except ValueError:
            raise InvalidQuery(f"{name} must be a date like 2026-05-26") from None
    if isinstance(value, datetime) or not isinstance(value, date):
        raise InvalidQuery(f"{name} must be a date like 2026-05-26")
    if not _EARLIEST.date() <= value < _LATEST.date():
        raise InvalidQuery(f"{name} is outside the supported years 2000 to 2099")
    return value


def check_window(start: object, end: object, max_days: int) -> tuple[datetime, datetime]:
    """A time window: both ends with a time zone, end after start, at most max_days long."""
    begin, finish = check_time(start, "start"), check_time(end, "end")
    if finish <= begin:
        raise InvalidQuery("end must be after start")
    if finish - begin > timedelta(days=max_days):
        raise InvalidQuery(f"window is longer than {max_days} days")
    return begin, finish


def check_hours(value: object, name: str, maximum: int) -> int:
    """A whole number of hours from 1 to maximum. True/False are not accepted as numbers."""
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise InvalidQuery(f"{name} must be a whole number from 1 to {maximum}")
    return value


def cap_text(value: str | None, max_chars: int) -> str | None:
    """Cut free-text notes to a fixed length before they leave a connector."""
    if value is None or len(value) <= max_chars:
        return value
    return value[: max_chars - 1] + "…"
