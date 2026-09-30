"""UTC clock helpers. All tool-generated timestamps are UTC ISO-8601 with a ``Z`` suffix."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def isoformat_utc(value: datetime) -> str:
    """Format ``value`` as ``YYYY-MM-DDTHH:MM:SS.ffffffZ``.

    Naive datetimes are rejected: the tool never guesses the zone of its own timestamps.
    """
    if value.tzinfo is None:
        raise ValueError("naive datetime; tool timestamps must be timezone-aware")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso_utc(text: str) -> datetime:
    """Parse a timestamp produced by :func:`isoformat_utc`."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)
