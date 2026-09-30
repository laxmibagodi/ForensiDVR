"""Deterministic JSON serialisation used for hashes, manifests and reports."""

from __future__ import annotations

import dataclasses
import enum
import json
from datetime import datetime
from pathlib import PurePath
from typing import Any

from forensidvr.core.timeutil import isoformat_utc


def to_jsonable(obj: Any) -> Any:
    """Convert dataclasses, enums, datetimes, paths and bytes into JSON-compatible values."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, datetime):
        return isoformat_utc(obj) if obj.tzinfo else obj.isoformat()
    if isinstance(obj, PurePath):
        return str(obj)
    if isinstance(obj, bytes | bytearray):
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple | set | frozenset):
        items = [to_jsonable(v) for v in obj]
        return sorted(items, key=repr) if isinstance(obj, set | frozenset) else items
    return obj


def canonical_json(obj: Any) -> bytes:
    """Canonical UTF-8 JSON: sorted keys, no insignificant whitespace. Used for hashing."""
    return json.dumps(to_jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def pretty_json(obj: Any) -> str:
    """Stable human-readable JSON (sorted keys, 2-space indent, trailing newline)."""
    return json.dumps(to_jsonable(obj), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
