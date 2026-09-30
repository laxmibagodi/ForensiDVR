"""Append-only, hash-chained chain-of-custody log (hard requirement #3).

Storage is JSON Lines. Each record contains the SHA-256 of the previous record
(``prev_hash``) and its own hash (``entry_hash``) computed over the canonical JSON of every other
field. Editing, deleting, inserting or reordering records breaks the chain and is reported by
:meth:`CustodyLog.verify`.

Truncation of the *tail* cannot be detected by a hash chain alone; callers should anchor the head
(``seq`` + ``entry_hash``) somewhere else (the case database does this, and reports print it)
and pass it as ``expected_head`` to :meth:`CustodyLog.verify`.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import platform
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensidvr import TOOL_NAME, __version__
from forensidvr.core.errors import CustodyLogError, CustodyLogTamperedError
from forensidvr.core.jsonutil import canonical_json, to_jsonable
from forensidvr.core.timeutil import Clock, isoformat_utc, parse_iso_utc, utcnow

GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 1

try:  # POSIX advisory lock serialises writers from multiple processes.
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)

except ImportError:  # pragma: no cover - non-POSIX

    def _lock(fd: int) -> None:
        return None

    def _unlock(fd: int) -> None:
        return None


@dataclass(frozen=True)
class CustodyEntry:
    """One immutable custody record."""

    seq: int
    timestamp_utc: str
    case_id: str
    actor: str
    action: str
    details: dict[str, Any]
    host: str
    os_user: str
    tool: str
    prev_hash: str
    entry_hash: str
    schema: int = SCHEMA_VERSION

    def body(self) -> dict[str, Any]:
        """All fields except ``entry_hash`` (the hashed content)."""
        d = {k: v for k, v in to_jsonable(self).items() if k != "entry_hash"}
        return d

    def compute_hash(self) -> str:
        return compute_entry_hash(self.body())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CustodyEntry:
        return cls(
            seq=int(d["seq"]),
            timestamp_utc=str(d["timestamp_utc"]),
            case_id=str(d["case_id"]),
            actor=str(d["actor"]),
            action=str(d["action"]),
            details=dict(d.get("details") or {}),
            host=str(d.get("host", "")),
            os_user=str(d.get("os_user", "")),
            tool=str(d.get("tool", "")),
            prev_hash=str(d["prev_hash"]),
            entry_hash=str(d["entry_hash"]),
            schema=int(d.get("schema", SCHEMA_VERSION)),
        )


def compute_entry_hash(body: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON of a record body."""
    return hashlib.sha256(canonical_json(body)).hexdigest()


@dataclass
class CustodyVerification:
    """Outcome of :meth:`CustodyLog.verify`."""

    ok: bool
    entries: int
    head_seq: int
    head_hash: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - no passwd entry in some containers
        return str(os.getuid()) if hasattr(os, "getuid") else "unknown"


class CustodyLog:
    """Append-only custody log bound to a single case."""

    def __init__(self, path: str | os.PathLike[str], case_id: str, clock: Clock = utcnow) -> None:
        self.path = Path(path)
        self.case_id = case_id
        self._clock = clock
        self._host = socket.gethostname()
        self._os_user = _os_user()
        self._tool = f"{TOOL_NAME} {__version__} (Python {platform.python_version()})"

    # -- reading ---------------------------------------------------------------------------
    def _raw_lines(self) -> Iterator[tuple[int, str]]:
        if not self.path.exists():
            return
        with open(self.path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if line.strip():
                    yield lineno, line

    def entries(self) -> Iterator[CustodyEntry]:
        """Yield parsed entries (no verification; malformed lines raise)."""
        for lineno, line in self._raw_lines():
            try:
                yield CustodyEntry.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError) as exc:
                raise CustodyLogTamperedError(f"line {lineno}: malformed record: {exc}") from exc

    def _last_entry(self, fd: int) -> CustodyEntry | None:
        size = os.fstat(fd).st_size
        if size == 0:
            return None
        # Read backwards until we hold the complete final line.
        block = 4096
        pos = size
        buf = b""
        while pos > 0:
            step = min(block, pos)
            pos -= step
            buf = os.pread(fd, step, pos) + buf
            stripped = buf.rstrip(b"\n")
            if b"\n" in stripped or pos == 0:
                last = stripped.rsplit(b"\n", 1)[-1]
                try:
                    return CustodyEntry.from_dict(json.loads(last))
                except (ValueError, KeyError, TypeError) as exc:
                    raise CustodyLogTamperedError(f"final record malformed: {exc}") from exc
            block *= 2
        return None  # pragma: no cover

    # -- writing ---------------------------------------------------------------------------
    def append(self, actor: str, action: str, details: dict[str, Any] | None = None) -> CustodyEntry:
        """Append one record. Refuses to extend a chain whose last record is corrupt."""
        if not actor or not action:
            raise CustodyLogError("actor and action are required")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o640)
        try:
            _lock(fd)
            rfd = os.open(self.path, os.O_RDONLY)
            try:
                last = self._last_entry(rfd)
            finally:
                os.close(rfd)
            if last is not None and not hmac.compare_digest(last.compute_hash(), last.entry_hash):
                raise CustodyLogTamperedError(
                    f"refusing to append: record seq={last.seq} fails its own hash check"
                )
            body: dict[str, Any] = {
                "schema": SCHEMA_VERSION,
                "seq": 0 if last is None else last.seq + 1,
                "timestamp_utc": isoformat_utc(self._clock()),
                "case_id": self.case_id,
                "actor": actor,
                "action": action,
                "details": to_jsonable(details or {}),
                "host": self._host,
                "os_user": self._os_user,
                "tool": self._tool,
                "prev_hash": GENESIS_HASH if last is None else last.entry_hash,
            }
            entry = CustodyEntry.from_dict({**body, "entry_hash": compute_entry_hash(body)})
            line = canonical_json({**body, "entry_hash": entry.entry_hash}) + b"\n"
            os.write(fd, line)
            os.fsync(fd)
            return entry
        finally:
            _unlock(fd)
            os.close(fd)

    # -- verification ----------------------------------------------------------------------
    def verify(self, expected_head: tuple[int, str] | None = None) -> CustodyVerification:
        """Walk the whole chain. Never raises for tampering; returns a report instead."""
        errors: list[str] = []
        warnings: list[str] = []
        prev_hash = GENESIS_HASH
        expected_seq = 0
        prev_ts = None
        count = 0
        head_seq, head_hash = -1, GENESIS_HASH
        for lineno, line in self._raw_lines():
            try:
                entry = CustodyEntry.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError) as exc:
                errors.append(f"line {lineno}: malformed record ({exc})")
                continue
            count += 1
            if entry.seq != expected_seq:
                errors.append(f"line {lineno}: sequence {entry.seq}, expected {expected_seq}")
            if not hmac.compare_digest(entry.prev_hash, prev_hash):
                errors.append(f"line {lineno} (seq {entry.seq}): prev_hash does not link to previous record")
            if not hmac.compare_digest(entry.compute_hash(), entry.entry_hash):
                errors.append(f"line {lineno} (seq {entry.seq}): content hash mismatch (record altered)")
            if entry.case_id != self.case_id:
                errors.append(f"line {lineno} (seq {entry.seq}): belongs to case {entry.case_id!r}")
            try:
                ts = parse_iso_utc(entry.timestamp_utc)
                if prev_ts is not None and ts < prev_ts:
                    warnings.append(f"seq {entry.seq}: timestamp earlier than previous record")
                prev_ts = ts
            except ValueError:
                errors.append(f"line {lineno} (seq {entry.seq}): invalid timestamp")
            prev_hash = entry.entry_hash
            expected_seq = entry.seq + 1
            head_seq, head_hash = entry.seq, entry.entry_hash
        if expected_head is not None:
            exp_seq, exp_hash = expected_head
            if head_seq != exp_seq or not hmac.compare_digest(head_hash, exp_hash):
                errors.append(
                    f"head mismatch: log ends at seq {head_seq}, anchor expects seq {exp_seq} "
                    "(records removed from the end, or log replaced)"
                )
        return CustodyVerification(
            ok=not errors,
            entries=count,
            head_seq=head_seq,
            head_hash=head_hash,
            errors=errors,
            warnings=warnings,
        )
