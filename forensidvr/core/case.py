"""Case management: case directory, SQLite case database, evidence register, output hashing.

Case directory layout::

    <case>/
      case.db          SQLite case database
      custody.jsonl    append-only hash-chained custody log
      evidence/        acquired images and logical imports (made read-only after acquisition)
      exports/         derived outputs (MP4, carved data, ...)
      reports/         acquisition / analysis reports
      logs/            per-operation logs

Every state-changing method writes a custody record, and the custody head is anchored in the
database after each append so tail truncation of the log is detectable.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forensidvr import TOOL_NAME, __version__
from forensidvr.core.custody import CustodyEntry, CustodyLog, CustodyVerification
from forensidvr.core.errors import CaseError, EvidenceIntegrityError
from forensidvr.core.hashing import HashSet, hash_file, hash_source
from forensidvr.core.io import ByteSource
from forensidvr.core.jsonutil import canonical_json
from forensidvr.core.timeutil import Clock, isoformat_utc, utcnow

SCHEMA_VERSION = 1
DB_NAME = "case.db"
CUSTODY_NAME = "custody.jsonl"
SUBDIRS = ("evidence", "exports", "reports", "logs")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    format TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    source_description TEXT,
    acquisition_id TEXT,
    registered_utc TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS acquisitions (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id),
    method TEXT NOT NULL,
    source TEXT NOT NULL,
    started_utc TEXT NOT NULL,
    finished_utc TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    verified INTEGER NOT NULL,
    bad_sector_count INTEGER NOT NULL DEFAULT 0,
    report_path TEXT
);
CREATE TABLE IF NOT EXISTS outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    evidence_id TEXT,
    produced_by TEXT NOT NULL,
    created_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    examiner TEXT NOT NULL,
    started_utc TEXT NOT NULL,
    md5 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    verified INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS custody_anchor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL,
    head_hash TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class CaseInfo:
    case_id: str
    name: str
    case_number: str
    examiner: str
    agency: str
    description: str
    created_utc: str
    tool: str


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    label: str
    kind: str
    format: str
    path: str
    size: int
    md5: str
    sha256: str
    source_description: str | None
    acquisition_id: str | None
    registered_utc: str
    registered_by: str
    notes: str | None

    @property
    def hashes(self) -> HashSet:
        return HashSet(md5=self.md5, sha256=self.sha256, size=self.size)


@dataclass(frozen=True)
class OutputRecord:
    id: int
    path: str
    kind: str
    size: int
    md5: str
    sha256: str
    evidence_id: str | None
    produced_by: str
    created_utc: str


@dataclass(frozen=True)
class VerificationOutcome:
    evidence_id: str
    ok: bool
    expected: HashSet
    actual: HashSet | None
    error: str | None = None


class Case:
    """An open case. Use :meth:`create` or :meth:`open`."""

    def __init__(self, root: Path, examiner: str | None = None, clock: Clock = utcnow) -> None:
        self.root = root.resolve()
        db = self.root / DB_NAME
        if not db.exists():
            raise CaseError(f"{self.root} is not a ForensiDVR case (no {DB_NAME})")
        self._clock = clock
        self._db = sqlite3.connect(db, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self.info = self._load_info()
        self.examiner = examiner or self.info.examiner
        self.custody = CustodyLog(self.root / CUSTODY_NAME, self.info.case_id, clock=clock)

    # -- lifecycle ---------------------------------------------------------------------------
    @classmethod
    def create(
        cls,
        root: str | os.PathLike[str],
        *,
        name: str,
        examiner: str,
        case_number: str = "",
        agency: str = "",
        description: str = "",
        clock: Clock = utcnow,
    ) -> Case:
        """Create a new case directory. Refuses to reuse a non-empty directory."""
        path = Path(root)
        if path.exists() and any(path.iterdir()):
            raise CaseError(f"{path} exists and is not empty")
        if not name or not examiner:
            raise CaseError("case name and examiner are required")
        path.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (path / sub).mkdir()
        case_id = str(uuid.uuid4())
        db = sqlite3.connect(path / DB_NAME, isolation_level=None)
        try:
            db.executescript(_SCHEMA)
            meta = {
                "schema_version": str(SCHEMA_VERSION),
                "case_id": case_id,
                "name": name,
                "case_number": case_number,
                "examiner": examiner,
                "agency": agency,
                "description": description,
                "created_utc": isoformat_utc(clock()),
                "tool": f"{TOOL_NAME} {__version__}",
            }
            db.executemany("INSERT INTO meta(key, value) VALUES (?, ?)", sorted(meta.items()))
        finally:
            db.close()
        case = cls(path, examiner=examiner, clock=clock)
        case.log("case.create", {k: v for k, v in meta.items() if k != "schema_version"})
        return case

    @classmethod
    def open(cls, root: str | os.PathLike[str], examiner: str | None = None, clock: Clock = utcnow) -> Case:
        """Open an existing case and record the access in the custody log."""
        case = cls(Path(root), examiner=examiner, clock=clock)
        case.log("case.open", {})
        return case

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Case:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _load_info(self) -> CaseInfo:
        rows = dict(self._db.execute("SELECT key, value FROM meta").fetchall())
        if rows.get("schema_version") != str(SCHEMA_VERSION):
            raise CaseError(f"unsupported case schema {rows.get('schema_version')!r}")
        return CaseInfo(
            case_id=rows["case_id"],
            name=rows["name"],
            case_number=rows.get("case_number", ""),
            examiner=rows["examiner"],
            agency=rows.get("agency", ""),
            description=rows.get("description", ""),
            created_utc=rows["created_utc"],
            tool=rows["tool"],
        )

    # -- custody -----------------------------------------------------------------------------
    def log(self, action: str, details: dict[str, Any] | None = None) -> CustodyEntry:
        """Append a custody record as the current examiner and anchor the new head."""
        entry = self.custody.append(self.examiner, action, details)
        self._db.execute(
            "INSERT INTO custody_anchor(id, seq, head_hash) VALUES (1, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET seq = excluded.seq, head_hash = excluded.head_hash",
            (entry.seq, entry.entry_hash),
        )
        return entry

    def custody_anchor(self) -> tuple[int, str] | None:
        row = self._db.execute("SELECT seq, head_hash FROM custody_anchor WHERE id = 1").fetchone()
        return None if row is None else (int(row["seq"]), str(row["head_hash"]))

    def verify_custody(self) -> CustodyVerification:
        """Verify the full chain against the database anchor (detects tail truncation)."""
        return self.custody.verify(expected_head=self.custody_anchor())

    # -- paths -------------------------------------------------------------------------------
    def rel(self, path: str | os.PathLike[str]) -> str:
        """Store paths inside the case relative to the case root, others absolute."""
        p = Path(path).resolve()
        try:
            return p.relative_to(self.root).as_posix()
        except ValueError:
            return str(p)

    def abs(self, stored: str) -> Path:
        p = Path(stored)
        return p if p.is_absolute() else self.root / p

    # -- evidence ----------------------------------------------------------------------------
    def _next_evidence_id(self) -> str:
        n = self._db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        return f"EV-{n + 1:04d}"

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield self._db
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    def add_evidence(
        self,
        path: str | os.PathLike[str],
        *,
        label: str,
        kind: str,
        format: str,
        hashes: HashSet,
        source_description: str | None = None,
        acquisition_id: str | None = None,
        notes: str | None = None,
    ) -> EvidenceRecord:
        """Register evidence whose hashes were computed by the caller (acquisition/import)."""
        with self._tx() as db:
            ev_id = self._next_evidence_id()
            rec = EvidenceRecord(
                id=ev_id,
                label=label,
                kind=kind,
                format=format,
                path=self.rel(path),
                size=hashes.size,
                md5=hashes.md5,
                sha256=hashes.sha256,
                source_description=source_description,
                acquisition_id=acquisition_id,
                registered_utc=isoformat_utc(self._clock()),
                registered_by=self.examiner,
                notes=notes,
            )
            db.execute(
                "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rec.id,
                    rec.label,
                    rec.kind,
                    rec.format,
                    rec.path,
                    rec.size,
                    rec.md5,
                    rec.sha256,
                    rec.source_description,
                    rec.acquisition_id,
                    rec.registered_utc,
                    rec.registered_by,
                    rec.notes,
                ),
            )
        self.log(
            "evidence.register",
            {
                "evidence_id": rec.id,
                "label": label,
                "kind": kind,
                "format": format,
                "path": rec.path,
                "size": rec.size,
                "md5": rec.md5,
                "sha256": rec.sha256,
                "acquisition_id": acquisition_id,
            },
        )
        return rec

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        row = self._db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise CaseError(f"unknown evidence id {evidence_id!r}")
        return EvidenceRecord(**dict(row))

    def list_evidence(self) -> list[EvidenceRecord]:
        rows = self._db.execute("SELECT * FROM evidence ORDER BY id").fetchall()
        return [EvidenceRecord(**dict(r)) for r in rows]

    def _hash_evidence(self, rec: EvidenceRecord) -> HashSet:
        from forensidvr.acquisition.readers import open_image

        path = self.abs(rec.path)
        if rec.kind == "logical":
            return hash_file(path)
        if rec.format in ("raw", "split-raw", "e01"):
            with open_image(path) as reader:
                return hash_source(reader)
        return hash_file(path)

    @staticmethod
    def _verify_logical_members(manifest_path: Path) -> list[str]:
        """Re-hash every file listed in a logical-import manifest; return mismatching paths."""
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        bad = []
        for item in manifest.get("files", []):
            member = manifest_path.parent / "files" / item["relative_path"]
            try:
                h = hash_file(member)
                if not h.matches(HashSet(item["md5"], item["sha256"], item["size"])):
                    bad.append(item["relative_path"])
            except OSError:
                bad.append(item["relative_path"])
        return bad

    def verify_evidence(self, evidence_id: str) -> VerificationOutcome:
        """Re-hash an evidence item and compare with its registered hashes."""
        rec = self.get_evidence(evidence_id)
        try:
            actual = self._hash_evidence(rec)
            ok = actual.matches(rec.hashes)
            error = None
            if ok and rec.kind == "logical":
                bad = self._verify_logical_members(self.abs(rec.path))
                if bad:
                    ok, error = False, "member files differ from manifest: " + ", ".join(bad)
            outcome = VerificationOutcome(evidence_id, ok, rec.hashes, actual, error)
        except (OSError, ValueError) as exc:
            outcome = VerificationOutcome(evidence_id, False, rec.hashes, None, str(exc))
        self.log(
            "evidence.verify",
            {
                "evidence_id": evidence_id,
                "ok": outcome.ok,
                "expected": rec.hashes.to_dict(),
                "actual": outcome.actual.to_dict() if outcome.actual else None,
                "error": outcome.error,
            },
        )
        return outcome

    def start_session(self, evidence_id: str) -> str:
        """Begin an analysis session: re-verify the evidence hash first (requirement #2).

        Raises :class:`EvidenceIntegrityError` (and logs it) if the hash no longer matches.
        """
        outcome = self.verify_evidence(evidence_id)
        session_id = str(uuid.uuid4())
        actual = outcome.actual or HashSet("", "", 0)
        self._db.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?)",
            (
                session_id,
                evidence_id,
                self.examiner,
                isoformat_utc(self._clock()),
                actual.md5,
                actual.sha256,
                int(outcome.ok),
            ),
        )
        self.log(
            "session.start",
            {"session_id": session_id, "evidence_id": evidence_id, "verified": outcome.ok},
        )
        if not outcome.ok:
            raise EvidenceIntegrityError(
                f"{evidence_id}: evidence hash mismatch or unreadable ({outcome.error or 'hash differs'})"
            )
        return session_id

    # -- acquisitions ------------------------------------------------------------------------
    def record_acquisition(
        self,
        *,
        acquisition_id: str,
        evidence_id: str | None,
        method: str,
        source: str,
        started_utc: str,
        finished_utc: str,
        hashes: HashSet,
        verified: bool,
        bad_sector_count: int,
        report_path: str | None,
    ) -> None:
        self._db.execute(
            "INSERT INTO acquisitions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                acquisition_id,
                evidence_id,
                method,
                source,
                started_utc,
                finished_utc,
                hashes.size,
                hashes.md5,
                hashes.sha256,
                int(verified),
                bad_sector_count,
                report_path,
            ),
        )

    def list_acquisitions(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._db.execute("SELECT * FROM acquisitions ORDER BY started_utc")]

    # -- outputs -----------------------------------------------------------------------------
    def register_output(
        self,
        path: str | os.PathLike[str],
        *,
        kind: str,
        produced_by: str,
        evidence_id: str | None = None,
    ) -> OutputRecord:
        """Hash (MD5 + SHA-256) and register a produced file (requirement #2)."""
        hashes = hash_file(path)
        stored = self.rel(path)
        created = isoformat_utc(self._clock())
        cur = self._db.execute(
            "INSERT INTO outputs(path, kind, size, md5, sha256, evidence_id, produced_by, created_utc)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (
                stored,
                kind,
                hashes.size,
                hashes.md5,
                hashes.sha256,
                evidence_id,
                produced_by,
                created,
            ),
        )
        rec = OutputRecord(
            int(cur.lastrowid or 0),
            stored,
            kind,
            hashes.size,
            hashes.md5,
            hashes.sha256,
            evidence_id,
            produced_by,
            created,
        )
        self.log(
            "output.register",
            {
                "path": stored,
                "kind": kind,
                "md5": hashes.md5,
                "sha256": hashes.sha256,
                "size": hashes.size,
                "evidence_id": evidence_id,
                "produced_by": produced_by,
            },
        )
        return rec

    def list_outputs(self) -> list[OutputRecord]:
        rows = self._db.execute("SELECT * FROM outputs ORDER BY id").fetchall()
        return [OutputRecord(**dict(r)) for r in rows]

    def verify_outputs(self) -> list[tuple[OutputRecord, bool]]:
        """Re-hash every registered output."""
        results = []
        for rec in self.list_outputs():
            try:
                h = hash_file(self.abs(rec.path))
                ok = h.matches(HashSet(rec.md5, rec.sha256, rec.size))
            except OSError:
                ok = False
            results.append((rec, ok))
        self.log(
            "outputs.verify",
            {"checked": len(results), "failed": [r.path for r, ok in results if not ok]},
        )
        return results

    def summary(self) -> dict[str, Any]:
        """Deterministic case summary (for ``case info`` and reports)."""
        anchor = self.custody_anchor()
        return {
            "case": self.info.__dict__,
            "evidence": [e.__dict__ for e in self.list_evidence()],
            "outputs": len(self.list_outputs()),
            "custody_head": {"seq": anchor[0], "hash": anchor[1]} if anchor else None,
        }


def fingerprint(obj: Any) -> str:
    """Stable SHA-256 of any JSON-able structure (used for determinism checks)."""
    import hashlib

    return hashlib.sha256(canonical_json(obj)).hexdigest()


__all__ = [
    "ByteSource",
    "Case",
    "CaseInfo",
    "EvidenceRecord",
    "OutputRecord",
    "VerificationOutcome",
    "fingerprint",
]
