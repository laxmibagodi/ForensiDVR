import os
import sqlite3
from pathlib import Path

import pytest

from forensidvr.acquisition.workflow import register_existing_image
from forensidvr.core.case import Case
from forensidvr.core.errors import CaseError, EvidenceIntegrityError
from forensidvr.core.hashing import hash_file


def test_create_layout_and_custody(case: Case) -> None:
    for sub in ("evidence", "exports", "reports", "logs"):
        assert (case.root / sub).is_dir()
    entries = list(case.custody.entries())
    assert entries[0].action == "case.create" and entries[0].actor == "examiner1"
    assert case.verify_custody().ok
    assert case.custody_anchor() == (entries[-1].seq, entries[-1].entry_hash)


def test_create_refuses_non_empty_dir(tmp_path: Path) -> None:
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "f").write_text("")
    with pytest.raises(CaseError):
        Case.create(tmp_path / "x", name="n", examiner="e")


def test_open_logs_access_as_examiner(case: Case) -> None:
    case.close()
    c2 = Case.open(case.root, examiner="examiner2")
    last = list(c2.custody.entries())[-1]
    assert last.action == "case.open" and last.actor == "examiner2"
    c2.close()


def test_register_verify_and_session(case: Case, image_path: Path) -> None:
    rec = register_existing_image(case, image_path, label="dvr disk")
    assert rec.id == "EV-0001"
    assert rec.sha256 == hash_file(image_path).sha256
    assert case.verify_evidence(rec.id).ok
    assert case.start_session(rec.id)


def test_session_refuses_modified_evidence(case: Case, image_path: Path) -> None:
    rec = register_existing_image(case, image_path, label="dvr disk")
    with open(image_path, "r+b") as fh:  # simulate evidence alteration outside the tool
        fh.seek(100)
        fh.write(b"\xff")
    with pytest.raises(EvidenceIntegrityError):
        case.start_session(rec.id)
    actions = [e.action for e in case.custody.entries()]
    assert actions[-2:] == ["evidence.verify", "session.start"]
    assert list(case.custody.entries())[-1].details["verified"] is False


def test_missing_evidence_fails_verification(case: Case, image_path: Path) -> None:
    rec = register_existing_image(case, image_path, label="dvr disk")
    os.remove(image_path)
    outcome = case.verify_evidence(rec.id)
    assert not outcome.ok and outcome.error


def test_outputs_hashed_and_reverified(case: Case) -> None:
    out = case.root / "exports" / "clip.mp4"
    out.write_bytes(b"fake mp4")
    rec = case.register_output(out, kind="video", produced_by="test")
    assert rec.path == "exports/clip.mp4"
    assert rec.sha256 == hash_file(out).sha256
    assert all(ok for _, ok in case.verify_outputs())
    out.write_bytes(b"changed")
    assert not any(ok for _, ok in case.verify_outputs())


def test_tail_truncation_detected_via_db_anchor(case: Case) -> None:
    case.log("some.action", {})
    lines = case.custody.path.read_text().splitlines(keepends=True)
    case.custody.path.write_text("".join(lines[:-1]))
    res = case.verify_custody()
    assert not res.ok and any("head mismatch" in e for e in res.errors)


def test_schema_mismatch_rejected(case: Case) -> None:
    db = sqlite3.connect(case.root / "case.db")
    db.execute("UPDATE meta SET value='999' WHERE key='schema_version'")
    db.commit()
    db.close()
    with pytest.raises(CaseError):
        Case.open(case.root)
