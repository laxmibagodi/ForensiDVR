import json
import os
from pathlib import Path

import pytest

from forensidvr.acquisition.logical import import_logical
from forensidvr.acquisition.workflow import import_logical_to_case
from forensidvr.core.case import Case
from forensidvr.core.errors import AcquisitionError
from forensidvr.core.hashing import hash_file


@pytest.fixture
def export_dir(tmp_path: Path) -> Path:
    d = tmp_path / "usb_export"
    (d / "ch01").mkdir(parents=True)
    (d / "ch01" / "20260101_120000.dav").write_bytes(b"DHAV" + bytes(1000))
    (d / "ch01" / "clip.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42" + bytes(100))
    (d / "config.bin").write_bytes(b"CFG" * 10)
    (d / "system.log").write_text("2026-01-01 12:00:00 login admin\n")
    (d / "link.mp4").symlink_to(d / "ch01" / "clip.mp4")
    return d


def test_import_copies_hashes_and_manifests(tmp_path: Path, export_dir: Path) -> None:
    r = import_logical(export_dir, tmp_path / "dest")
    rels = [f.relative_path for f in r.files]
    assert rels == sorted(rels) and len(rels) == 4
    cats = {f.relative_path: f.category for f in r.files}
    assert cats["ch01/20260101_120000.dav"] == "video" and cats["config.bin"] == "config"
    assert cats["system.log"] == "log"
    assert "link.mp4" in r.skipped and r.all_verified
    for f in r.files:
        assert hash_file(export_dir / f.relative_path).sha256 == f.sha256
        assert hash_file(tmp_path / "dest" / "files" / f.relative_path).sha256 == f.sha256
    manifest = json.loads(Path(r.manifest_path).read_text())
    assert len(manifest["files"]) == 4


def test_unreadable_file_skipped_not_fatal(tmp_path: Path, export_dir: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read mode-000 files")
    bad = export_dir / "locked.log"
    bad.write_text("secret")
    bad.chmod(0)
    try:
        r = import_logical(export_dir, tmp_path / "dest")
        assert "locked.log" in r.skipped and len(r.files) == 4
    finally:
        bad.chmod(0o644)


def test_refuses_non_empty_destination(tmp_path: Path, export_dir: Path) -> None:
    (tmp_path / "dest").mkdir()
    (tmp_path / "dest" / "x").write_text("")
    with pytest.raises(AcquisitionError):
        import_logical(export_dir, tmp_path / "dest")


def test_import_to_case(case: Case, export_dir: Path) -> None:
    r, rec = import_logical_to_case(case, export_dir, label="usb export")
    assert rec.kind == "logical" and rec.path == "evidence/usb_export/manifest.json"
    assert case.verify_evidence(rec.id).ok
    finish = next(e for e in case.custody.entries() if e.action == "logical.finish")
    assert finish.details["files"] == 4 and finish.details["all_verified"] is True


def test_logical_verify_detects_modified_member_file(case: Case, export_dir: Path) -> None:
    _, rec = import_logical_to_case(case, export_dir, label="usb export")
    member = case.root / "evidence" / "usb_export" / "files" / "system.log"
    member.chmod(0o644)
    member.write_text("tampered\n")
    outcome = case.verify_evidence(rec.id)
    assert not outcome.ok and "system.log" in (outcome.error or "")
