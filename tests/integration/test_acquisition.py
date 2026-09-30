import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from forensidvr.acquisition.imager import acquire_raw
from forensidvr.acquisition.workflow import acquire_to_case
from forensidvr.core.case import Case
from forensidvr.core.errors import AcquisitionError
from forensidvr.core.hashing import hash_file
from forensidvr.core.readonly import WriteBlocker
from tests.fixtures.images import FaultySource, pattern_bytes


def test_acquire_file_hashes_and_verifies(tmp_path: Path, image_path: Path, fixed_clock) -> None:
    data = image_path.read_bytes()
    before = hash_file(image_path)
    mtime = os.stat(image_path).st_mtime_ns
    with WriteBlocker([image_path]):
        r = acquire_raw(
            image_path,
            tmp_path / "out.dd",
            block_size=64 * 1024,
            log_path=tmp_path / "acq.jsonl",
            report_dir=tmp_path / "rep",
            clock=fixed_clock,
        )
    assert r.verified and not r.bad_sectors
    assert r.acquisition_hashes.sha256 == hashlib.sha256(data).hexdigest()
    assert r.acquisition_hashes.md5 == hashlib.md5(data).hexdigest()
    assert (tmp_path / "out.dd").read_bytes() == data
    assert stat.S_IMODE(os.stat(tmp_path / "out.dd").st_mode) == 0o444
    # source untouched (read-only requirement)
    assert hash_file(image_path) == before and os.stat(image_path).st_mtime_ns == mtime
    report = json.loads(Path(r.report_json).read_text())
    assert report["verified"] is True and report["acquisition_hashes"]["sha256"] == before.sha256
    assert "PASS" in Path(r.report_md).read_text()
    events = [json.loads(line)["event"] for line in Path(r.log_path).read_text().splitlines()]
    assert events == ["start", "acquired", "verified", "finish"]


def test_never_overwrites_destination(tmp_path: Path, image_path: Path) -> None:
    dest = tmp_path / "out.dd"
    dest.write_bytes(b"existing")
    with pytest.raises(AcquisitionError):
        acquire_raw(image_path, dest)
    assert dest.read_bytes() == b"existing"


def test_split_output(tmp_path: Path, image_path: Path) -> None:
    r = acquire_raw(image_path, tmp_path / "out.dd", block_size=512 * 1024, split_size=1024 * 1024)
    assert r.verified and r.format == "split-raw"
    assert [Path(p).name for p in r.destination] == ["out.dd.001", "out.dd.002", "out.dd.003", "out.dd.004"]
    joined = b"".join(Path(p).read_bytes() for p in r.destination)
    assert joined == image_path.read_bytes()


def test_bad_sectors_zero_filled_logged_and_hashed(tmp_path: Path) -> None:
    data = pattern_bytes(256 * 1024, seed=1)
    src = FaultySource(data, bad_ranges=[(70_000, 1500), (200_704, 512)])
    r = acquire_raw(
        src,
        tmp_path / "out.dd",
        block_size=64 * 1024,
        retries=1,
        log_path=tmp_path / "log.jsonl",
        report_dir=tmp_path,
    )
    assert r.verified
    # 70000..71500 touches sectors 136..139 (69632..71680)
    assert [(b.offset, b.length) for b in r.bad_sectors] == [(69_632, 2048), (200_704, 512)]
    expected = bytearray(data)
    expected[69_632:71_680] = bytes(2048)
    expected[200_704:201_216] = bytes(512)
    assert (tmp_path / "out.dd").read_bytes() == bytes(expected)
    assert r.acquisition_hashes.sha256 == hashlib.sha256(expected).hexdigest()
    assert "Unreadable sectors" in Path(r.report_md).read_text()
    log = Path(r.log_path).read_text()
    assert log.count('"event":"bad_sector"') == 5 and '"event":"read_error"' in log


def test_transient_error_recovered_by_retry(tmp_path: Path) -> None:
    data = pattern_bytes(128 * 1024, seed=2)
    src = FaultySource(data, bad_ranges=[(1000, 10)], transient=1)
    r = acquire_raw(src, tmp_path / "out.dd", block_size=64 * 1024, retries=2)
    assert not r.bad_sectors and (tmp_path / "out.dd").read_bytes() == data


def test_deterministic_repeat_acquisition(tmp_path: Path, image_path: Path) -> None:
    a = acquire_raw(image_path, tmp_path / "a.dd")
    b = acquire_raw(image_path, tmp_path / "b.dd", block_size=4096)
    assert a.evidence_summary() == b.evidence_summary()


def test_empty_source(tmp_path: Path) -> None:
    src = tmp_path / "empty"
    src.write_bytes(b"")
    r = acquire_raw(src, tmp_path / "out.dd")
    assert r.verified and r.acquisition_hashes.size == 0 and (tmp_path / "out.dd").exists()


def test_invalid_block_size(tmp_path: Path, image_path: Path) -> None:
    with pytest.raises(AcquisitionError):
        acquire_raw(image_path, tmp_path / "o", block_size=1000)


def test_acquire_to_case_registers_everything(case: Case, image_path: Path) -> None:
    result, rec = acquire_to_case(case, image_path, label="DVR-1 HDD")
    assert rec is not None and rec.path == "evidence/DVR-1_HDD.dd"
    assert rec.sha256 == hash_file(image_path).sha256
    kinds = sorted(o.kind for o in case.list_outputs())
    assert kinds == ["acquisition-log", "acquisition-report-json", "acquisition-report-md"]
    acq = case.list_acquisitions()
    assert acq[0]["verified"] == 1 and acq[0]["evidence_id"] == rec.id
    actions = [e.action for e in case.custody.entries()]
    assert (
        actions.index("acquisition.start")
        < actions.index("evidence.register")
        < actions.index("acquisition.finish")
    )
    assert case.verify_custody().ok
    assert case.start_session(rec.id)
    with pytest.raises(AcquisitionError):
        acquire_to_case(case, image_path, label="DVR-1 HDD")
