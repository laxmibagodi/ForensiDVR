import os
import shutil
from pathlib import Path

import pytest

from forensidvr.core.errors import WriteBlockedError
from forensidvr.core.hashing import hash_file
from forensidvr.core.readonly import ReadOnlyFile, WriteBlocker, open_readonly


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    p = tmp_path / "evidence.dd"
    p.write_bytes(b"EVIDENCE" * 1024)
    return p


def test_open_readonly_fd_cannot_write(evidence: Path) -> None:
    fd = open_readonly(evidence)
    try:
        with pytest.raises(OSError):
            os.write(fd, b"x")
    finally:
        os.close(fd)


def test_readonly_file_has_no_write_path(evidence: Path) -> None:
    with ReadOnlyFile(evidence) as f:
        assert f.read_at(0, 8) == b"EVIDENCE"
        assert f.read_at(f.size - 2, 100) == b"CE"
        with pytest.raises(WriteBlockedError):
            f.write(b"x")
        with pytest.raises(WriteBlockedError):
            f.truncate(0)


@pytest.mark.parametrize("mode", ["wb", "ab", "r+b", "xb", "w", "a+"])
def test_blocker_denies_write_modes(evidence: Path, mode: str) -> None:
    with WriteBlocker([evidence]) as wb, pytest.raises(WriteBlockedError):
        open(evidence, mode)
    assert wb.blocked_attempts


def test_blocker_denies_os_level_and_path_ops(evidence: Path, tmp_path: Path) -> None:
    with WriteBlocker([evidence]):
        for flags in (os.O_WRONLY, os.O_RDWR, os.O_RDONLY | os.O_TRUNC, os.O_APPEND):
            with pytest.raises(WriteBlockedError):
                os.open(evidence, flags)
        with pytest.raises(WriteBlockedError):
            os.remove(evidence)
        with pytest.raises(WriteBlockedError):
            os.unlink(evidence)
        with pytest.raises(WriteBlockedError):
            os.rename(evidence, tmp_path / "moved")
        with pytest.raises(WriteBlockedError):
            os.replace(tmp_path / "other", evidence)
        with pytest.raises(WriteBlockedError):
            os.truncate(evidence, 0)
        with pytest.raises(WriteBlockedError):
            os.chmod(evidence, 0o777)
        with pytest.raises(WriteBlockedError):
            shutil.move(evidence, tmp_path / "moved")
        with pytest.raises(WriteBlockedError):
            evidence.write_bytes(b"x")
        with pytest.raises(WriteBlockedError):
            evidence.unlink()


def test_blocker_matches_symlink_and_relative_paths(evidence: Path, tmp_path: Path, monkeypatch) -> None:
    link = tmp_path / "link.dd"
    link.symlink_to(evidence)
    monkeypatch.chdir(tmp_path)
    with WriteBlocker([evidence]):
        with pytest.raises(WriteBlockedError):
            open(link, "wb")
        with pytest.raises(WriteBlockedError):
            open("evidence.dd", "r+b")


def test_blocker_allows_reads_and_other_files(evidence: Path, tmp_path: Path) -> None:
    other = tmp_path / "report.txt"
    with WriteBlocker([evidence]):
        with open(evidence, "rb") as fh:
            assert fh.read(8) == b"EVIDENCE"
        other.write_text("ok")
        with ReadOnlyFile(evidence) as f:
            assert f.size == 8192
    assert other.read_text() == "ok"


def test_blocker_uninstalls_cleanly(evidence: Path) -> None:
    import builtins

    original = builtins.open
    with WriteBlocker([evidence]), WriteBlocker([evidence]):
        assert builtins.open is not original
    assert builtins.open is original
    with open(evidence, "ab") as fh:  # no longer protected
        fh.write(b"")


def test_reading_pipeline_leaves_evidence_unchanged(evidence: Path) -> None:
    from forensidvr.acquisition.readers import open_image

    before = hash_file(evidence)
    st = os.stat(evidence)
    with WriteBlocker([evidence]), open_image(evidence) as r:
        r.read_at(0, r.size)
    assert hash_file(evidence) == before
    assert os.stat(evidence).st_mtime_ns == st.st_mtime_ns
