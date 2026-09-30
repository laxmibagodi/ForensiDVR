"""Identification inside a case: re-verification, hashed output, custody logging, CLI."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from forensidvr.acquisition.workflow import identify_evidence, register_existing_image
from forensidvr.cli.main import app
from forensidvr.core.case import Case
from forensidvr.core.errors import EvidenceIntegrityError
from tests.fixtures.images import make_e01
from tests.fixtures.synth import MiB, make_dahua, make_hikvision

runner = CliRunner()


def run(*args: str, code: int = 0) -> str:
    res = runner.invoke(app, list(args), catch_exceptions=False)
    assert res.exit_code == code, res.output
    return res.output


@pytest.fixture
def dahua_img(tmp_path: Path) -> Path:
    return make_dahua(tmp_path / "dvr.img", size=12 * MiB).path


def _case(root: Path) -> Case:
    return Case.create(root, name="t", examiner="insp.rao")


def test_identify_evidence_logs_and_hashes(tmp_path: Path, dahua_img: Path) -> None:
    with _case(tmp_path / "c") as case:
        ev = register_existing_image(case, dahua_img, label="dvr")
        result, out = identify_evidence(case, ev.id)
        assert result.vendor_family == "dahua" and out.kind == "identification"
        saved = json.loads((case.root / out.path).read_text())
        assert saved["vendor"] == "Dahua" and saved["channel_count"] == 4
        actions = [e.action for e in case.custody.entries()]
        assert actions.index("session.start") < actions.index("identify.result")
        entry = next(e for e in case.custody.entries() if e.action == "identify.result")
        assert entry.details["output_sha256"] == out.sha256 and entry.details["status"] == "identified"
        _, out2 = identify_evidence(case, ev.id)
        assert out2.path != out.path and out2.sha256 == out.sha256  # deterministic
        assert case.custody.verify().ok


def test_identify_refuses_modified_evidence(tmp_path: Path, dahua_img: Path) -> None:
    copy = tmp_path / "copy.img"
    shutil.copy(dahua_img, copy)
    with _case(tmp_path / "c") as case:
        ev = register_existing_image(case, copy, label="dvr")
        with copy.open("r+b") as fh:
            fh.seek(100)
            fh.write(b"X")
        with pytest.raises(EvidenceIntegrityError):
            identify_evidence(case, ev.id)
        assert not any(e.action == "identify.result" for e in case.custody.entries())


@pytest.mark.skipif(shutil.which("ewfacquire") is None, reason="ewfacquire not installed")
def test_identify_e01_container(tmp_path: Path) -> None:
    raw = make_hikvision(tmp_path / "hik.img", size=8 * MiB).path
    e01 = make_e01(raw, tmp_path / "hik")
    with _case(tmp_path / "c") as case:
        ev = register_existing_image(case, e01, label="hik")
        result, _ = identify_evidence(case, ev.id)
    assert (result.vendor, result.fs_version) == ("Hikvision", "HIK.2011.03.08")


def test_cli_identify(tmp_path: Path, dahua_img: Path) -> None:
    case = tmp_path / "case"
    run("case", "create", str(case), "--name", "x", "--examiner", "insp.rao")
    run("evidence", "add", str(case), str(dahua_img), "--label", "dvr")
    out = run("identify", str(case), "EV-0001")
    assert "IDENTIFIED" in out and "Dahua" in out and "saved" in out
    data = json.loads(run("identify", str(case), "EV-0001", "--json"))
    assert data["vendor_family"] == "dahua" and data["recommended_fs_plugin"] == "generic-carve"
    assert "Identifier plugins" in run("plugins", "list")
    assert "custody log OK" in run("custody", "verify", str(case))
    with dahua_img.open("r+b") as fh:
        fh.write(b"\x00")
    assert "mismatch" in run("identify", str(case), "EV-0001", code=2)


def test_cli_image_identify_preview(tmp_path: Path) -> None:
    img = make_hikvision(tmp_path / "h.img", size=8 * MiB).path
    out = run("image", "identify", str(img))
    assert "Hikvision" in out and "preview only" in out
    assert run("image", "identify", str(tmp_path / "missing.img"), code=1)
