import json
from pathlib import Path

from typer.testing import CliRunner

from forensidvr.cli.main import app

runner = CliRunner()


def run(*args: str, code: int = 0) -> str:
    res = runner.invoke(app, list(args), catch_exceptions=False)
    assert res.exit_code == code, res.output
    return res.output


def test_end_to_end_cli(tmp_path: Path, image_path: Path) -> None:
    case = tmp_path / "case"
    run(
        "case",
        "create",
        str(case),
        "--name",
        "Burglary 42",
        "--examiner",
        "insp.rao",
        "--case-number",
        "FIR-42/2026",
        "--agency",
        "State FSL",
    )
    out = run("acquire", "disk", str(case), str(image_path), "--label", "hdd1", "--block-size", "256K")
    assert "verification: PASS" in out and "EV-0001" in out
    run("evidence", "add", str(case), str(image_path), "--label", "original", "-e", "analyst2")
    out = run("evidence", "verify", str(case))
    assert out.count("PASS") == 2
    assert "hash verified" in run("session", str(case), "EV-0001")
    info = json.loads(run("case", "info", str(case), "--json"))
    assert info["case"]["case_number"] == "FIR-42/2026" and len(info["evidence"]) == 2
    assert "custody log OK" in run("custody", "verify", str(case))
    entries = json.loads(run("custody", "show", str(case), "--tail", "0", "--json"))
    assert {"analyst2", "insp.rao"} <= {e["actor"] for e in entries}
    assert any(e["action"] == "cli.command" for e in entries)

    # tamper with the custody log -> exit code 3
    log = case / "custody.jsonl"
    lines = log.read_text().splitlines(keepends=True)
    rec = json.loads(lines[1])
    rec["actor"] = "mallory"
    lines[1] = json.dumps(rec) + "\n"
    log.write_text("".join(lines))
    assert "TAMPERED" in run("custody", "verify", str(case), code=3)


def test_session_fails_on_modified_evidence(tmp_path: Path, image_path: Path) -> None:
    case = tmp_path / "case"
    run("case", "create", str(case), "--name", "n", "--examiner", "e")
    run("evidence", "add", str(case), str(image_path), "--label", "img")
    with open(image_path, "r+b") as fh:
        fh.write(b"X")
    run("session", str(case), "EV-0001", code=2)
    run("evidence", "verify", str(case), "EV-0001", code=2)


def test_hash_image_info_and_plugins(image_path: Path) -> None:
    out = json.loads(run("hash", str(image_path), "--json"))
    assert out[str(image_path)]["size"] == image_path.stat().st_size
    info = json.loads(run("image", "info", str(image_path), "--hash"))
    assert info["format"] == "raw" and info["media_hashes"]["sha256"]
    assert "generic-carve" in run("plugins", "list")
    assert "ForensiDVR" in run("version")


def test_errors_are_clean(tmp_path: Path) -> None:
    res = runner.invoke(app, ["case", "info", str(tmp_path / "nope")])
    assert res.exit_code == 1 and "not a ForensiDVR case" in res.output
