import itertools
import json
from pathlib import Path

import pytest

from forensidvr.core.custody import GENESIS_HASH, CustodyLog
from forensidvr.core.errors import CustodyLogError, CustodyLogTamperedError


def _log(tmp_path: Path, clock, n: int = 5) -> CustodyLog:
    log = CustodyLog(tmp_path / "custody.jsonl", "case-1", clock=clock)
    for i in range(n):
        log.append("alice", f"action.{i}", {"i": i, "note": "ünïcode"})
    return log


def _lines(log: CustodyLog) -> list[str]:
    return log.path.read_text(encoding="utf-8").splitlines(keepends=True)


def _write(log: CustodyLog, lines: list[str]) -> None:
    log.path.write_text("".join(lines), encoding="utf-8")


def test_chain_links_and_verifies(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    entries = list(log.entries())
    assert [e.seq for e in entries] == list(range(5))
    assert entries[0].prev_hash == GENESIS_HASH
    for a, b in itertools.pairwise(entries):
        assert b.prev_hash == a.entry_hash
    assert entries[0].timestamp_utc == "2026-01-01T00:00:00.000000Z"
    res = log.verify(expected_head=(4, entries[-1].entry_hash))
    assert res.ok and res.entries == 5 and not res.warnings


def test_detects_modified_record(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    lines = _lines(log)
    rec = json.loads(lines[2])
    rec["details"]["i"] = 999
    lines[2] = json.dumps(rec) + "\n"
    _write(log, lines)
    res = log.verify()
    assert not res.ok
    assert any("content hash mismatch" in e for e in res.errors)


def test_detects_recomputed_hash_forgery(tmp_path, fixed_clock) -> None:
    """Attacker edits a record AND recomputes its own hash: the next link breaks."""
    from forensidvr.core.custody import compute_entry_hash

    log = _log(tmp_path, fixed_clock)
    lines = _lines(log)
    rec = json.loads(lines[1])
    rec["actor"] = "mallory"
    body = {k: v for k, v in rec.items() if k != "entry_hash"}
    rec["entry_hash"] = compute_entry_hash(body)
    lines[1] = json.dumps(rec) + "\n"
    _write(log, lines)
    res = log.verify()
    assert not res.ok
    assert any("seq 2" in e and "prev_hash" in e for e in res.errors)


def test_detects_deleted_middle_record(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    lines = _lines(log)
    del lines[2]
    _write(log, lines)
    res = log.verify()
    assert not res.ok
    assert any("sequence 3, expected 2" in e for e in res.errors)


def test_detects_reordering(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    lines = _lines(log)
    lines[1], lines[2] = lines[2], lines[1]
    _write(log, lines)
    assert not log.verify().ok


def test_tail_truncation_needs_anchor(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    head = list(log.entries())[-1]
    _write(log, _lines(log)[:-1])
    assert log.verify().ok  # chain alone cannot see a removed tail ...
    res = log.verify(expected_head=(head.seq, head.entry_hash))
    assert not res.ok and any("head mismatch" in e for e in res.errors)  # ... the anchor can


def test_malformed_line_reported_not_raised(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    lines = _lines(log)
    lines.insert(2, "{not json\n")
    _write(log, lines)
    res = log.verify()
    assert not res.ok and any("malformed" in e for e in res.errors)


def test_refuses_to_append_after_tampered_tail(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    lines = _lines(log)
    rec = json.loads(lines[-1])
    rec["action"] = "forged"
    lines[-1] = json.dumps(rec) + "\n"
    _write(log, lines)
    with pytest.raises(CustodyLogTamperedError):
        log.append("alice", "next")


def test_wrong_case_id_detected(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock)
    other = CustodyLog(log.path, "case-2")
    assert not other.verify().ok


def test_requires_actor_and_action(tmp_path) -> None:
    log = CustodyLog(tmp_path / "c.jsonl", "c")
    with pytest.raises(CustodyLogError):
        log.append("", "x")


def test_file_is_append_only_in_practice(tmp_path, fixed_clock) -> None:
    log = _log(tmp_path, fixed_clock, n=2)
    before = log.path.read_bytes()
    log.append("bob", "later")
    assert log.path.read_bytes().startswith(before)


def test_non_monotonic_clock_warns(tmp_path) -> None:
    from datetime import UTC, datetime

    times = iter([datetime(2026, 1, 2, tzinfo=UTC), datetime(2026, 1, 1, tzinfo=UTC)])
    log = CustodyLog(tmp_path / "c.jsonl", "c", clock=lambda: next(times))
    log.append("a", "one")
    log.append("a", "two")
    res = log.verify()
    assert res.ok and res.warnings
