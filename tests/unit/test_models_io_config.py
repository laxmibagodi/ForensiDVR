from datetime import UTC, datetime

import pytest

from forensidvr.core.config import Config
from forensidvr.core.io import BytesSource, SliceSource, iter_chunks
from forensidvr.core.jsonutil import canonical_json
from forensidvr.core.models import (
    EventType,
    ProbeResult,
    Recording,
    RecoveryStatus,
    SourceRef,
    TimeConfidence,
    TimestampValue,
)


def test_timestamp_keeps_raw_and_requires_aware_utc() -> None:
    ts = TimestampValue(
        raw=0x5F5E1000,
        raw_encoding="u32-epoch-local",
        utc=datetime(2020, 9, 13, tzinfo=UTC),
        tz_name="Asia/Kolkata",
        utc_offset_seconds=19800,
        confidence=TimeConfidence.MEDIUM,
    )
    assert ts.raw == 0x5F5E1000
    with pytest.raises(ValueError):
        TimestampValue(raw="x", raw_encoding="t", utc=datetime(2020, 1, 1))


def test_confidence_bounds() -> None:
    with pytest.raises(ValueError):
        ProbeResult(plugin="x", confidence=1.5)
    with pytest.raises(ValueError):
        Recording(recording_id="r", channel=1, start=None, end=None, size=0, confidence=-0.1)


def test_recording_serialises_deterministically() -> None:
    def make() -> Recording:
        return Recording(
            recording_id="r1",
            channel=3,
            start=None,
            end=None,
            size=10,
            event_type=EventType.MOTION,
            status=RecoveryStatus.RECOVERED_CARVED,
            extents=[SourceRef(512, 10)],
            raw_metadata={"b": 1, "a": 2},
            confidence=0.5,
        )

    assert canonical_json(make()) == canonical_json(make())
    assert b'"status":"RECOVERED-CARVED"' in canonical_json(make())


def test_sources() -> None:
    src = BytesSource(bytes(range(100)))
    sl = SliceSource(src, 10, 20)
    assert sl.size == 20 and sl.read_at(0, 3) == bytes([10, 11, 12])
    assert sl.read_at(18, 10) == bytes([28, 29]) and sl.read_at(25, 1) == b""
    assert b"".join(d for _, d in iter_chunks(src, 7)) == bytes(range(100))
    with pytest.raises(ValueError):
        SliceSource(src, 90, 20)


def test_config_env_override(tmp_path, monkeypatch) -> None:
    cfg_file = tmp_path / "c.toml"
    cfg_file.write_text('[forensidvr]\nchunk_size = 1024\nexaminer = "file"\n')
    monkeypatch.setenv("FORENSIDVR_EXAMINER", "env")
    monkeypatch.setenv("FORENSIDVR_REDACT_PASSWORDS", "false")
    cfg = Config.load(cfg_file)
    assert cfg.chunk_size == 1024 and cfg.examiner == "env" and cfg.redact_passwords is False
