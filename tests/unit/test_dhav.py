"""DHAV header/date helpers (layout from FFmpeg libavformat/dhav.c)."""

from __future__ import annotations

import struct
from datetime import datetime

import pytest

from forensidvr.formats.dhav import (
    DATE_ENCODING,
    dahua_timestamp,
    decode_dahua_datetime,
    encode_dahua_datetime,
    iter_dhav_headers,
    parse_dhav_header,
    trailer_matches,
)
from tests.fixtures.synth import dahua_packed, dhav_frame, h264_payload


def test_packed_datetime_roundtrip_matches_fixture_encoder() -> None:
    dt = datetime(2026, 1, 15, 23, 59, 58)
    raw = encode_dahua_datetime(dt)
    assert raw == dahua_packed(dt)
    assert decode_dahua_datetime(raw) == dt


def test_invalid_packed_datetime() -> None:
    assert decode_dahua_datetime(0) is None  # month 0
    with pytest.raises(ValueError):
        encode_dahua_datetime(datetime(1999, 1, 1))


def test_timestamp_keeps_raw_and_no_utc() -> None:
    raw = encode_dahua_datetime(datetime(2026, 1, 15, 10, 0, 0))
    ts = dahua_timestamp(raw)
    assert ts.raw == raw and ts.raw_encoding == DATE_ENCODING and ts.utc is None
    assert any("local=2026-01-15T10:00:00" in n for n in ts.notes)
    assert "invalid" in dahua_timestamp(0).notes[0]


def test_parse_frame_header_and_trailer() -> None:
    frame = dhav_frame(0xFD, 3, 42, datetime(2026, 1, 15, 10, 0, 1), h264_payload(True, 500, 1), ms=1234)
    hdr = parse_dhav_header(frame, 0, base_offset=1000)
    assert hdr is not None
    assert (hdr.offset, hdr.kind, hdr.channel, hdr.frame_number) == (1000, "video-key", 3, 42)
    assert hdr.frame_length == len(frame) and hdr.timestamp_ms == 1234 and hdr.ext_length == 8
    assert hdr.payload_length == 500
    assert trailer_matches(frame, 0, hdr.frame_length) is True
    assert trailer_matches(frame[:-1], 0, hdr.frame_length) is None
    broken = frame[:-4] + struct.pack("<I", 7)
    assert trailer_matches(broken, 0, hdr.frame_length) is False


def test_aux_frame_has_short_header() -> None:
    body = b"DHAV" + bytes([0xF1, 0, 0, 0]) + struct.pack("<III", 1, 28, dahua_packed(datetime(2026, 1, 1)))
    frame = body + b"dhav" + struct.pack("<I", 28)
    hdr = parse_dhav_header(frame)
    assert hdr is not None and hdr.kind == "aux" and hdr.timestamp_ms is None and hdr.header_length == 20


@pytest.mark.parametrize(
    "mutate",
    [
        lambda f: f[:4] + b"\x10" + f[5:],  # unknown type
        lambda f: f[:12] + struct.pack("<I", 5) + f[16:],  # too short
        lambda f: f[:12] + struct.pack("<I", 0x7FFFFFFF) + f[16:],  # absurd length
        lambda f: f[:10],  # truncated header
        lambda f: b"XHAV" + f[4:],
    ],
)
def test_rejects_implausible_headers(mutate) -> None:  # type: ignore[no-untyped-def]
    frame = dhav_frame(0xFC, 0, 1, datetime(2026, 1, 1), b"x" * 64)
    assert parse_dhav_header(mutate(frame)) is None


def test_iter_headers_skips_garbage() -> None:
    f1 = dhav_frame(0xFD, 0, 1, datetime(2026, 1, 1), b"a" * 100)
    f2 = dhav_frame(0xFC, 1, 2, datetime(2026, 1, 1), b"b" * 100)
    buf = b"DHAV\x00junk" + f1 + b"\xff" * 13 + f2
    found = iter_dhav_headers(buf, base_offset=500)
    assert [(h.channel, ok) for h, ok in found] == [(0, True), (1, True)]
    assert found[0][0].offset == 500 + 9
