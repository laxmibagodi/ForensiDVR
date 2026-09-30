"""Dahua DHAV frame structures (header/trailer and packed date-time).

Source: FFmpeg ``libavformat/dhav.c`` (DHAV demuxer, LGPL-2.1, Paul B Mahol 2018),
https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/dhav.c. This module is an independent
re-implementation of the documented byte layout, not a copy of FFmpeg code:

```
off  size  field
0    4     "DHAV"
4    1     type      0xFD video key frame, 0xFC video, 0xF0 audio, 0xF1 auxiliary
5    1     subtype
6    1     channel   (raw id; whether 0- or 1-based is UNVERIFIED)
7    1     frame sub-number
8    4 LE  frame number
12   4 LE  frame length (header + extensions + payload + 8-byte trailer)
16   4 LE  date      packed local date-time, see :func:`decode_dahua_datetime`
20   2 LE  timestamp (ms, wraps)            -- absent for type 0xF1
22   1     extension length                 -- absent for type 0xF1
23   1     checksum (not validated by FFmpeg; UNVERIFIED algorithm)
...        extensions, payload
-8   4     "dhav"
-4   4 LE  frame length (same as offset 12)
```

The same packed date-time layout is used by DHFS 4.1 descriptors (galileu batista,
``dhfs_extractor``, MIT: https://github.com/gbatmobile/dhfs_extractor).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime

from forensidvr.core.models import TimeConfidence, TimestampValue

DHAV_MAGIC = b"DHAV"
DHAV_TRAILER = b"dhav"
HEADER_SIZE = 24
AUX_HEADER_SIZE = 20
TRAILER_SIZE = 8
MAX_FRAME_LENGTH = 16 * 1024 * 1024
FRAME_TYPES: dict[int, str] = {0xFD: "video-key", 0xFC: "video", 0xF0: "audio", 0xF1: "aux"}
VIDEO_CODECS: dict[int, str] = {
    0x1: "mpeg4",
    0x2: "h264",
    0x3: "mjpeg",
    0x4: "h264",
    0x8: "h264",
    0xC: "hevc",
}
DATE_ENCODING = "dahua-packed-u32 (FFmpeg dhav.c get_timeinfo)"


@dataclass(frozen=True)
class DhavHeader:
    """Decoded DHAV frame header. ``offset`` is absolute within the source."""

    offset: int
    frame_type: int
    subtype: int
    channel: int
    frame_subnumber: int
    frame_number: int
    frame_length: int
    date_raw: int
    timestamp_ms: int | None
    ext_length: int
    checksum: int | None

    @property
    def kind(self) -> str:
        return FRAME_TYPES.get(self.frame_type, "unknown")

    @property
    def header_length(self) -> int:
        return AUX_HEADER_SIZE if self.frame_type == 0xF1 else HEADER_SIZE + self.ext_length

    @property
    def payload_length(self) -> int:
        return self.frame_length - self.header_length - TRAILER_SIZE


def decode_dahua_datetime(raw: int) -> datetime | None:
    """Unpack sec:6 min:6 hour:5 day:5 month:4 year:6 (+2000). Returns naive local time or None."""
    sec = raw & 0x3F
    minute = (raw >> 6) & 0x3F
    hour = (raw >> 12) & 0x1F
    day = (raw >> 17) & 0x1F
    month = (raw >> 22) & 0x0F
    year = ((raw >> 26) & 0x3F) + 2000
    try:
        return datetime(year, month, day, hour, minute, sec)
    except ValueError:
        return None


def encode_dahua_datetime(dt: datetime) -> int:
    """Inverse of :func:`decode_dahua_datetime` (years 2000-2063)."""
    if not 2000 <= dt.year <= 2063:
        raise ValueError("year outside packed range 2000-2063")
    return (
        ((dt.year - 2000) << 26)
        | (dt.month << 22)
        | (dt.day << 17)
        | (dt.hour << 12)
        | (dt.minute << 6)
        | dt.second
    )


def dahua_timestamp(raw: int) -> TimestampValue:
    """Raw packed value as a :class:`TimestampValue`; device-local, zone unknown (no UTC yet)."""
    local = decode_dahua_datetime(raw)
    notes: tuple[str, ...] = (
        ("invalid packed date-time",)
        if local is None
        else ("device local time; timezone not yet determined", f"local={local.isoformat()}")
    )
    return TimestampValue(raw=raw, raw_encoding=DATE_ENCODING, confidence=TimeConfidence.UNKNOWN, notes=notes)


def parse_dhav_header(buf: bytes, pos: int = 0, base_offset: int = 0) -> DhavHeader | None:
    """Decode a header at ``buf[pos:]``; ``None`` if it is not a plausible DHAV frame header."""
    if buf[pos : pos + 4] != DHAV_MAGIC or len(buf) - pos < AUX_HEADER_SIZE:
        return None
    ftype, subtype, channel, sub = buf[pos + 4 : pos + 8]
    if ftype not in FRAME_TYPES:
        return None
    number, length, date = struct.unpack_from("<III", buf, pos + 8)
    if ftype == 0xF1:
        ts = ext = None
        checksum = None
        ext_len = 0
        min_len = AUX_HEADER_SIZE + TRAILER_SIZE
    else:
        if len(buf) - pos < HEADER_SIZE:
            return None
        ts, ext, checksum = struct.unpack_from("<HBB", buf, pos + 20)
        ext_len = ext
        min_len = HEADER_SIZE + ext_len + TRAILER_SIZE
    if not min_len <= length <= MAX_FRAME_LENGTH:
        return None
    return DhavHeader(
        offset=base_offset + pos,
        frame_type=ftype,
        subtype=subtype,
        channel=channel,
        frame_subnumber=sub,
        frame_number=number,
        frame_length=length,
        date_raw=date,
        timestamp_ms=ts,
        ext_length=ext_len,
        checksum=checksum,
    )


def trailer_matches(buf: bytes, header_pos: int, frame_length: int) -> bool | None:
    """True/False if the trailer lies inside ``buf``; ``None`` if it is beyond the buffer."""
    t = header_pos + frame_length - TRAILER_SIZE
    if t < 0 or t + TRAILER_SIZE > len(buf):
        return None
    return buf[t : t + 4] == DHAV_TRAILER and struct.unpack_from("<I", buf, t + 4)[0] == frame_length


def iter_dhav_headers(
    buf: bytes, base_offset: int = 0, limit: int = 10_000
) -> list[tuple[DhavHeader, bool | None]]:
    """Scan ``buf`` for DHAV headers; returns ``(header, trailer_ok)`` pairs in offset order."""
    out: list[tuple[DhavHeader, bool | None]] = []
    pos = buf.find(DHAV_MAGIC)
    while pos != -1 and len(out) < limit:
        hdr = parse_dhav_header(buf, pos, base_offset)
        if hdr is not None:
            out.append((hdr, trailer_matches(buf, pos, hdr.frame_length)))
        pos = buf.find(DHAV_MAGIC, pos + 1)
    return out
