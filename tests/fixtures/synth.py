"""Synthetic DVR disk-image generator with ground-truth manifests.

Layouts follow the public sources cited in ``forensidvr/identify/signatures/{hikvision,dahua}.py``
and ``forensidvr/formats/dhav.py``. These images only prove the code matches those documented
assumptions; they are NOT a substitute for real DVR disks. Sizes are scaled down (e.g. 4 MiB
Hikvision data blocks instead of 1 GiB). Everything is deterministic (no clock, fixed seeds).

Usage: ``python -m tests.fixtures.synth OUTDIR``
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from tests.fixtures.images import pattern_bytes

MiB = 1024 * 1024
GENERATOR = "forensidvr-synth"
GENERATOR_VERSION = 1


def dahua_packed(dt: datetime) -> int:
    """Packed Dahua date-time (independent encoder for fixtures; see FFmpeg dhav.c)."""
    return (dt.year - 2000) << 26 | dt.month << 22 | dt.day << 17 | dt.hour << 12 | dt.minute << 6 | dt.second


def h264_payload(key: bool, size: int, seed: int) -> bytes:
    """Fake Annex-B H.264 access unit (SPS/PPS/IDR or non-IDR NAL start codes + filler)."""
    nals = b"\x00\x00\x00\x01\x67\x64\x00\x28" + b"\x00\x00\x00\x01\x68\xee\x3c\x80" if key else b""
    nals += b"\x00\x00\x00\x01" + (b"\x65" if key else b"\x41")
    filler = pattern_bytes(max(0, size - len(nals)) * 4 // 3 + 64, seed)[: max(0, size - len(nals))]
    return (nals + filler.replace(b"\x00\x00\x01", b"\x00\x02\x01"))[:size]


def dhav_frame(ftype: int, channel: int, number: int, dt: datetime, payload: bytes, ms: int = 0) -> bytes:
    """One DHAV frame: 24-byte header, 8 bytes extensions (0x80 size, 0x81 codec), payload, trailer."""
    ext = bytes([0x80, 0, 1920 // 8, 1080 // 8, 0x81, 0, 0x02, 25])
    length = 24 + len(ext) + len(payload) + 8
    hdr = b"DHAV" + bytes([ftype, 0, channel, 0]) + struct.pack("<III", number, length, dahua_packed(dt))
    hdr += struct.pack("<HB", ms & 0xFFFF, len(ext))
    hdr += bytes([sum(hdr) & 0xFF])  # UNVERIFIED checksum algorithm (FFmpeg ignores it)
    return hdr + ext + payload + b"dhav" + struct.pack("<I", length)


@dataclass
class SynthImage:
    path: Path
    manifest: dict[str, Any]


def _finish(path: Path, buf: bytearray, manifest: dict[str, Any], truncate_to: int | None) -> SynthImage:
    data = bytes(buf[:truncate_to] if truncate_to else buf)
    path.write_bytes(data)
    manifest.update(
        generator=GENERATOR,
        generator_version=GENERATOR_VERSION,
        file=path.name,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
    )
    path.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return SynthImage(path, manifest)


def make_hikvision(
    path: Path,
    *,
    size: int = 32 * MiB,
    brand: str = "HIKVISION",
    model: str = "DS-7208HQHI-K1",
    firmware: str = "V4.21.005 build 190813",
    channels: int = 4,
    variant: str = "clean",
) -> SynthImage:
    """Hikvision-style disk. Variants: clean, zero_master, truncated."""
    buf = bytearray(size)
    fs_version = "HIK.2011.03.08"
    sig = 0x210
    log_off, log_size = 0x10000, 0x10000
    video_off, block_size = 1 * MiB, 4 * MiB
    bt1, bt2 = size - 2 * MiB, size - 1 * MiB
    blocks = (bt1 - video_off) // block_size
    buf[sig : sig + 18] = b"HIKVISION@HANGZHOU"
    buf[0x230 : 0x230 + len(fs_version)] = fs_version.encode()  # UNVERIFIED exact placement (+0x30 of sector)
    fields = [
        (0x38, "<Q", size),
        (0x50, "<Q", log_off),
        (0x58, "<Q", log_size),
        (0x68, "<Q", video_off),
        (0x78, "<Q", block_size),
        (0x80, "<I", blocks),
        (0x88, "<Q", bt1),
        (0x90, "<I", 1 * MiB),
        (0x98, "<Q", bt2),
        (0xA0, "<I", 1 * MiB),
        (0xE0, "<I", 1767225600),  # 2026-01-01T00:00:00 as u32
    ]
    for off, fmt, val in fields:
        struct.pack_into(fmt, buf, sig + off, val)
    # RATS system-log records: signature, created time u32, type u16, NUL-terminated description
    log = bytearray()
    entries = [
        (1767225600, 3, "Power On"),
        (1767225605, 4, f"Local HDD Information {brand} {model}"),
        (1767225610, 4, f"Firmware Version: {firmware}"),
        (1767225615, 4, "Serial No: DS7208HQHI0120260101CCRR"),
        (1767225620, 1, "Start Motion detect"),
    ]
    for t, typ, desc in entries:
        log += b"RATS\x14\x00\x00\x00" + struct.pack("<IH", t, typ) + desc.encode() + b"\x00"
    buf[log_off : log_off + len(log)] = log
    for i in range(min(blocks, channels * 2)):
        start = video_off + i * block_size
        chunk = b"\x00\x00\x01\xba" + pattern_bytes(64 * 1024, seed=100 + i)[: 64 * 1024 - 4]
        buf[start : start + len(chunk)] = chunk
    for bt in (bt1, bt2):
        buf[bt + 16 : bt + 24] = b"HIKBTREE"
    truncate_to = None
    if variant == "zero_master":
        buf[0x200:0x400] = bytes(0x200)
    elif variant == "truncated":
        truncate_to = size // 2
    elif variant != "clean":
        raise ValueError(variant)
    manifest = {
        "variant": f"hikvision-{variant}",
        "vendor": "Hikvision" if brand == "HIKVISION" else brand,
        "family": "hikvision",
        "fs_version": fs_version,
        "firmware": firmware,
        "model": model,
        "channels_planted": channels,
        "layout": {
            "master_signature": sig,
            "system_log": [log_off, log_size],
            "video_data_offset": video_off,
            "data_block_size": block_size,
            "hikbtree": [bt1, bt2],
        },
        "expected": {
            "clean": {
                "status": "identified",
                "family": "hikvision",
                "vendor": "Hikvision",
                "channel_count": None,
            },
            "zero_master": {"family": "hikvision"},
            "truncated": {"family": "hikvision", "warning": "HIKBTREE_MISSING"},
        }[variant],
    }
    return _finish(path, buf, manifest, truncate_to)


def make_dahua(
    path: Path,
    *,
    size: int = 32 * MiB,
    brand: str = "DAHUA",
    model: str = "DH-XVR5108HS-X",
    firmware: str = "V4.001.0000000.1.R",
    channels: int = 4,
    variant: str = "clean",
) -> SynthImage:
    """Dahua-style (DHFS4.1) disk with DHAV frames. Variants: clean, zero_magic, truncated, corrupt_frames."""
    buf = bytearray(size)
    buf[0:7] = b"DHFS4.1"
    part_off, sb_rel = 64 * 1024, 4096
    entry = bytearray(64)
    struct.pack_into("<I", entry, 20, sb_rel // 512)
    struct.pack_into("<Q", entry, 48, part_off // 512)
    pt = 0x3C00 + 0x34
    buf[pt : pt + 64] = entry
    buf[pt + 64 : pt + 68] = b"\xaa\x55\xaa\x55"
    t0 = datetime(2026, 1, 15, 10, 0, 0)
    frames_per_channel = 400
    t_end = t0 + timedelta(seconds=frames_per_channel // 25)
    logs_off = 256 * 1024
    data_off = 2 * MiB
    sb = part_off + sb_rel
    for off, val in (
        (0x10, dahua_packed(t0)),
        (0x14, dahua_packed(t_end)),
        (0x2C, 512),
        (0x30, 2048),
        (0x38, 0),
        (0x44, 8),
        (0x48, data_off // 512),
        (0x4C, 16),
        (0xF8, logs_off // 512),
    ):
        struct.pack_into("<I", buf, sb + off, val)
    log = (
        f"2026-01-15 09:59:00 System Start {brand} {model}\n"
        f"2026-01-15 09:59:01 Software Version: {firmware}\n"
        f"2026-01-15 09:59:02 Serial No: 6G0123PAZ0A1B2C\n"
    ).encode()
    buf[logs_off : logs_off + len(log)] = log
    pos = data_off
    frame_offsets = []
    for n in range(frames_per_channel):
        dt = t0 + timedelta(seconds=n // 25)
        for ch in range(channels):
            key = n % 25 == 0
            f = dhav_frame(
                0xFD if key else 0xFC, ch, n, dt, h264_payload(key, 3000, seed=n * 16 + ch), ms=n * 40
            )
            if pos + len(f) > size:
                break
            frame_offsets.append(pos)
            buf[pos : pos + len(f)] = f
            pos += len(f)
    truncate_to = None
    if variant == "zero_magic":
        buf[0:16] = bytes(16)
    elif variant == "truncated":
        truncate_to = data_off + (pos - data_off) // 3
    elif variant == "corrupt_frames":
        for off in frame_offsets[::3]:
            buf[off + 12 : off + 16] = b"\xff\xff\xff\x7f"  # impossible frame length
    elif variant != "clean":
        raise ValueError(variant)
    manifest = {
        "variant": f"dahua-{variant}",
        "vendor": "Dahua" if brand == "DAHUA" else brand,
        "family": "dahua",
        "fs_version": "DHFS4.1",
        "firmware": firmware,
        "model": model,
        "channels_planted": channels,
        "frames_written": len(frame_offsets),
        "layout": {
            "partition_offset": part_off,
            "superblock_offset": sb,
            "logs_offset": logs_off,
            "data_area_offset": data_off,
            "data_end": pos,
        },
        "time_range_local": [t0.isoformat(), t_end.isoformat()],
    }
    return _finish(path, buf, manifest, truncate_to)


def make_noise(path: Path, size: int = 16 * MiB, seed: int = 99) -> SynthImage:
    """Unknown device: pseudo-random data with no vendor structures."""
    return _finish(
        path, bytearray(pattern_bytes(size, seed)), {"variant": "unknown-noise", "family": None}, None
    )


def generate_all(outdir: Path) -> list[SynthImage]:
    outdir.mkdir(parents=True, exist_ok=True)
    out = [
        make_hikvision(outdir / "hikvision-clean.img"),
        make_hikvision(outdir / "hikvision-zero_master.img", variant="zero_master"),
        make_hikvision(outdir / "hikvision-truncated.img", variant="truncated"),
        make_dahua(outdir / "dahua-clean.img"),
        make_dahua(outdir / "dahua-zero_magic.img", variant="zero_magic"),
        make_dahua(outdir / "dahua-truncated.img", variant="truncated"),
        make_dahua(outdir / "dahua-corrupt_frames.img", variant="corrupt_frames"),
        make_dahua(outdir / "cpplus-clean.img", brand="CP PLUS", model="CP-UVR-0801E1-CS", channels=8),
        make_noise(outdir / "unknown-noise.img"),
    ]
    index = [{k: s.manifest[k] for k in ("file", "variant", "sha256", "size")} for s in out]
    (outdir / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    return out


if __name__ == "__main__":
    for s in generate_all(Path(sys.argv[1] if len(sys.argv) > 1 else "synthetic-images")):
        print(f"{s.manifest['sha256']}  {s.path}")
