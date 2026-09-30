"""Dahua-family fingerprint (DHFS superblock magic, partition table, DHAV frames).

Sources:
  * DHFS 4.1 layout: galileu batista, dhfs_extractor (MIT), https://github.com/gbatmobile/dhfs_extractor
    and D. Wullen, X-Ways-DHFS4_1-X-Tension (BSD-3-Clause), https://github.com/dw2102/X-Ways-DHFS4_1-X-Tension
  * DHAV frames: FFmpeg libavformat/dhav.c (see :mod:`forensidvr.formats.dhav`).
Validated only against synthetic images: EXPERIMENTAL.
"""

from __future__ import annotations

import struct
from collections import Counter

from forensidvr.core.models import PluginWarning, SourceRef
from forensidvr.formats.dhav import DHAV_MAGIC, VIDEO_CODECS, decode_dahua_datetime, iter_dhav_headers
from forensidvr.identify.base import Identifier, Signal, SignalKind
from forensidvr.identify.context import ScanContext

FAMILY = "dahua"
DHFS_MAGIC = b"DHFS"
SUPPORTED = b"DHFS4.1"
PART_TABLE_OFFSET = 0x3C00 + 0x34
PART_ENTRY_SIZE = 64
PART_END = b"\xaa\x55\xaa\x55"
MAX_PARTITIONS = 16


def parse_partition_table(buf: bytes) -> list[dict[str, int]]:
    """64-byte entries until AA55AA55: boot-sector offset @20, partition offset @48 (in sectors)."""
    parts = []
    for i in range(MAX_PARTITIONS):
        e = buf[i * PART_ENTRY_SIZE : (i + 1) * PART_ENTRY_SIZE]
        if len(e) < PART_ENTRY_SIZE or e[:4] == PART_END:
            break
        sb = struct.unpack_from("<I", e, 20)[0] * 512
        start = struct.unpack_from("<Q", e, 48)[0] * 512
        parts.append({"index": i, "partition_offset": start, "superblock_offset": sb})
    return parts


def parse_superblock(buf: bytes) -> dict[str, int]:
    names = {
        "begin_time_raw": 0x10,
        "end_time_raw": 0x14,
        "block_size": 0x2C,
        "fragment_blocks": 0x30,
        "reserved_fragments": 0x38,
        "descriptor_table_offset": 0x44,
        "data_area_offset": 0x48,
        "descriptor_count": 0x4C,
        "logs_offset_blocks": 0xF8,
    }
    return {k: struct.unpack_from("<I", buf, o)[0] for k, o in names.items() if o + 4 <= len(buf)}


class DahuaIdentifier(Identifier):
    name = "dahua-dhfs-id"
    version = "0.1.0"
    priority = 10
    experimental = True

    def scan(self, ctx: ScanContext) -> list[Signal]:
        out: list[Signal] = []
        magic = ctx.head[:16]
        if magic.startswith(DHFS_MAGIC):
            out += self._from_superblock(ctx, magic)
        out += self._frames(ctx)
        return out

    def _from_superblock(self, ctx: ScanContext, magic: bytes) -> list[Signal]:
        version = magic[:7].decode("ascii", "replace")
        warn = []
        if not magic.startswith(SUPPORTED):
            warn.append(
                PluginWarning("UNSUPPORTED_DHFS_VERSION", f"{version!r}; only DHFS4.1 is documented", 0)
            )
        out = [
            self.signal(
                kind=SignalKind.FS_SIGNATURE,
                description=f"{version} file-system magic",
                family=FAMILY,
                confidence=0.85 if not warn else 0.7,
                sources=[SourceRef(0, 7)],
                warnings=warn,
                facts={"fs_version": version},
            )
        ]
        parts = parse_partition_table(ctx.read(PART_TABLE_OFFSET, PART_ENTRY_SIZE * MAX_PARTITIONS))
        for p in parts[:4]:
            sb_at = p["partition_offset"] + p["superblock_offset"]
            sb = ctx.read(sb_at, 0x100)
            if len(sb) < 0x100:
                ctx.warnings.append(
                    PluginWarning("DHFS_SUPERBLOCK_UNREADABLE", f"partition {p['index']}", sb_at)
                )
                continue
            fields = parse_superblock(sb)
            begin = decode_dahua_datetime(fields.get("begin_time_raw", 0))
            end = decode_dahua_datetime(fields.get("end_time_raw", 0))
            sane = (
                fields.get("block_size") in (512, 1024, 2048, 4096) and begin is not None and end is not None
            )
            if not sane:
                ctx.warnings.append(
                    PluginWarning("DHFS_SUPERBLOCK_INVALID", f"partition {p['index']}: {fields}", sb_at)
                )
                continue
            out.append(
                self.signal(
                    kind=SignalKind.STRUCTURE,
                    description=f"DHFS partition {p['index']} superblock (block size {fields['block_size']})",
                    family=FAMILY,
                    confidence=0.8,
                    sources=[SourceRef(sb_at, 0x100)],
                    raw_metadata={**p, **fields},
                )
            )
            logs = fields.get("logs_offset_blocks", 0) * fields["block_size"]
            if logs:
                ctx.add_region(logs, ctx.read(logs, 64 * 1024))
        return out

    def _frames(self, ctx: ScanContext) -> list[Signal]:
        good = 0
        channels: set[int] = set()
        codecs: Counter[str] = Counter()
        first: int | None = None
        bad = 0
        for base, data in ctx.regions():
            headers = iter_dhav_headers(data, base)
            bad += data.count(DHAV_MAGIC) - len(headers)  # magic present but header implausible
            for hdr, trailer_ok in headers:
                if trailer_ok is False or decode_dahua_datetime(hdr.date_raw) is None:
                    bad += 1
                    continue
                good += 1
                first = hdr.offset if first is None else min(first, hdr.offset)
                if hdr.kind.startswith("video"):
                    channels.add(hdr.channel)
                    ext = data[hdr.offset - base + 24 : hdr.offset - base + 24 + hdr.ext_length]
                    i = 0
                    while i + 4 <= len(ext):
                        if ext[i] == 0x81:
                            codecs[VIDEO_CODECS.get(ext[i + 2], f"0x{ext[i + 2]:x}")] += 1
                            break
                        i += 4 if ext[i] in (0x80, 0x81, 0x83, 0x84, 0x85) else 8
        if not good:
            return []
        return [
            self.signal(
                kind=SignalKind.STREAM,
                description=f"{good} DHAV frame(s) with valid trailer/date in sampled data",
                family=FAMILY,
                confidence=min(0.9, 0.3 + 0.05 * good),
                sources=[SourceRef(first or 0, 24)],
                raw_metadata={
                    "valid_frames": good,
                    "rejected_candidates": bad,
                    "codecs": dict(sorted(codecs.items())),
                },
                facts={"channels": sorted(channels)},
            )
        ]
