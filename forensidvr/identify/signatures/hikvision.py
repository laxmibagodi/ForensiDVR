"""Hikvision-family fingerprint (HIKVISION@HANGZHOU master sector, HIKBTREE, RATS system log).

Sources (layout of the master sector and HIKBTREE header):
  * J. Han, D. Jeong, S. Lee, "Analysis of the HIKVISION DVR file system", ICDF2C 2015,
    https://www.researchgate.net/publication/285429692_Analysis_of_the_HIKVISION_DVR_file_system
  * D. Wullen, X-Ways-HIKVISION-X-Tension (BSD-3-Clause), https://github.com/dw2102/X-Ways-HIKVISION-X-Tension
  * akira7799/hikvision-dvr-parser (MIT), https://github.com/akira7799/hikvision-dvr-parser
Both implementations agree on the offsets used here (relative to the 18-byte signature, which is at
0x210 of the file system: 0x200 master sector + 0x10). Validated only against synthetic images:
EXPERIMENTAL.
"""

from __future__ import annotations

import re
import struct

from forensidvr.core.models import PluginWarning, SourceRef
from forensidvr.identify.base import Identifier, Signal, SignalKind
from forensidvr.identify.context import ScanContext

FAMILY = "hikvision"
MASTER_SIG = b"HIKVISION@HANGZHOU"
MASTER_SIG_OFFSET = 0x210
HIKBTREE_SIG = b"HIKBTREE"
HIKBTREE_SIG_SKIP = 16  # signature follows a 16-byte prefix at the recorded offset
RATS_SIG = b"RATS\x14\x00\x00\x00"
FS_VERSION_RE = re.compile(rb"HIK\.\d{4}\.\d{2}\.\d{2}")
# offsets relative to MASTER_SIG
FIELDS = {
    "hdd_capacity": (0x38, "<Q"),
    "system_log_offset": (0x50, "<Q"),
    "system_log_size": (0x58, "<Q"),
    "video_data_offset": (0x68, "<Q"),
    "data_block_size": (0x78, "<Q"),
    "data_block_total": (0x80, "<I"),
    "hikbtree1_offset": (0x88, "<Q"),
    "hikbtree1_size": (0x90, "<I"),
    "hikbtree2_offset": (0x98, "<Q"),
    "hikbtree2_size": (0xA0, "<I"),
    "init_time_raw": (0xE0, "<I"),
}


def parse_master(buf: bytes) -> dict[str, int]:
    """Decode master-sector fields from a buffer starting at the signature."""
    out = {}
    for name, (off, fmt) in FIELDS.items():
        if off + struct.calcsize(fmt) <= len(buf):
            out[name] = struct.unpack_from(fmt, buf, off)[0]
    return out


class HikvisionIdentifier(Identifier):
    name = "hikvision-hikbtree-id"
    version = "0.1.0"
    priority = 10
    experimental = True

    def scan(self, ctx: ScanContext) -> list[Signal]:
        out: list[Signal] = []
        for base in [0, *(p.start for p in ctx.partitions)]:
            sig_off = base + MASTER_SIG_OFFSET
            buf = ctx.read(sig_off, 0x100)
            if buf[: len(MASTER_SIG)] == MASTER_SIG:
                out += self._from_master(ctx, base, sig_off, buf)
                return out
        # master sector missing/damaged: look for secondary structures in the sampled regions only
        for off in ctx.find_all(HIKBTREE_SIG, limit=4):
            out.append(
                self.signal(
                    kind=SignalKind.STRUCTURE,
                    description="HIKBTREE signature in sampled data (no master sector)",
                    family=FAMILY,
                    confidence=0.6,
                    sources=[SourceRef(off, 8)],
                )
            )
        for off in ctx.find_all(RATS_SIG, limit=2):
            out.append(
                self.signal(
                    kind=SignalKind.STRUCTURE,
                    description="RATS system-log record in sampled data",
                    family=FAMILY,
                    confidence=0.3,
                    sources=[SourceRef(off, 8)],
                )
            )
        m = FS_VERSION_RE.search(ctx.head)
        if m:
            out.append(
                self.signal(
                    kind=SignalKind.STRING,
                    description="HIK file-system version string",
                    family=FAMILY,
                    confidence=0.5,
                    sources=[SourceRef(m.start(), len(m.group()))],
                    facts={"fs_version": m.group().decode()},
                )
            )
        return out

    def _from_master(self, ctx: ScanContext, base: int, sig_off: int, buf: bytes) -> list[Signal]:
        fields = parse_master(buf)
        warnings: list[PluginWarning] = []
        cap = fields.get("hdd_capacity", 0)
        if cap and cap > ctx.size - base:
            warnings.append(
                PluginWarning(
                    "SIZE_MISMATCH",
                    f"master-sector capacity {cap} > available image size {ctx.size - base} (truncated?)",
                    sig_off + 0x38,
                )
            )
        facts: dict[str, object] = {}
        sector = ctx.read(base + 0x200, 0x200)
        m = FS_VERSION_RE.search(sector)
        if m:
            facts["fs_version"] = m.group().decode()
        out = [
            self.signal(
                kind=SignalKind.FS_SIGNATURE,
                description="HIKVISION@HANGZHOU master-sector signature",
                family=FAMILY,
                confidence=0.85,
                sources=[SourceRef(sig_off, len(MASTER_SIG))],
                raw_metadata={"fs_base": base, **fields},
                warnings=warnings,
                facts=facts,
            )
        ]
        for idx, weight in (("1", 0.9), ("2", 0.5)):
            rel = fields.get(f"hikbtree{idx}_offset", 0)
            if not rel:
                continue
            at = base + rel + HIKBTREE_SIG_SKIP
            got = ctx.read(at, 8)
            if got == HIKBTREE_SIG:
                out.append(
                    self.signal(
                        kind=SignalKind.STRUCTURE,
                        description=f"HIKBTREE{idx} signature at master-sector offset",
                        family=FAMILY,
                        confidence=weight,
                        sources=[SourceRef(at, 8)],
                    )
                )
            else:
                ctx.warnings.append(
                    PluginWarning(
                        "HIKBTREE_MISSING",
                        f"HIKBTREE{idx} expected at 0x{at:x} but "
                        + ("beyond end of image" if at >= ctx.size else "signature not found"),
                        at,
                    )
                )
        log_off, log_size = fields.get("system_log_offset", 0), fields.get("system_log_size", 0)
        if log_off:
            data = ctx.read(base + log_off, min(log_size or 65536, 256 * 1024))
            ctx.add_region(base + log_off, data)
            if data.startswith(RATS_SIG):
                out.append(
                    self.signal(
                        kind=SignalKind.STRUCTURE,
                        description="RATS system-log area at master-sector offset",
                        family=FAMILY,
                        confidence=0.6,
                        sources=[SourceRef(base + log_off, 8)],
                    )
                )
        return out
