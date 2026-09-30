"""MBR / GPT partition-table reader (informational signals; also feeds other identifiers)."""

from __future__ import annotations

import struct

from forensidvr.core.models import SourceRef
from forensidvr.identify.base import Identifier, Signal, SignalKind
from forensidvr.identify.context import Partition, ScanContext


class PartitionTableIdentifier(Identifier):
    name = "partition-table"
    version = "0.1.0"
    priority = 5

    def scan(self, ctx: ScanContext) -> list[Signal]:
        head = ctx.head
        out: list[Signal] = []
        if len(head) >= 1024 and head[512:520] == b"EFI PART":
            out.append(
                self.signal(
                    kind=SignalKind.PARTITION,
                    description="GPT header",
                    confidence=0.0,
                    sources=[SourceRef(512, 92)],
                    raw_metadata={"scheme": "gpt"},
                )
            )
            return out
        if len(head) < 512 or head[510:512] != b"\x55\xaa":
            return out
        for i in range(4):
            e = head[446 + 16 * i : 462 + 16 * i]
            status, ptype = e[0], e[4]
            lba, count = struct.unpack_from("<II", e, 8)
            if ptype == 0 or count == 0 or status not in (0x00, 0x80):
                continue
            start, length = lba * 512, count * 512
            if start >= ctx.size:
                continue
            ctx.partitions.append(Partition("mbr", i, start, length, f"0x{ptype:02x}"))
            out.append(
                self.signal(
                    kind=SignalKind.PARTITION,
                    description=f"MBR partition {i} type 0x{ptype:02x}",
                    confidence=0.0,
                    sources=[SourceRef(446 + 16 * i, 16)],
                    raw_metadata={
                        "scheme": "mbr",
                        "index": i,
                        "type": f"0x{ptype:02x}",
                        "start": start,
                        "length": length,
                    },
                )
            )
        return out
