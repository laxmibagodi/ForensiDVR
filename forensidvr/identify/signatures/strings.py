"""Vendor / model / firmware / serial strings, driven by ``oem_signatures.json`` (data, not code)."""

from __future__ import annotations

import re

from forensidvr.core.models import SourceRef
from forensidvr.identify.base import Identifier, Signal, SignalKind
from forensidvr.identify.context import ScanContext
from forensidvr.identify.oem import load_table

MAX_SIGNALS_PER_VENDOR = 3
FIRMWARE_RE = re.compile(
    r"(?i)\b(?:firmware|software|fw)[ _-]?(?:version|ver)?\s*[:=]\s*"
    r"([A-Za-z]?\d+(?:\.\d+){1,5}[A-Za-z0-9._ -]{0,24})"
)
SERIAL_RE = re.compile(r"(?i)\bserial[ _-]?(?:no|number|num)?\.?\s*[:=]\s*([A-Z0-9]{8,48})\b")


class VendorStringIdentifier(Identifier):
    name = "vendor-strings"
    version = "0.1.0"
    priority = 90

    def scan(self, ctx: ScanContext) -> list[Signal]:
        table = load_table()
        out: list[Signal] = []
        counts: dict[str, int] = {}
        for off, text in ctx.strings():
            for v in table.vendors:
                if any(p.search(text) for p in v.patterns):
                    counts[v.vendor] = counts.get(v.vendor, 0) + 1
                    if counts[v.vendor] <= MAX_SIGNALS_PER_VENDOR:
                        out.append(
                            self.signal(
                                kind=SignalKind.STRING,
                                description=f"brand string for {v.vendor}",
                                vendor=v.vendor,
                                confidence=v.weight,
                                sources=[SourceRef(off, len(text))],
                                raw_metadata={"text": text, "unverified_mapping": v.unverified},
                            )
                        )
                for model_re in v.models:
                    m = model_re.search(text)
                    if m:
                        out.append(
                            self.signal(
                                kind=SignalKind.STRING,
                                description=f"model string ({v.vendor} naming, unverified pattern)",
                                vendor=v.vendor,
                                confidence=0.3,
                                sources=[SourceRef(off + m.start(), len(m.group()))],
                                facts={"model": m.group()},
                            )
                        )
            for regex, key in ((FIRMWARE_RE, "firmware"), (SERIAL_RE, "serial")):
                m = regex.search(text)
                if m:
                    out.append(
                        self.signal(
                            kind=SignalKind.STRING,
                            description=f"{key} string",
                            confidence=0.0,
                            sources=[SourceRef(off + m.start(1), len(m.group(1)))],
                            raw_metadata={"text": text},
                            facts={key: m.group(1).strip()},
                        )
                    )
        return out
