"""Bounded, deterministic view of an image for identification plugins."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from forensidvr.core.errors import ForensiDVRError
from forensidvr.core.io import ByteSource
from forensidvr.core.models import PluginWarning

HEAD_SIZE = 1024 * 1024
SAMPLE_COUNT = 64
SAMPLE_SIZE = 64 * 1024
READ_BUDGET = 64 * 1024 * 1024
MAX_STRINGS = 50_000
_STRING_RE = re.compile(rb"[\x20-\x7e]{6,256}")


@dataclass(frozen=True)
class Partition:
    scheme: str  # "mbr" | "gpt"
    index: int
    start: int  # bytes
    length: int  # bytes
    type_id: str


@dataclass
class ScanContext:
    """Wraps a :class:`ByteSource` with cached head/sample reads, a read budget and string extraction.

    Sampling is deterministic: ``SAMPLE_COUNT`` evenly spaced sector-aligned windows plus the tail.
    """

    image: ByteSource
    head_size: int = HEAD_SIZE
    sample_count: int = SAMPLE_COUNT
    sample_size: int = SAMPLE_SIZE
    budget: int = READ_BUDGET
    bytes_read: int = 0
    warnings: list[PluginWarning] = field(default_factory=list)
    partitions: list[Partition] = field(default_factory=list)
    extra_regions: list[tuple[int, bytes]] = field(default_factory=list)
    shared: dict[str, Any] = field(default_factory=dict)
    _budget_warned: bool = False

    @property
    def size(self) -> int:
        return self.image.size

    def read(self, offset: int, length: int) -> bytes:
        """Budgeted read; ``b""`` (never raises) outside the image, on I/O error or over budget."""
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        if self.bytes_read + length > self.budget:
            if not self._budget_warned:
                self._budget_warned = True
                self.warnings.append(
                    PluginWarning("SCAN_BUDGET", f"identification read budget of {self.budget} bytes reached")
                )
            return b""
        try:
            data = self.image.read_at(offset, length)
        except (OSError, ForensiDVRError) as exc:
            self.warnings.append(PluginWarning("READ_ERROR", f"{type(exc).__name__}: {exc}", offset))
            return b""
        self.bytes_read += len(data)
        return data

    @cached_property
    def head(self) -> bytes:
        return self.read(0, self.head_size)

    @cached_property
    def samples(self) -> list[tuple[int, bytes]]:
        if self.size <= self.head_size:
            return []
        offsets = {(i * self.size // self.sample_count) // 512 * 512 for i in range(1, self.sample_count)}
        offsets.add(max(0, self.size - self.sample_size) // 512 * 512)
        out = []
        for off in sorted(o for o in offsets if o >= self.head_size):
            data = self.read(off, self.sample_size)
            if data:
                out.append((off, data))
        return out

    def add_region(self, offset: int, data: bytes) -> None:
        """Register an already-read region (e.g. a log area) for string extraction and searches."""
        if data:
            self.extra_regions.append((offset, data))

    def regions(self) -> list[tuple[int, bytes]]:
        regs = [(0, self.head), *self.samples, *self.extra_regions]
        return sorted((r for r in regs if r[1]), key=lambda r: r[0])

    def find_all(self, needle: bytes, limit: int = 1000) -> list[int]:
        """Absolute offsets of ``needle`` in the scanned regions (deduplicated, sorted)."""
        hits: set[int] = set()
        for base, data in self.regions():
            pos = data.find(needle)
            while pos != -1 and len(hits) < limit:
                hits.add(base + pos)
                pos = data.find(needle, pos + 1)
        return sorted(hits)

    def strings(self) -> list[tuple[int, str]]:
        """Printable ASCII strings (>= 6 chars) from the scanned regions, sorted by offset."""
        seen: dict[int, str] = {}
        for base, data in self.regions():
            for m in _STRING_RE.finditer(data):
                seen.setdefault(base + m.start(), m.group().decode("ascii"))
                if len(seen) >= MAX_STRINGS:
                    break
        return sorted(seen.items())
