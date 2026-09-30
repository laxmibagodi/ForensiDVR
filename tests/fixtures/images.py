"""Deterministic synthetic image helpers for tests (no real evidence required)."""

from __future__ import annotations

import errno
import hashlib
import shutil
import subprocess
from pathlib import Path

from forensidvr.core.io import BytesSource


def pattern_bytes(size: int, seed: int = 0) -> bytes:
    """Deterministic pseudo-random bytes (SHA-256 counter mode), with a compressible tail."""
    out = bytearray()
    counter = 0
    random_part = size * 3 // 4
    while len(out) < random_part:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    del out[random_part:]
    out += bytes(size - len(out))  # zero tail exercises EWF compressed chunks
    return bytes(out)


def write_pattern_image(path: Path, size: int, seed: int = 0) -> Path:
    path.write_bytes(pattern_bytes(size, seed))
    return path


class FaultySource(BytesSource):
    """In-memory source that raises EIO for reads touching the given byte ranges."""

    name = "faulty-test-source"

    def __init__(self, data: bytes, bad_ranges: list[tuple[int, int]], transient: int = 0) -> None:
        super().__init__(data)
        self.bad_ranges = bad_ranges
        self.transient = transient  # number of failures before a region starts reading fine
        self.failures = 0

    def read_at(self, offset: int, length: int) -> bytes:
        for start, ln in self.bad_ranges:
            if offset < start + ln and start < offset + length:
                if self.transient and self.failures >= self.transient:
                    break
                self.failures += 1
                raise OSError(errno.EIO, "Input/output error")
        return super().read_at(offset, length)


def ewfacquire_available() -> bool:
    return shutil.which("ewfacquire") is not None


def make_e01(
    source: Path,
    target_stem: Path,
    *,
    compression: str = "best",
    segment_size: int | None = None,
    fmt: str = "encase6",
) -> Path:
    """Create an E01 with libewf's ``ewfacquire`` (independent reference implementation)."""
    cmd = [
        "ewfacquire",
        "-u",
        "-q",
        "-t",
        str(target_stem),
        "-c",
        compression,
        "-f",
        fmt,
        "-C",
        "CASE-42",
        "-e",
        "Test Examiner",
        "-E",
        "EV-1",
        "-D",
        "synthetic",
        "-N",
        "notes",
        "-d",
        "sha1",
    ]
    if segment_size:
        cmd += ["-S", str(segment_size)]
    cmd.append(str(source))
    subprocess.run(cmd, check=True, capture_output=True, timeout=120)
    return target_stem.with_suffix(".E01")
