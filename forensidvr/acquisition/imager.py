"""Bit-for-bit physical imaging to raw/dd with hash-on-the-fly and bad-sector handling.

Behaviour (mirrors ``dd conv=noerror,sync`` / ``ewfacquire`` conventions):

* The source is opened ``O_RDONLY``; the destination is created with ``O_EXCL`` (never
  overwrites) and made read-only (0444) when complete.
* Blocks are read with ``pread``. On a read error the block is retried ``retries`` times, then
  re-read sector by sector; sectors that still fail are written as zeros and recorded.
* MD5 + SHA-256 are computed over the bytes written (including zero-filled sectors).
* A verification pass re-reads the destination and must reproduce the acquisition hashes.
* Every event goes to a JSONL acquisition log; a JSON + Markdown report is produced.
"""

from __future__ import annotations

import errno
import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensidvr import TOOL_NAME, __version__
from forensidvr.acquisition.readers import ImageReader, RawImageReader, SplitRawReader
from forensidvr.core.errors import AcquisitionError
from forensidvr.core.hashing import HashSet, MultiHasher, hash_source
from forensidvr.core.io import ByteSource
from forensidvr.core.jsonutil import canonical_json, pretty_json
from forensidvr.core.timeutil import Clock, isoformat_utc, utcnow

ProgressCallback = Callable[[int, int], None]


@dataclass(frozen=True)
class BadSectorRange:
    offset: int
    length: int
    error: str


@dataclass
class AcquisitionResult:
    """Everything needed to write the acquisition report."""

    acquisition_id: str
    source: str
    destination: list[str]
    format: str
    source_size: int
    bytes_acquired: int
    block_size: int
    sector_size: int
    retries: int
    acquisition_hashes: HashSet
    verification_hashes: HashSet | None
    verified: bool
    bad_sectors: list[BadSectorRange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    started_utc: str = ""
    finished_utc: str = ""
    duration_seconds: float = 0.0
    tool: str = f"{TOOL_NAME} {__version__}"
    log_path: str | None = None
    report_json: str | None = None
    report_md: str | None = None

    @property
    def throughput_mb_s(self) -> float:
        return (self.bytes_acquired / 1e6) / self.duration_seconds if self.duration_seconds else 0.0

    def evidence_summary(self) -> dict[str, Any]:
        """Deterministic subset (no timings/paths) — identical for identical sources."""
        return {
            "source_size": self.source_size,
            "bytes_acquired": self.bytes_acquired,
            "acquisition_hashes": self.acquisition_hashes.to_dict(),
            "verified": self.verified,
            "bad_sectors": [b.__dict__ for b in self.bad_sectors],
            "sector_size": self.sector_size,
        }


class _Log:
    def __init__(self, path: Path | None, clock: Clock) -> None:
        self.path = path
        self._clock = clock
        self._fh = open(path, "xb") if path else None  # noqa: SIM115 - closed in close()

    def event(self, event: str, **details: Any) -> None:
        if self._fh:
            rec = {"t": isoformat_utc(self._clock()), "event": event, **details}
            self._fh.write(canonical_json(rec) + b"\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            os.fsync(self._fh.fileno())
            self._fh.close()


class _SplitWriter:
    """Writes sequential output to one file or to numbered segments of ``split_size`` bytes."""

    def __init__(self, dest: Path, split_size: int | None) -> None:
        self.dest = dest
        self.split_size = split_size
        self.paths: list[Path] = []
        self._fd: int | None = None
        self._in_segment = 0

    def _open_next(self) -> None:
        if self._fd is not None:
            os.fsync(self._fd)
            os.close(self._fd)
        path = (
            self.dest
            if not self.split_size
            else self.dest.with_name(f"{self.dest.name}.{len(self.paths) + 1:03d}")
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        try:
            self._fd = os.open(path, flags, 0o640)
        except FileExistsError as exc:
            raise AcquisitionError(f"refusing to overwrite existing file {path}") from exc
        self.paths.append(path)
        self._in_segment = 0

    def write(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            if self._fd is None or (self.split_size and self._in_segment >= self.split_size):
                self._open_next()
            assert self._fd is not None
            room = len(view) if not self.split_size else self.split_size - self._in_segment
            n = os.write(self._fd, view[:room])
            self._in_segment += n
            view = view[n:]

    def close(self) -> None:
        if self._fd is None:
            self._open_next()  # zero-length source still yields a (empty) image file
        assert self._fd is not None
        os.fsync(self._fd)
        os.close(self._fd)
        self._fd = None
        for p in self.paths:
            os.chmod(p, 0o444)


def _open_source(source: str | os.PathLike[str] | ByteSource) -> tuple[ByteSource, str, bool]:
    if isinstance(source, str | os.PathLike):
        return RawImageReader(source), str(Path(source).resolve()), True
    return source, getattr(source, "name", repr(source)), False


def acquire_raw(
    source: str | os.PathLike[str] | ByteSource,
    dest: str | os.PathLike[str],
    *,
    block_size: int = 1024 * 1024,
    sector_size: int = 512,
    retries: int = 2,
    split_size: int | None = None,
    log_path: str | os.PathLike[str] | None = None,
    report_dir: str | os.PathLike[str] | None = None,
    verify: bool = True,
    clock: Clock = utcnow,
    progress: ProgressCallback | None = None,
) -> AcquisitionResult:
    """Image ``source`` (device/file path or :class:`ByteSource`) to ``dest``.

    ``split_size`` writes ``dest.001``, ``dest.002``... instead of a single file.
    """
    if block_size <= 0 or block_size % sector_size:
        raise AcquisitionError("block_size must be a positive multiple of sector_size")
    if split_size is not None and (split_size <= 0 or split_size % sector_size):
        raise AcquisitionError("split_size must be a positive multiple of sector_size")
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    src, src_name, owned = _open_source(source)
    acq_id = str(uuid.uuid4())
    log = _Log(Path(log_path) if log_path else None, clock)
    started = clock()
    t0 = time.monotonic()
    hasher = MultiHasher()
    bad: list[BadSectorRange] = []
    warnings: list[str] = []
    writer = _SplitWriter(dest_path, split_size)
    total = src.size
    log.event(
        "start",
        acquisition_id=acq_id,
        source=src_name,
        destination=str(dest_path),
        source_size=total,
        block_size=block_size,
        sector_size=sector_size,
        retries=retries,
        split_size=split_size,
        tool=f"{TOOL_NAME} {__version__}",
    )

    def read_sector_by_sector(offset: int, length: int) -> bytes:
        out = bytearray()
        for s in range(offset, offset + length, sector_size):
            n = min(sector_size, offset + length - s)
            try:
                data = src.read_at(s, n)
                if len(data) != n:
                    raise OSError(errno.EIO, f"short read ({len(data)} of {n})")
                out += data
            except OSError as exc:
                out += b"\x00" * n
                if bad and bad[-1].offset + bad[-1].length == s and bad[-1].error == str(exc):
                    bad[-1] = BadSectorRange(bad[-1].offset, bad[-1].length + n, bad[-1].error)
                else:
                    bad.append(BadSectorRange(s, n, str(exc)))
                log.event("bad_sector", offset=s, length=n, error=str(exc))
        return bytes(out)

    try:
        offset = 0
        while offset < total:
            n = min(block_size, total - offset)
            data: bytes | None = None
            last_err: OSError | None = None
            for attempt in range(retries + 1):
                try:
                    data = src.read_at(offset, n)
                    if len(data) != n:
                        raise OSError(errno.EIO, f"short read ({len(data)} of {n})")
                    break
                except OSError as exc:
                    data, last_err = None, exc
                    log.event("read_error", offset=offset, length=n, attempt=attempt + 1, error=str(exc))
            if data is None:
                warnings.append(
                    f"read error in block at {offset}: {last_err}; fell back to sector-level reads"
                )
                data = read_sector_by_sector(offset, n)
            writer.write(data)
            hasher.update(data)
            offset += n
            if progress:
                progress(offset, total)
    finally:
        writer.close()
        if owned and isinstance(src, ImageReader):
            src.close()

    acq_hash = hasher.result()
    log.event(
        "acquired",
        bytes=acq_hash.size,
        md5=acq_hash.md5,
        sha256=acq_hash.sha256,
        bad_sector_ranges=len(bad),
    )

    ver_hash: HashSet | None = None
    verified = False
    if verify:
        reader: ImageReader = (
            SplitRawReader(writer.paths[0]) if split_size else RawImageReader(writer.paths[0])
        )
        with reader:
            ver_hash = hash_source(reader)
        verified = ver_hash.matches(acq_hash)
        log.event("verified", ok=verified, md5=ver_hash.md5, sha256=ver_hash.sha256)
        if not verified:
            warnings.append("verification hash does not match acquisition hash")

    finished = clock()
    result = AcquisitionResult(
        acquisition_id=acq_id,
        source=src_name,
        destination=[str(p) for p in writer.paths],
        format="split-raw" if split_size else "raw",
        source_size=total,
        bytes_acquired=acq_hash.size,
        block_size=block_size,
        sector_size=sector_size,
        retries=retries,
        acquisition_hashes=acq_hash,
        verification_hashes=ver_hash,
        verified=verified,
        bad_sectors=bad,
        warnings=warnings,
        started_utc=isoformat_utc(started),
        finished_utc=isoformat_utc(finished),
        duration_seconds=round(time.monotonic() - t0, 6),
        log_path=str(log.path) if log.path else None,
    )
    log.event("finish", verified=verified)
    log.close()
    if report_dir is not None:
        write_acquisition_report(result, Path(report_dir))
    return result


def write_acquisition_report(result: AcquisitionResult, report_dir: Path) -> tuple[Path, Path]:
    """Write ``acquisition-<id>.json`` and ``.md``; fills ``report_json``/``report_md``."""
    report_dir.mkdir(parents=True, exist_ok=True)
    base = report_dir / f"acquisition-{result.acquisition_id}"
    json_path, md_path = base.with_suffix(".json"), base.with_suffix(".md")
    result.report_json, result.report_md = str(json_path), str(md_path)
    payload = {k: v for k, v in result.__dict__.items() if k not in ("report_json", "report_md")}
    payload["throughput_mb_s"] = round(result.throughput_mb_s, 3)
    json_path.write_text(pretty_json(payload), encoding="utf-8")
    md_path.write_text(render_acquisition_markdown(result), encoding="utf-8")
    return json_path, md_path


def render_acquisition_markdown(r: AcquisitionResult) -> str:
    """Human-readable acquisition report."""
    a, v = r.acquisition_hashes, r.verification_hashes
    lines = [
        "# Acquisition Report",
        "",
        f"- **Acquisition ID:** {r.acquisition_id}",
        f"- **Tool:** {r.tool}",
        f"- **Source:** `{r.source}` ({r.source_size} bytes)",
        f"- **Destination:** {', '.join(f'`{d}`' for d in r.destination)} ({r.format})",
        f"- **Started (UTC):** {r.started_utc}",
        f"- **Finished (UTC):** {r.finished_utc}",
        f"- **Duration:** {r.duration_seconds:.3f} s ({r.throughput_mb_s:.2f} MB/s)",
        f"- **Block / sector size:** {r.block_size} / {r.sector_size} bytes; retries: {r.retries}",
        "",
        "## Hashes",
        "",
        "| Pass | Bytes | MD5 | SHA-256 |",
        "|---|---|---|---|",
        f"| Acquisition | {a.size} | `{a.md5}` | `{a.sha256}` |",
    ]
    if v:
        lines.append(f"| Verification | {v.size} | `{v.md5}` | `{v.sha256}` |")
    lines += [
        "",
        f"**Verification result:** {'PASS' if r.verified else 'FAIL / NOT PERFORMED'}",
        "",
        "## Read errors",
        "",
    ]
    if r.bad_sectors:
        lines += ["| Offset | Length | Error |", "|---|---|---|"]
        lines += [f"| {b.offset} | {b.length} | {b.error} |" for b in r.bad_sectors]
        lines += ["", "Unreadable sectors were written as zeros and are included in the hashes."]
    else:
        lines.append("None.")
    if r.warnings:
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in r.warnings]
    return "\n".join(lines) + "\n"
