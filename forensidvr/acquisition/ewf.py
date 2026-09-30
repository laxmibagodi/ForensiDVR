"""Pure-Python reader for EWF version 1 (``.E01``) images.

Source: Joachim Metz, "Expert Witness Compression Format (EWF)" specification, libewf project
(https://github.com/libyal/libewf/blob/main/documentation/). Validated against images produced by
``ewfacquire`` (libewf 20140807) in the test-suite. Implemented natively to avoid an LGPL
runtime dependency.

Supported: EWF-E01 segment files (``EVF\\x09\\x0d\\x0a\\xff\\x00``), multi-segment sets
(``.E01``...``.E99``, ``.EAA``...), ``volume``/``disk``, ``table``/``table2``, ``sectors``,
``header``/``header2``, ``hash`` and ``digest`` sections, deflate-compressed and stored chunks.
Not supported: EWF2 (``.Ex01``), ``.L01`` logical evidence, bzip2 chunks, delta (``.D01``) files.

Corrupt chunks never crash the reader: an unreadable chunk is returned as zeros and recorded in
:attr:`EWFImage.chunk_errors`.
"""

from __future__ import annotations

import string
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forensidvr.core.errors import ImageFormatError
from forensidvr.core.readonly import ReadOnlyFile

EWF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
FILE_HEADER_SIZE = 13
SECTION_DESCRIPTOR_SIZE = 76
TABLE_HEADER_SIZE = 24
COMPRESSED_FLAG = 0x80000000
OFFSET_MASK = 0x7FFFFFFF
MAX_SECTIONS_PER_SEGMENT = 1_000_000


@dataclass(frozen=True)
class Section:
    """One section descriptor inside a segment file."""

    segment: int
    offset: int
    type: str
    next_offset: int
    size: int


@dataclass(frozen=True)
class ChunkLocation:
    segment: int
    offset: int
    stored_size: int | None  # None: unknown end (compressed chunk at end of table)
    compressed: bool


@dataclass
class EWFImage:
    """An opened EWF-E01 segment set."""

    first_segment: Path
    segment_paths: list[Path] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    chunk_count: int = 0
    sectors_per_chunk: int = 0
    bytes_per_sector: int = 0
    sector_count: int = 0
    stored_md5: str | None = None
    stored_sha1: str | None = None
    header_values: dict[str, str] = field(default_factory=dict)
    chunk_errors: dict[int, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._files: list[ReadOnlyFile] = []
        self._chunks: list[ChunkLocation] = []
        self._cache_index = -1
        self._cache_data = b""
        try:
            self._open()
        except Exception:
            self.close()
            raise

    # -- opening -----------------------------------------------------------------------------
    @staticmethod
    def segment_name(first: Path, number: int) -> Path:
        """Segment ``number`` (1-based) path: E01..E99, then EAA..EZZ, FAA.. per libewf."""
        stem = first.with_suffix("")
        first_char = first.suffix[1:2] or "E"
        upper = first_char.isupper()
        if number < 100:
            ext = f"{first_char}{number:02d}"
        else:
            n = number - 100
            letters = string.ascii_uppercase
            c0 = chr(ord(first_char.upper()) + n // (26 * 26))
            ext = f"{c0}{letters[(n // 26) % 26]}{letters[n % 26]}"
            ext = ext if upper else ext.lower()
        return stem.with_suffix("." + ext)

    def _open(self) -> None:
        number = 1
        path = self.first_segment
        while path.exists():
            f = ReadOnlyFile(path)
            header = f.read_at(0, FILE_HEADER_SIZE)
            if len(header) < FILE_HEADER_SIZE or header[:8] != EWF_SIGNATURE:
                f.close()
                if number == 1:
                    raise ImageFormatError(f"{path}: not an EWF-E01 segment (bad signature)")
                self.warnings.append(f"{path}: bad signature; segment set truncated here")
                break
            seg_no = struct.unpack_from("<H", header, 9)[0]
            if seg_no != number:
                self.warnings.append(f"{path}: header segment number {seg_no}, expected {number}")
            self._files.append(f)
            self.segment_paths.append(path)
            last = self._read_sections(len(self._files) - 1)
            if last == "done":
                break
            number += 1
            path = self.segment_name(self.first_segment, number)
        else:
            if number > 1:
                self.warnings.append(f"segment {path.name} missing; image is incomplete")
        if not self._files:
            raise ImageFormatError(f"{self.first_segment}: cannot open")
        if self.bytes_per_sector == 0 or self.sectors_per_chunk == 0:
            raise ImageFormatError("no volume/disk section found")
        if len(self._chunks) < self.chunk_count:
            self.warnings.append(
                f"table lists {len(self._chunks)} chunks, volume declares {self.chunk_count}"
            )

    def _read_sections(self, seg_index: int) -> str:
        f = self._files[seg_index]
        offset = FILE_HEADER_SIZE
        last_type = ""
        sectors_end: int | None = None
        pending_table = False
        for _ in range(MAX_SECTIONS_PER_SEGMENT):
            desc = f.read_at(offset, SECTION_DESCRIPTOR_SIZE)
            if len(desc) < SECTION_DESCRIPTOR_SIZE:
                self.warnings.append(f"segment {seg_index + 1}: truncated section at {offset}")
                return last_type
            stype = desc[:16].split(b"\x00", 1)[0].decode("ascii", "replace")
            next_offset, size = struct.unpack_from("<QQ", desc, 16)
            stored_adler = struct.unpack_from("<I", desc, 72)[0]
            if zlib.adler32(desc[:72]) != stored_adler:
                self.warnings.append(
                    f"segment {seg_index + 1}: section {stype!r} at {offset} descriptor checksum mismatch"
                )
            sec = Section(seg_index + 1, offset, stype, next_offset, size)
            self.sections.append(sec)
            data_off = offset + SECTION_DESCRIPTOR_SIZE
            try:
                if stype in ("volume", "disk"):
                    self._parse_volume(f.read_at(data_off, 94))
                elif stype == "sectors":
                    sectors_end = offset + size
                elif stype == "table":
                    self._parse_table(seg_index, f, data_off, sectors_end or offset)
                    pending_table = True
                elif stype == "table2" and not pending_table:
                    self._parse_table(seg_index, f, data_off, sectors_end or offset)
                elif stype in ("header", "header2") and not self.header_values:
                    self._parse_header(f.read_at(data_off, size - SECTION_DESCRIPTOR_SIZE), stype)
                elif stype == "hash":
                    self.stored_md5 = f.read_at(data_off, 16).hex()
                elif stype == "digest":
                    d = f.read_at(data_off, 36)
                    self.stored_md5 = d[:16].hex()
                    self.stored_sha1 = d[16:36].hex()
            except (struct.error, ValueError, zlib.error, UnicodeDecodeError) as exc:
                self.warnings.append(f"segment {seg_index + 1}: section {stype!r} unparsable: {exc}")
            if stype == "sectors":
                pending_table = False
            last_type = stype
            if stype in ("done", "next") or next_offset == offset:
                return stype
            if next_offset < offset or next_offset > f.size:
                self.warnings.append(f"segment {seg_index + 1}: invalid next offset {next_offset}")
                return stype
            offset = next_offset
        return last_type  # pragma: no cover

    def _parse_volume(self, data: bytes) -> None:
        chunks, spc, bps, sectors = struct.unpack_from("<IIIQ", data, 4)
        if self.bytes_per_sector and (spc, bps) != (self.sectors_per_chunk, self.bytes_per_sector):
            self.warnings.append("inconsistent volume sections across segments")
            return
        self.chunk_count, self.sectors_per_chunk = chunks, spc
        self.bytes_per_sector, self.sector_count = bps, sectors
        if bps not in (512, 1024, 2048, 4096) or spc == 0:
            raise ImageFormatError(f"implausible geometry: {spc} sectors/chunk, {bps} bytes/sector")

    def _parse_table(self, seg_index: int, f: ReadOnlyFile, data_off: int, data_end: int) -> None:
        hdr = f.read_at(data_off, TABLE_HEADER_SIZE)
        count = struct.unpack_from("<I", hdr, 0)[0]
        base = struct.unpack_from("<Q", hdr, 8)[0]
        if zlib.adler32(hdr[:20]) != struct.unpack_from("<I", hdr, 20)[0]:
            self.warnings.append(f"segment {seg_index + 1}: table header checksum mismatch")
        raw = f.read_at(data_off + TABLE_HEADER_SIZE, count * 4)
        if len(raw) < count * 4:
            self.warnings.append(f"segment {seg_index + 1}: table truncated")
            count = len(raw) // 4
        entries = struct.unpack_from(f"<{count}I", raw)
        offsets = [base + (e & OFFSET_MASK) for e in entries]
        for i, e in enumerate(entries):
            end = offsets[i + 1] if i + 1 < count else data_end
            stored = end - offsets[i] if end > offsets[i] else None
            self._chunks.append(ChunkLocation(seg_index, offsets[i], stored, bool(e & COMPRESSED_FLAG)))

    def _parse_header(self, data: bytes, stype: str) -> None:
        text_raw = zlib.decompress(data)
        if stype == "header2":
            text = text_raw.decode("utf-16-le", "replace").lstrip("\ufeff")
        else:
            text = text_raw.decode("latin-1")
        lines = [ln.rstrip("\r") for ln in text.split("\n")]
        # Layout: count, category name, keys (tab separated), values (tab separated).
        if len(lines) >= 4:
            keys = lines[2].split("\t")
            values = lines[3].split("\t")
            self.header_values = {k: v for k, v in zip(keys, values, strict=False) if k}

    # -- reading -----------------------------------------------------------------------------
    @property
    def chunk_size(self) -> int:
        return self.sectors_per_chunk * self.bytes_per_sector

    @property
    def media_size(self) -> int:
        return self.sector_count * self.bytes_per_sector

    def _chunk(self, index: int) -> bytes:
        if index == self._cache_index:
            return self._cache_data
        expected = min(self.chunk_size, self.media_size - index * self.chunk_size)
        data: bytes
        try:
            if index >= len(self._chunks):
                raise ImageFormatError("chunk missing from table")
            loc = self._chunks[index]
            f = self._files[loc.segment]
            if loc.compressed:
                limit = loc.stored_size if loc.stored_size is not None else self.chunk_size + 1024
                d = zlib.decompressobj()
                data = d.decompress(f.read_at(loc.offset, limit), self.chunk_size)
                if not d.eof:
                    raise ImageFormatError("truncated compressed chunk")
            else:
                want = loc.stored_size if loc.stored_size is not None else expected + 4
                raw = f.read_at(loc.offset, min(want, self.chunk_size + 4))
                data = raw[:-4]
                if zlib.adler32(data) != struct.unpack_from("<I", raw, len(raw) - 4)[0]:
                    raise ImageFormatError("stored chunk checksum mismatch")
            if expected < len(data) <= self.chunk_size and index == self.chunk_count - 1:
                # Source was not sector aligned: the chunk holds bytes beyond the sector count.
                self._note(f"last chunk holds {len(data) - expected} bytes beyond declared media size")
                data = data[:expected]
            if len(data) != expected:
                raise ImageFormatError(f"chunk decoded to {len(data)} bytes, expected {expected}")
        except (ImageFormatError, zlib.error, OSError, struct.error) as exc:
            self.chunk_errors[index] = str(exc)
            data = b"\x00" * expected
        self._cache_index, self._cache_data = index, data
        return data

    def _note(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)

    def read_at(self, offset: int, length: int) -> bytes:
        end = min(offset + length, self.media_size)
        out = bytearray()
        pos = offset
        cs = self.chunk_size
        while pos < end:
            idx, rel = divmod(pos, cs)
            chunk = self._chunk(idx)
            take = min(end - pos, len(chunk) - rel)
            if take <= 0:
                break
            out += chunk[rel : rel + take]
            pos += take
        return bytes(out)

    def describe(self) -> dict[str, Any]:
        return {
            "ewf": {
                "bytes_per_sector": self.bytes_per_sector,
                "sectors_per_chunk": self.sectors_per_chunk,
                "sector_count": self.sector_count,
                "chunk_count": self.chunk_count,
                "stored_md5": self.stored_md5,
                "stored_sha1": self.stored_sha1,
                "header": dict(sorted(self.header_values.items())),
                "warnings": list(self.warnings),
            }
        }

    def close(self) -> None:
        for f in self._files:
            f.close()
        self._files = []
