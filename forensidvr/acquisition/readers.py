"""Read-only evidence image readers: raw/dd, split raw (``.001``...), and EWF/E01.

All readers implement :class:`~forensidvr.core.io.ByteSource` over the *logical media* (for E01:
the decompressed disk contents), open every file with ``O_RDONLY``, and expose no write path.
"""

from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
from types import TracebackType
from typing import Any

from forensidvr.acquisition.ewf import EWF_SIGNATURE, EWFImage
from forensidvr.core.errors import ImageFormatError
from forensidvr.core.readonly import ReadOnlyFile


class ImageReader(ABC):
    """Base reader. Subclasses provide :attr:`size` and :meth:`read_at`."""

    format_name: str = "unknown"

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths

    @property
    @abstractmethod
    def size(self) -> int: ...

    @abstractmethod
    def read_at(self, offset: int, length: int) -> bytes: ...

    @abstractmethod
    def close(self) -> None: ...

    def describe(self) -> dict[str, Any]:
        """Deterministic description for reports / ``image info``."""
        return {
            "format": self.format_name,
            "size": self.size,
            "segments": [str(p) for p in self.paths],
        }

    def __enter__(self) -> ImageReader:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _check_range(offset: int, length: int) -> None:
    if offset < 0 or length < 0:
        raise ValueError("offset and length must be non-negative")


class RawImageReader(ImageReader):
    """Single-file raw/dd image or block device."""

    format_name = "raw"

    def __init__(self, path: str | os.PathLike[str]) -> None:
        super().__init__([Path(path)])
        self._f = ReadOnlyFile(path)

    @property
    def size(self) -> int:
        return self._f.size

    def read_at(self, offset: int, length: int) -> bytes:
        _check_range(offset, length)
        return self._f.read_at(offset, min(length, max(0, self.size - offset)))

    def close(self) -> None:
        self._f.close()


_SPLIT_RE = re.compile(r"^(?P<base>.+)\.(?P<num>\d{3,})$")


def split_segments(first: Path) -> list[Path]:
    """Return ``first`` and its consecutive siblings (``x.001``, ``x.002``, ...)."""
    m = _SPLIT_RE.match(first.name)
    if not m:
        raise ImageFormatError(f"{first} is not a numbered split segment")
    width = len(m["num"])
    start = int(m["num"])
    segs: list[Path] = []
    n = start
    while True:
        p = first.with_name(f"{m['base']}.{n:0{width}d}")
        if not p.exists():
            break
        segs.append(p)
        n += 1
    if not segs:
        raise ImageFormatError(f"{first} does not exist")
    return segs


class SplitRawReader(ImageReader):
    """Raw image split across numbered segments."""

    format_name = "split-raw"

    def __init__(self, first_segment: str | os.PathLike[str]) -> None:
        segs = split_segments(Path(first_segment))
        super().__init__(segs)
        self._files = [ReadOnlyFile(p) for p in segs]
        self._starts: list[int] = []
        total = 0
        for f in self._files:
            self._starts.append(total)
            total += f.size
        self._size = total

    @property
    def size(self) -> int:
        return self._size

    def read_at(self, offset: int, length: int) -> bytes:
        _check_range(offset, length)
        out = bytearray()
        end = min(offset + length, self._size)
        pos = offset
        for start, f in zip(self._starts, self._files, strict=True):
            if pos >= end:
                break
            seg_end = start + f.size
            if pos < seg_end and end > start:
                rel = pos - start
                take = min(end, seg_end) - pos
                out += f.read_at(rel, take)
                pos += take
        return bytes(out)

    def close(self) -> None:
        for f in self._files:
            f.close()


class EWFImageReader(ImageReader):
    """EWF-E01 (EnCase 1-7 style, ``EVF`` signature) reader. See :mod:`forensidvr.acquisition.ewf`."""

    format_name = "e01"

    def __init__(self, first_segment: str | os.PathLike[str]) -> None:
        self._ewf = EWFImage(Path(first_segment))
        super().__init__(self._ewf.segment_paths)

    @property
    def size(self) -> int:
        return self._ewf.media_size

    def read_at(self, offset: int, length: int) -> bytes:
        _check_range(offset, length)
        return self._ewf.read_at(offset, length)

    @property
    def ewf(self) -> EWFImage:
        return self._ewf

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d.update(self._ewf.describe())
        return d

    def close(self) -> None:
        self._ewf.close()


def open_image(path: str | os.PathLike[str]) -> ImageReader:
    """Open an evidence image, detecting the container from magic bytes / segment naming."""
    p = Path(path)
    with ReadOnlyFile(p) as f:
        head = f.read_at(0, 8)
    if head == EWF_SIGNATURE:
        return EWFImageReader(p)
    if _SPLIT_RE.match(p.name):
        return SplitRawReader(p)
    return RawImageReader(p)
