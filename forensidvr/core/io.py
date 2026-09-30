"""Random-access byte sources. Every parser reads evidence through :class:`ByteSource`."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol, runtime_checkable

DEFAULT_CHUNK = 4 * 1024 * 1024


@runtime_checkable
class ByteSource(Protocol):
    """Read-only, random-access view of bytes (a disk image, a segment of one, or memory).

    Implementations must never expose a write path.
    """

    @property
    def size(self) -> int:
        """Total size in bytes."""
        ...

    def read_at(self, offset: int, length: int) -> bytes:
        """Return up to ``length`` bytes starting at ``offset`` (short only at end of source)."""
        ...


def iter_chunks(
    source: ByteSource, chunk_size: int = DEFAULT_CHUNK, start: int = 0, end: int | None = None
) -> Iterator[tuple[int, bytes]]:
    """Yield ``(offset, data)`` pairs covering ``[start, end)`` of ``source``."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    stop = source.size if end is None else min(end, source.size)
    offset = max(0, start)
    while offset < stop:
        data = source.read_at(offset, min(chunk_size, stop - offset))
        if not data:
            break
        yield offset, data
        offset += len(data)


class BytesSource:
    """In-memory :class:`ByteSource` (used for tests and carved fragments)."""

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)

    @property
    def size(self) -> int:
        return len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        return self._data[offset : offset + length]


class SliceSource:
    """A window ``[base, base+length)`` of another source, e.g. a partition."""

    def __init__(self, parent: ByteSource, base: int, length: int) -> None:
        if base < 0 or length < 0 or base + length > parent.size:
            raise ValueError("slice outside parent source")
        self._parent = parent
        self.base = base
        self._length = length

    @property
    def size(self) -> int:
        return self._length

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must be non-negative")
        if offset >= self._length:
            return b""
        return self._parent.read_at(self.base + offset, min(length, self._length - offset))
