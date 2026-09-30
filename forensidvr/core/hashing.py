"""MD5 + SHA-256 hashing of files, byte sources and streams (hard requirement #2).

MD5 is retained for compatibility with existing forensic tooling and court practice; SHA-256 is
the integrity hash of record. Both are always computed together in a single pass.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forensidvr.core.io import DEFAULT_CHUNK, ByteSource, iter_chunks
from forensidvr.core.readonly import ReadOnlyFile


def _new_md5() -> Any:
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:  # pragma: no cover - very old OpenSSL builds
        return hashlib.md5()


@dataclass(frozen=True)
class HashSet:
    """Hex digests plus the number of bytes hashed."""

    md5: str
    sha256: str
    size: int

    def matches(self, other: HashSet) -> bool:
        """Constant-time comparison of both digests and the size."""
        return (
            self.size == other.size
            and hmac.compare_digest(self.md5, other.md5)
            and hmac.compare_digest(self.sha256, other.sha256)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"md5": self.md5, "sha256": self.sha256, "size": self.size}


class MultiHasher:
    """Incremental MD5 + SHA-256 hasher (hash-on-the-fly during acquisition/copy)."""

    def __init__(self) -> None:
        self._md5 = _new_md5()
        self._sha256 = hashlib.sha256()
        self.size = 0

    def update(self, data: bytes | bytearray | memoryview) -> None:
        self._md5.update(data)
        self._sha256.update(data)
        self.size += len(data)

    def result(self) -> HashSet:
        return HashSet(md5=self._md5.hexdigest(), sha256=self._sha256.hexdigest(), size=self.size)


def hash_bytes(data: bytes) -> HashSet:
    """Hash an in-memory buffer."""
    h = MultiHasher()
    h.update(data)
    return h.result()


def hash_source(source: ByteSource, chunk_size: int = DEFAULT_CHUNK) -> HashSet:
    """Hash every byte of a :class:`ByteSource` (e.g. the logical media of an E01)."""
    h = MultiHasher()
    for _, data in iter_chunks(source, chunk_size):
        h.update(data)
    if h.size != source.size:
        raise OSError(f"short read while hashing: got {h.size} of {source.size} bytes")
    return h.result()


def hash_file(path: str | os.PathLike[str], chunk_size: int = DEFAULT_CHUNK) -> HashSet:
    """Hash a file, opening it strictly read-only."""
    with ReadOnlyFile(Path(path)) as f:
        return hash_source(f, chunk_size)
