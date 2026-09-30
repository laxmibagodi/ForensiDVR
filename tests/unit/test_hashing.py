import hashlib
from pathlib import Path

import pytest

from forensidvr.core.hashing import HashSet, MultiHasher, hash_bytes, hash_file, hash_source
from forensidvr.core.io import BytesSource


def test_known_vectors() -> None:
    h = hash_bytes(b"abc")
    assert h.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert h.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert h.size == 3


@pytest.mark.parametrize("chunk", [1, 7, 4096, 1 << 20])
def test_chunking_does_not_change_digest(tmp_path: Path, chunk: int) -> None:
    data = bytes(range(256)) * 1000
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    h = hash_file(p, chunk_size=chunk)
    assert h.sha256 == hashlib.sha256(data).hexdigest()
    assert h.md5 == hashlib.md5(data).hexdigest()
    assert h == hash_source(BytesSource(data), chunk_size=chunk)


def test_multihasher_incremental_equals_oneshot() -> None:
    m = MultiHasher()
    for part in (b"a", b"bc", b""):
        m.update(part)
    assert m.result() == hash_bytes(b"abc")


def test_matches_requires_size_and_both_digests() -> None:
    h = hash_bytes(b"x")
    assert h.matches(HashSet(h.md5, h.sha256, h.size))
    assert not h.matches(HashSet(h.md5, h.sha256, h.size + 1))
    assert not h.matches(HashSet("0" * 32, h.sha256, h.size))
    assert not h.matches(HashSet(h.md5, "0" * 64, h.size))


def test_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert hash_file(p).sha256 == hashlib.sha256(b"").hexdigest()
