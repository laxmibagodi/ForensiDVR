import hashlib
import shutil
from pathlib import Path

import pytest

from forensidvr.acquisition.ewf import EWFImage
from forensidvr.acquisition.readers import (
    EWFImageReader,
    RawImageReader,
    SplitRawReader,
    open_image,
)
from forensidvr.core.errors import ImageFormatError
from forensidvr.core.hashing import hash_source
from tests.fixtures.images import ewfacquire_available, make_e01, pattern_bytes

needs_ewf = pytest.mark.skipif(not ewfacquire_available(), reason="ewfacquire not installed")


def test_raw_reader(image_path: Path) -> None:
    data = image_path.read_bytes()
    with open_image(image_path) as r:
        assert isinstance(r, RawImageReader)
        assert r.size == len(data)
        assert r.read_at(1000, 50) == data[1000:1050]
        assert r.read_at(len(data) - 5, 100) == data[-5:]
        assert r.read_at(len(data) + 10, 5) == b""
        with pytest.raises(ValueError):
            r.read_at(-1, 5)


def test_split_reader_spans_segments(tmp_path: Path) -> None:
    data = pattern_bytes(10_000, seed=3)
    for i, start in enumerate(range(0, len(data), 3000), start=1):
        (tmp_path / f"img.{i:03d}").write_bytes(data[start : start + 3000])
    with open_image(tmp_path / "img.001") as r:
        assert isinstance(r, SplitRawReader)
        assert len(r.paths) == 4 and r.size == 10_000
        assert r.read_at(2990, 30) == data[2990:3020]
        assert r.read_at(0, 20_000) == data
        assert hash_source(r).sha256 == hashlib.sha256(data).hexdigest()


def test_not_ewf_raises_format_error(tmp_path: Path) -> None:
    p = tmp_path / "x.E01"
    p.write_bytes(b"not an ewf file at all")
    with pytest.raises(ImageFormatError):
        EWFImageReader(p)


@needs_ewf
@pytest.mark.ewftools
@pytest.mark.parametrize(
    ("compression", "segment", "fmt"),
    [
        ("best", None, "encase6"),
        ("none", 1024 * 1024, "encase6"),
        ("fast", None, "encase5"),
        ("empty-block", None, "ftk"),
        ("best", None, "encase7"),
    ],
)
def test_e01_matches_libewf_reference(
    tmp_path: Path, compression: str, segment: int | None, fmt: str
) -> None:
    data = pattern_bytes(3 * 1024 * 1024 + 4096, seed=11)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    e01 = make_e01(src, tmp_path / "ev", compression=compression, segment_size=segment, fmt=fmt)
    with open_image(e01) as r:
        assert isinstance(r, EWFImageReader)
        assert r.size == len(data)
        assert r.read_at(12345, 70000) == data[12345:82345]
        h = hash_source(r)
        assert h.md5 == hashlib.md5(data).hexdigest() == r.ewf.stored_md5
        assert not r.ewf.chunk_errors and not r.ewf.warnings
        if segment:
            assert len(r.paths) > 1
        if fmt in ("encase6", "encase7"):
            assert r.ewf.stored_sha1 == hashlib.sha1(data).hexdigest()
            assert r.ewf.header_values.get("c") == "CASE-42"


@needs_ewf
@pytest.mark.ewftools
def test_corrupt_e01_chunk_is_zeroed_and_reported(tmp_path: Path) -> None:
    data = pattern_bytes(1024 * 1024, seed=5)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    e01 = make_e01(src, tmp_path / "ev", compression="none")
    raw = bytearray(e01.read_bytes())
    img = EWFImage(e01)
    first_chunk = img._chunks[3].offset
    img.close()
    raw[first_chunk + 100] ^= 0xFF
    corrupt = tmp_path / "corrupt.E01"
    corrupt.write_bytes(bytes(raw))
    with open_image(corrupt) as r:
        out = r.read_at(0, r.size)  # must not raise
        cs = r.ewf.chunk_size
        assert 3 in r.ewf.chunk_errors
        assert out[3 * cs : 4 * cs] == bytes(cs)
        assert out[: 3 * cs] == data[: 3 * cs] and out[4 * cs :] == data[4 * cs :]


@needs_ewf
@pytest.mark.ewftools
def test_truncated_e01_does_not_crash(tmp_path: Path) -> None:
    data = pattern_bytes(1024 * 1024, seed=6)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    e01 = make_e01(src, tmp_path / "ev", compression="best")
    trunc = tmp_path / "trunc.E01"
    trunc.write_bytes(e01.read_bytes()[: e01.stat().st_size // 2])
    try:
        with open_image(trunc) as r:
            r.read_at(0, r.size)
            assert r.ewf.warnings or r.ewf.chunk_errors
    except ImageFormatError:
        pass  # acceptable: clean, typed failure


@needs_ewf
@pytest.mark.ewftools
def test_missing_middle_segment_reported(tmp_path: Path) -> None:
    src = tmp_path / "src.bin"
    src.write_bytes(pattern_bytes(3 * 1024 * 1024, seed=8))
    e01 = make_e01(src, tmp_path / "ev", compression="none", segment_size=1024 * 1024)
    shutil.move(tmp_path / "ev.E02", tmp_path / "moved.E02")
    with open_image(e01) as r:
        assert any("missing" in w for w in r.ewf.warnings)
        r.read_at(0, r.size)
        assert r.ewf.chunk_errors


def test_segment_naming() -> None:
    first = Path("/x/img.E01")
    assert EWFImage.segment_name(first, 2).name == "img.E02"
    assert EWFImage.segment_name(first, 99).name == "img.E99"
    assert EWFImage.segment_name(first, 100).name == "img.EAA"
    assert EWFImage.segment_name(first, 101).name == "img.EAB"
    assert EWFImage.segment_name(first, 126).name == "img.EBA"
