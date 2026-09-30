"""Identification engine against synthetic Hikvision-/Dahua-style images and failure cases."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import ClassVar

import pytest

from forensidvr.acquisition.readers import open_image
from forensidvr.core.io import BytesSource
from forensidvr.core.jsonutil import canonical_json
from forensidvr.core.readonly import WriteBlocker
from forensidvr.identify import IdentificationResult, discover_identifiers, identify
from forensidvr.identify.base import Identifier, Signal, SignalKind
from forensidvr.identify.context import ScanContext
from forensidvr.identify.engine import noisy_or
from forensidvr.identify.oem import load_table, parse_table
from forensidvr.identify.signatures.dahua import DahuaIdentifier
from forensidvr.identify.signatures.hikvision import HikvisionIdentifier
from tests.fixtures.synth import MiB, SynthImage, generate_all, make_hikvision


@pytest.fixture(scope="module")
def synth(tmp_path_factory: pytest.TempPathFactory) -> dict[str, SynthImage]:
    return {s.path.stem: s for s in generate_all(tmp_path_factory.mktemp("synth"))}


def run(path: Path) -> IdentificationResult:
    with open_image(path) as img:
        return identify(img)


def codes(r: IdentificationResult) -> set[str]:
    return {w.code for w in r.warnings}


def test_builtin_identifiers_discovered() -> None:
    names = {p.name for p in discover_identifiers().plugins}
    assert {"partition-table", "hikvision-hikbtree-id", "dahua-dhfs-id", "vendor-strings"} <= names


def test_noisy_or() -> None:
    assert noisy_or([]) == 0.0
    assert noisy_or([0.5, 0.5]) == 0.75
    assert noisy_or([1.5, -1]) == 1.0


def test_hikvision_clean(synth: dict[str, SynthImage]) -> None:
    s = synth["hikvision-clean"]
    r = run(s.path)
    m = s.manifest
    assert (r.status, r.vendor_family, r.vendor) == ("identified", "hikvision", "Hikvision")
    assert (r.fs_version, r.firmware, r.model_family) == (m["fs_version"], m["firmware"], m["model"])
    assert r.serial == "DS7208HQHI0120260101CCRR"
    assert r.channel_count is None  # needs HIKBTREE entry parsing (Phase 3)
    master = next(x for x in r.signals if x.kind is SignalKind.FS_SIGNATURE)
    assert master.sources[0].offset == m["layout"]["master_signature"]
    assert master.raw_metadata["hikbtree1_offset"] == m["layout"]["hikbtree"][0]
    assert master.plugin == "hikvision-hikbtree-id" and master.plugin_version
    assert "NO_FS_PLUGIN" in codes(r) and r.recommended_fs_plugin == "generic-carve"
    assert r.bytes_scanned < 8 * MiB


def test_hikvision_zero_master_is_only_probable(synth: dict[str, SynthImage]) -> None:
    r = run(synth["hikvision-zero_master"].path)
    assert r.vendor_family == "hikvision" and r.status == "probable"
    assert "NO_FS_SIGNATURE" in codes(r) and r.fs_version is None


def test_hikvision_truncated(synth: dict[str, SynthImage]) -> None:
    r = run(synth["hikvision-truncated"].path)
    assert r.vendor_family == "hikvision" and r.status == "identified"
    master = next(x for x in r.signals if x.kind is SignalKind.FS_SIGNATURE)
    assert "SIZE_MISMATCH" in {w.code for w in master.warnings}
    assert "HIKBTREE_MISSING" in codes(r)


def test_dahua_clean(synth: dict[str, SynthImage]) -> None:
    s = synth["dahua-clean"]
    r = run(s.path)
    assert (r.status, r.vendor_family, r.vendor, r.fs_version) == ("identified", "dahua", "Dahua", "DHFS4.1")
    assert r.channel_count == s.manifest["channels_planted"] and r.channel_count_estimated
    assert (r.firmware, r.model_family) == (s.manifest["firmware"], s.manifest["model"])
    stream = next(x for x in r.signals if x.kind is SignalKind.STREAM)
    assert stream.raw_metadata["codecs"] == {"h264": stream.raw_metadata["codecs"]["h264"]}
    lay = s.manifest["layout"]
    assert lay["data_area_offset"] <= stream.sources[0].offset < lay["data_end"]
    sb = next(x for x in r.signals if x.kind is SignalKind.STRUCTURE)
    assert sb.sources[0].offset == lay["superblock_offset"] and sb.raw_metadata["block_size"] == 512


def test_dahua_zero_magic_is_probable(synth: dict[str, SynthImage]) -> None:
    r = run(synth["dahua-zero_magic"].path)
    assert r.vendor_family == "dahua" and r.status == "probable" and r.channel_count == 4
    assert "NO_FS_SIGNATURE" in codes(r)


def test_dahua_truncated_and_corrupt_frames(synth: dict[str, SynthImage]) -> None:
    r = run(synth["dahua-truncated"].path)
    assert r.status == "identified" and r.vendor_family == "dahua"
    r = run(synth["dahua-corrupt_frames"].path)
    stream = next(x for x in r.signals if x.kind is SignalKind.STREAM)
    assert stream.raw_metadata["rejected_candidates"] > 0 and r.channel_count == 4


def test_cpplus_maps_to_dahua_family(synth: dict[str, SynthImage]) -> None:
    r = run(synth["cpplus-clean"].path)
    assert (r.vendor, r.vendor_family, r.channel_count) == ("CP Plus", "dahua", 8)
    assert r.model_family == "CP-UVR-0801E1-CS"
    assert "BRAND_NOT_FOUND" not in codes(r)


def test_unknown_noise_falls_back_to_generic_carving(synth: dict[str, SynthImage]) -> None:
    r = run(synth["unknown-noise"].path)
    assert (r.status, r.vendor, r.vendor_family, r.confidence) == ("unknown", None, None, 0.0)
    assert "UNKNOWN_DEVICE" in codes(r) and r.recommended_fs_plugin == "generic-carve"


def test_deterministic_output(synth: dict[str, SynthImage]) -> None:
    for name in ("hikvision-clean", "dahua-clean", "unknown-noise"):
        assert canonical_json(run(synth[name].path)) == canonical_json(run(synth[name].path))


def test_fixture_generation_is_deterministic(tmp_path: Path) -> None:
    a = make_hikvision(tmp_path / "a.img", size=8 * MiB)
    b = make_hikvision(tmp_path / "b.img", size=8 * MiB)
    assert a.manifest["sha256"] == b.manifest["sha256"]
    assert (tmp_path / "a.manifest.json").exists()


def test_identification_never_writes(synth: dict[str, SynthImage]) -> None:
    path = synth["dahua-clean"].path
    before = path.read_bytes()
    with WriteBlocker([path]) as wb:
        run(path)
    assert wb.blocked_attempts == [] and path.read_bytes() == before


class _Broken(Identifier):
    name = "broken-test"
    version = "9.9"

    def scan(self, ctx: ScanContext) -> list[Signal]:
        raise RuntimeError("boom")


def test_broken_identifier_is_isolated(synth: dict[str, SynthImage]) -> None:
    with open_image(synth["dahua-clean"].path) as img:
        r = identify(img, identifiers=[_Broken, DahuaIdentifier])
    assert "IDENTIFIER_FAILED" in codes(r) and r.vendor_family == "dahua"


@pytest.mark.parametrize("data", [b"", b"DHFS4.1", b"HIKVISION@HANGZHOU" * 3, b"\x00" * 600])
def test_tiny_and_empty_images(data: bytes) -> None:
    r = identify(BytesSource(data))
    assert isinstance(r, IdentificationResult) and r.image_size == len(data)


class _ExplodingSource(BytesSource):
    def read_at(self, offset: int, length: int) -> bytes:
        raise OSError(5, "Input/output error")


def test_read_errors_become_warnings() -> None:
    r = identify(_ExplodingSource(bytes(4 * MiB)))
    assert r.status == "unknown" and "READ_ERROR" in codes(r)


def test_read_budget(synth: dict[str, SynthImage]) -> None:
    with open_image(synth["dahua-clean"].path) as img:
        ctx = ScanContext(img, budget=2 * MiB)
        r = identify(img, ctx=ctx)
    assert "SCAN_BUDGET" in codes(r) and r.bytes_scanned <= 2 * MiB


def test_hikvision_inside_mbr_partition(tmp_path: Path) -> None:
    fs = make_hikvision(tmp_path / "fs.img", size=8 * MiB).path.read_bytes()
    disk = bytearray(1 * MiB) + fs
    struct.pack_into("<BxxxBxxxII", disk, 446, 0x00, 0x83, 1 * MiB // 512, len(fs) // 512)
    disk[510:512] = b"\x55\xaa"
    r = identify(BytesSource(bytes(disk)), identifiers=[*_builtins()])
    assert r.vendor_family == "hikvision" and r.partitions[0]["start"] == 1 * MiB
    master = next(x for x in r.signals if x.kind is SignalKind.FS_SIGNATURE)
    assert master.sources[0].offset == 1 * MiB + 0x210


def _builtins() -> list[type[Identifier]]:
    return list(discover_identifiers().plugins)


def test_new_vendor_via_data_table_only() -> None:
    data = bytearray(2 * MiB)
    data[4096:4120] = b"Acme Surveillance NVR-X "
    table = parse_table(
        {
            "families": {"acmefs": {"default_vendor": "Acme"}},
            "vendors": [
                {"vendor": "Acme", "families": {"acmefs": 1.0}, "weight": 0.5, "patterns": ["\\bACME\\b"]}
            ],
        }
    )

    class _AcmeStrings(Identifier):
        name = "acme-strings"
        version = "0.1"
        priority: ClassVar[int] = 90

        def scan(self, ctx: ScanContext) -> list[Signal]:
            return [
                self.signal(kind=SignalKind.STRING, description="acme", vendor="Acme", confidence=0.5)
                for _, t in ctx.strings()
                if any(p.search(t) for v in table.vendors for p in v.patterns)
            ]

    r = identify(BytesSource(bytes(data)), identifiers=[_AcmeStrings], table=table, probe_fs=False)
    assert (r.vendor, r.vendor_family, r.status) == ("Acme", "acmefs", "probable")
    assert "NO_FS_SIGNATURE" in codes(r)


def test_brand_without_family_structure() -> None:
    data = bytearray(2 * MiB)
    data[8192:8220] = b"Uniview NVR system log start"
    r = identify(BytesSource(bytes(data)), probe_fs=False)
    assert r.vendor == "Uniview" and r.vendor_family is None and r.status == "unknown"
    assert {"FAMILY_UNKNOWN", "UNKNOWN_DEVICE"} <= codes(r)


def test_oem_table_loads_all_target_vendors() -> None:
    vendors = {v.vendor for v in load_table().vendors}
    assert vendors == {
        "Hikvision",
        "Dahua",
        "CP Plus",
        "Uniview",
        "Honeywell",
        "TP-Link VIGI",
        "Godrej",
        "Matrix",
    }


def test_hikvision_identifier_marked_experimental() -> None:
    assert HikvisionIdentifier.experimental and DahuaIdentifier.experimental
