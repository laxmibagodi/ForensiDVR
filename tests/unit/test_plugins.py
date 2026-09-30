import sys
import textwrap
from pathlib import Path

from forensidvr.core.io import BytesSource
from forensidvr.core.plugins import discover
from forensidvr.formats import discover_format_plugins
from forensidvr.fs import discover_fs_plugins
from forensidvr.fs.base import FSPlugin
from forensidvr.fs.generic import GenericCarveFS


def test_builtin_discovery_finds_fallback() -> None:
    rep = discover_fs_plugins()
    assert GenericCarveFS in rep.plugins
    assert not rep.failures
    assert discover_format_plugins().failures == {}


def test_unknown_vendor_falls_back_to_generic_carving() -> None:
    img = BytesSource(b"\x00" * 1000)
    probes = sorted((p.probe(img) for p in discover_fs_plugins().plugins), key=lambda r: -r.confidence)
    best = next(p for p in discover_fs_plugins().plugins if p.name == probes[0].plugin)
    fs = best()
    info = fs.mount(img)
    assert info.vendor_family == "unknown" and info.warnings[0].code == "UNKNOWN_FS"
    regions = list(fs.iter_unallocated())
    assert sum(r.length for r in regions) == 1000
    assert list(fs.list_recordings()) == []


def test_discovery_skips_broken_modules_and_finds_new_plugins(tmp_path: Path, monkeypatch) -> None:
    pkg = tmp_path / "thirdparty_plugins"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "broken.py").write_text("raise RuntimeError('corrupt plugin')\n")
    (pkg / "good.py").write_text(
        textwrap.dedent("""
        from forensidvr.fs.generic import GenericCarveFS
        class AcmeFS(GenericCarveFS):
            name = "acme"
            vendor_family = "acme"
    """)
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        rep = discover(FSPlugin, ["thirdparty_plugins", "does_not_exist_pkg"])
        names = [p.name for p in rep.plugins]
        assert "acme" in names
        assert "thirdparty_plugins.broken" in rep.failures
        assert "does_not_exist_pkg" in rep.failures
    finally:
        for m in [m for m in sys.modules if m.startswith("thirdparty_plugins")]:
            del sys.modules[m]
