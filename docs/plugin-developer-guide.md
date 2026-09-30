# Plugin Developer Guide

## Writing a file-system plugin

1. Create `forensidvr/fs/<family>.py` (built-in) or a separate package exposing an entry point:

   ```toml
   [project.entry-points."forensidvr.fs"]
   acme = "acme_forensidvr.fs:AcmeFS"
   ```

2. Subclass `forensidvr.fs.base.FSPlugin`:

   ```python
   class AcmeFS(FSPlugin):
       name = "acme-fs"
       version = "0.1.0"
       vendor_family = "acme"
       vendors = ("Acme", "Acme OEM rebrand")
       experimental = True            # until the layout is backed by citable documentation

       @classmethod
       def probe(cls, image: ByteSource) -> ProbeResult:
           head = image.read_at(0x200, 16)
           if head.startswith(b"ACMEFS"):
               return ProbeResult(plugin=cls.name, confidence=0.9, reasons=("superblock magic",))
           return ProbeResult(plugin=cls.name, confidence=0.0)

       def mount(self, image): ...
       def list_recordings(self): ...
       def read_index(self): ...
       def iter_unallocated(self): ...
   ```

No core code changes are needed; `forensidvr plugins list` should show the plugin.

## Rules

* **Read-only.** Only use `ByteSource.read_at`. Never open evidence paths yourself.
* **No crashes after `mount`.** Wrap per-record parsing; on failure attach a `PluginWarning`
  (`code`, `message`, `offset`) to the affected finding, lower its `confidence`, continue.
  `probe` must never raise.
* **Offsets.** Every finding lists `SourceRef(offset, length)` for the bytes it came from.
* **Raw metadata.** Put decoded-but-uninterpreted fields in `raw_metadata`.
* **Timestamps.** Build `TimestampValue(raw=..., raw_encoding=...)`; leave `utc=None` unless the
  zone is known. Normalisation belongs to `forensidvr.timeline`.
* **Determinism.** Iterate in on-disk order; no randomness, no wall-clock values.
* **Documentation.** Cite the source of each structure in the module docstring. If none exists,
  set `experimental = True`, mark assumptions `# UNVERIFIED:` in code, and add them to
  `docs/known-limitations.md`.
* **Tests.** Add a fixture generator under `tests/fixtures/` with a ground-truth manifest,
  plus corrupt/truncated variants.

## Format plugins

Same pattern with `forensidvr.formats.base.FormatPlugin` and entry-point group
`forensidvr.formats`. `to_standard_video` should remux (no re-encode) by default and report the
method in `ConversionResult.method`.
