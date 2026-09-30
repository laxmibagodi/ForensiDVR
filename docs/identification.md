# Device identification (Phase 2)

`forensidvr identify CASE EV-0001` fingerprints the device that wrote a disk image. It re-verifies
the evidence hash first (refusing with exit code 2 on mismatch), writes the result to
`exports/identify-EV-0001.json`, hashes that file (MD5 + SHA-256) and appends an `identify.result`
custody record. `forensidvr image identify IMAGE` is a preview outside any case; it logs nothing.

## Output

| field | meaning |
|---|---|
| `status` | `identified` (confidence >= 0.8), `probable` (>= 0.35), `unknown` ("unknown - attempt generic carving") |
| `vendor`, `vendor_family` | brand (e.g. *CP Plus*) and the shared parser family (e.g. *dahua*) |
| `model_family`, `firmware`, `fs_version`, `serial` | best supporting string, preferring signals consistent with the family |
| `channel_count`, `channel_ids` | **estimate**: distinct channel ids in sampled frame headers |
| `signals[]` | every piece of evidence: kind, weight (`confidence`), absolute `sources` offsets, `raw_metadata`, warnings, plugin + version |
| `family_candidates[]`, `vendor_candidates[]` | all scored alternatives |
| `recommended_fs_plugin` | FS plugin to use next (`generic-carve` until the Phase 3/4 parsers land) |
| `bytes_scanned` | how much of the image was read |

## How it works

1. **Bounded, deterministic reads** (`identify/context.py`): first 1 MiB, 64 evenly spaced
   sector-aligned 64 KiB windows plus the tail, and specific structures pointed to by superblocks
   (e.g. the log area). A 64 MiB read budget caps the scan on any disk size. I/O errors become
   `READ_ERROR` warnings.
2. **Identifier plugins** (`identify/signatures/`, entry-point group `forensidvr.identify`), run in
   `priority` order; a plugin that raises is recorded as `IDENTIFIER_FAILED` and skipped:
   * `partition-table` - MBR/GPT (informational; lets vendor plugins look inside partitions);
   * `hikvision-hikbtree-id` (EXPERIMENTAL) - `HIKVISION@HANGZHOU` at FS offset 0x210, master-sector
     fields, `HIKBTREE` at the recorded offsets (+16), `RATS` system-log area, `HIK.yyyy.mm.dd`;
   * `dahua-dhfs-id` (EXPERIMENTAL) - `DHFS4.1` magic, partition table at 0x3C34, superblock sanity
     (block size, packed dates), DHAV frames with matching trailer and valid date;
   * `vendor-strings` - brand/model patterns from `identify/oem_signatures.json`, plus generic
     firmware and serial-number patterns.
3. **Scoring** (`identify/engine.py`): family score is the noisy-OR `1 - prod(1 - w)` of signal
   weights; brand strings add `w x mapping` to each family the vendor maps to. Without a file-system
   signature the confidence is capped at 0.79 (`NO_FS_SIGNATURE`), so damaged-superblock images are
   never reported as more than *probable*. If no brand string is found the family's default vendor
   is reported with `BRAND_NOT_FOUND` (may be an OEM rebrand).

Adding a vendor: add an entry to `oem_signatures.json` (strings/mapping) and/or ship an
`Identifier` subclass via the entry point; no core change is needed.

## Sources

* Hikvision: Han, Jeong & Lee, *Analysis of the HIKVISION DVR file system*, ICDF2C 2015;
  [dw2102/X-Ways-HIKVISION-X-Tension](https://github.com/dw2102/X-Ways-HIKVISION-X-Tension) (targets `HIK.2011.03.08`);
  [akira7799/hikvision-dvr-parser](https://github.com/akira7799/hikvision-dvr-parser) (MIT). Both agree on the master-sector offsets used.
* Dahua DHFS4.1: [gbatmobile/dhfs_extractor](https://github.com/gbatmobile/dhfs_extractor) (MIT);
  [dw2102/X-Ways-DHFS4_1-X-Tension](https://github.com/dw2102/X-Ways-DHFS4_1-X-Tension).
* DHAV frames and packed date: FFmpeg [`libavformat/dhav.c`](https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/dhav.c)
  (independently re-implemented; no FFmpeg code copied).

## Synthetic fixtures

`python -m tests.fixtures.synth OUTDIR` writes deterministic images with `*.manifest.json` ground
truth: `hikvision-{clean,zero_master,truncated}`, `dahua-{clean,zero_magic,truncated,corrupt_frames}`,
`cpplus-clean` (Dahua layout + CP Plus strings, 8 channels) and `unknown-noise`. They are scaled
down (e.g. 4 MiB instead of 1 GiB Hikvision data blocks) and only prove that the code matches the
cited layouts, not that it works on real recorders.
