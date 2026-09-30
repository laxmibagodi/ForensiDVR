# Known Limitations

This file records every unverified assumption and EXPERIMENTAL component. It is updated in every
phase. Anything listed here must also be mentioned in the "Limitations" section of court reports.

## Phase 0/1 (current)

| Area | Limitation | Impact / mitigation |
|---|---|---|
| Software write-blocker | `WriteBlocker` intercepts Python-level calls only (`open`, `os.open`, `os.remove`, `os.rename`, `os.replace`, `os.truncate`, `os.chmod`, `os.utime`, `shutil.move`, `shutil.rmtree`). It cannot stop native extensions, other processes, or the kernel/firmware. | Defence in depth only. Physical disks **must** be attached through a hardware write-blocker (see `docs/sop/acquisition.md`). All readers additionally open with `O_RDONLY`. |
| `O_NOATIME` | Used when permitted; the kernel refuses it for files not owned by the caller, in which case the source access time may be updated by the OS. | Access time is file-system metadata, not evidence content; hashes are unaffected. Image from a hardware write-blocked device to avoid it entirely. |
| Custody log truncation | A hash chain cannot detect removal of the newest records by itself. | Head (`seq`, `entry_hash`) is anchored in `case.db` after every append and printed in reports; `custody verify` checks it. An attacker able to rewrite both files consistently is out of scope. Future: external anchoring (signed timestamps / printed head hash in the case file). |
| Custody log append-only | Enforced by the application (`O_APPEND`, refuse to extend a broken chain), not by the OS. | Optionally set `chattr +a custody.jsonl` (root) on the analysis workstation. |
| E01 reading | Pure-Python reader supports EWF-E01 (EnCase 1–7, FTK, libewf "ewf" formats) with deflate or stored chunks. **Not supported:** EWF2 `.Ex01`, `.L01` logical evidence, bzip2 chunks, `.D01` delta segments, encryption. | Unsupported variants fail with a clean `ImageFormatError`. Convert with `ewfexport` to raw if needed. |
| E01 non-sector-aligned sources | When a source size is not a multiple of the sector size, libewf 20140807 records `floor(size/512)` sectors but stores the full tail; the stored MD5 then covers bytes beyond the declared media size. Our reader follows the declared sector count and emits a warning. | Stored-MD5 comparison will report a mismatch for such images; this is flagged in the evidence note. |
| E01 writing | Acquisition writes raw/dd (single or split) only. | Use `ewfacquire` for E01 output and register the result with `forensidvr evidence add`. |
| Bad-sector handling | Unreadable sectors are zero-filled (same convention as `dd conv=noerror,sync` and `ewfacquire`) and included in the image hash. Verification re-reads the *destination*; a second pass over a failing source may legitimately produce a different hash. | Bad ranges are listed in the acquisition log and report. |
| Platform | Developed and tested on Linux (Ubuntu 22.04, Python 3.11/3.12). `fcntl`/`pread` are POSIX-only. | Windows support is not a Phase 1 goal. |

## Proprietary DVR formats

Phase 2 implements identification only (no recording extraction yet). Every assumption below is
validated **only against synthetic images** built from the cited sources; no real DVR disk has been
tested. Sources are listed in `docs/identification.md`.

| # | Assumption | Status | Source / reason |
|---|---|---|---|
| F1 | Hikvision master-sector signature `HIKVISION@HANGZHOU` at FS offset 0x210; field offsets (+0x38 capacity ... +0xE0 init time) relative to it | Cited, EXPERIMENTAL | Han/Jeong/Lee 2015; two independent open-source parsers agree. Only FS version `HIK.2011.03.08` is documented; other firmware may differ. |
| F2 | `HIKBTREE` signature 16 bytes after the recorded HIKBTREE offset; offsets partition-relative | Cited, EXPERIMENTAL | X-Ways X-Tension; akira7799 parser. |
| F3 | System log records start with `RATS\x14\x00\x00\x00` | Cited, EXPERIMENTAL | akira7799 parser. Record body layout used in fixtures (u32 time, u16 type, text) is UNVERIFIED. |
| F4 | `HIK.yyyy.mm.dd` version string lies in the master sector (fixture places it at 0x230) | UNVERIFIED placement | Parser READMEs mention the string; exact offset not confirmed, so the engine searches the whole sector. |
| F5 | Hikvision channel count is not estimated in Phase 2 | Limitation | Needs HIKBTREE entry parsing (Phase 3). |
| F6 | `DHFS4.1` magic at offset 0; partition table at 0x3C34, 64-byte entries, boot-sector offset @20 and partition offset @48 in sectors, terminated by `AA55AA55` | Cited, EXPERIMENTAL | dhfs_extractor (MIT). Other DHFS versions are flagged `UNSUPPORTED_DHFS_VERSION`. |
| F7 | DHFS superblock fields (+0x10/0x14 packed dates, +0x2C block size, +0x30 fragment size, +0x44/0x48/0x4C descriptor/data area, +0xF8 log offset in blocks, absolute) | Cited, EXPERIMENTAL | dhfs_extractor / X-Ways DHFS X-Tension. |
| F8 | DHAV frame header/trailer layout and packed date-time | Cited | FFmpeg `dhav.c`. The header checksum algorithm is UNVERIFIED (FFmpeg ignores it; fixtures use byte-sum). Whether the channel byte is 0- or 1-based is UNVERIFIED; raw ids are reported. |
| F9 | Dahua packed times are device-local time with unknown zone | Limitation | No UTC is derived until Phase 6; the raw value is always kept. |
| F10 | Channel count = distinct channel ids in sampled frame headers | Estimate | Idle or disabled channels, or channels outside the sampled windows, are missed. |
| F11 | Rebrand mapping: CP Plus -> dahua (0.6), Honeywell -> dahua 0.4 / hikvision 0.3, Godrej -> 0.2 each | UNVERIFIED | Public product/market reports only; kept below 1.0 and overridable in `oem_signatures.json`. |
| F12 | Uniview, TP-Link VIGI, Matrix: brand strings only, no file-system signature | Limitation | No public file-system documentation found; these fall back to `unknown - attempt generic carving` with `FAMILY_UNKNOWN`. |
| F13 | Model-name regexes (`DS-7xxx`, `DH-XVR...`, `CP-UVR...`, `VIGI NVRxxxx`) and firmware/serial patterns | UNVERIFIED | Public product naming, not observed on disk; low weight (0.3) or informational (0). |
| F14 | Synthetic images are scaled down (4 MiB data blocks, 32 MiB disks) | Limitation | Fixture sizes chosen for CI speed. |
| F15 | Identification reads ~5 MiB of a disk (head, 64 sampled windows, tail, pointed-to structures) | Limitation | Vendor strings outside those regions are not seen; full-disk string search is left to later phases. |
