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

Not yet implemented (Phases 2+). No format specifications have been assumed so far.
