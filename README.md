# ForensiDVR

Open, vendor-agnostic forensic platform for acquiring, parsing, recovering, analysing and reporting
evidence from DVR/NVR storage (Smart India Hackathon 2026 — SIH26150, NTRO).

**Status: Phase 0 + 1** — plugin interfaces, hashing, tamper-evident custody log, read-only
enforcement, case database, raw/split/E01 readers, physical + logical acquisition, CLI.
Vendor parsers start in Phase 2/3. See `docs/known-limitations.md`.

## Guarantees

| Requirement | Where |
|---|---|
| Read-only evidence (`O_RDONLY`, software write-blocker) | `forensidvr/core/readonly.py`, `tests/unit/test_readonly.py` |
| MD5 + SHA-256 on every output; source re-verified per session | `core/hashing.py`, `Case.register_output`, `Case.start_session` |
| Append-only hash-chained custody log, UTC, DB-anchored head | `core/custody.py`, `tests/unit/test_custody.py` |
| Raw timestamp always retained | `core/models.py::TimestampValue` |
| Deterministic outputs | canonical JSON, sorted iteration, `test_deterministic_repeat_acquisition` |
| No crash on corrupt data | EWF chunk errors → zeros + report; bad sectors → zero-fill + log; plugin import failures skipped |

## Install

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
sudo apt-get install ewf-tools   # optional: only used by tests as an independent E01 reference
```

## Quick start

```bash
forensidvr case create ./cases/fir42 --name "FIR 42/2026" --examiner insp.rao --agency "State FSL"
forensidvr acquire disk ./cases/fir42 /dev/sdb --label "DVR1-HDD1"      # behind a HW write-blocker
forensidvr evidence add ./cases/fir42 ./images/dvr2.E01 --label "DVR2"    # pre-existing image
forensidvr acquire logical ./cases/fir42 /media/usb --label "USB export"
forensidvr session ./cases/fir42 EV-0001          # re-verifies hash before analysis
forensidvr custody verify ./cases/fir42           # exit 3 if the log was tampered with
forensidvr case info ./cases/fir42
forensidvr image info ./images/dvr2.E01 --hash
forensidvr plugins list
```

## Development

```bash
ruff check forensidvr tests && ruff format --check forensidvr tests
mypy
pytest --cov=forensidvr
```

Docs: [architecture](docs/architecture.md) · [plugin guide](docs/plugin-developer-guide.md) ·
[acquisition SOP](docs/sop/acquisition.md) · [known limitations](docs/known-limitations.md)
