"""``forensidvr`` command-line interface (Typer).

Every command that touches a case writes custody records as the examiner given by
``--examiner`` / ``FORENSIDVR_EXAMINER`` (default: the case's lead examiner).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Optional

import typer

from forensidvr import TOOL_NAME, __version__
from forensidvr.core.case import Case
from forensidvr.core.errors import EvidenceIntegrityError, ForensiDVRError
from forensidvr.core.hashing import hash_file
from forensidvr.core.jsonutil import pretty_json

if TYPE_CHECKING:
    from forensidvr.identify.engine import IdentificationResult

app = typer.Typer(
    name="forensidvr",
    help=f"{TOOL_NAME}: multi-vendor DVR/NVR forensics.",
    no_args_is_help=True,
    add_completion=False,
)
case_app = typer.Typer(help="Create and inspect cases.", no_args_is_help=True)
evidence_app = typer.Typer(help="Register and verify evidence.", no_args_is_help=True)
acquire_app = typer.Typer(help="Physical and logical acquisition.", no_args_is_help=True)
custody_app = typer.Typer(help="Chain-of-custody log.", no_args_is_help=True)
image_app = typer.Typer(help="Inspect image containers (read-only, no case needed).", no_args_is_help=True)
plugins_app = typer.Typer(help="List discovered plugins.", no_args_is_help=True)
for sub, name in (
    (case_app, "case"),
    (evidence_app, "evidence"),
    (acquire_app, "acquire"),
    (custody_app, "custody"),
    (image_app, "image"),
    (plugins_app, "plugins"),
):
    app.add_typer(sub, name=name)

CaseDir = Annotated[Path, typer.Argument(help="Case directory.")]
Examiner = Annotated[
    str | None,
    typer.Option("--examiner", "-e", envvar="FORENSIDVR_EXAMINER", help="Examiner performing the action."),
]
AsJson = Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")]


def _fail(msg: str, code: int = 1) -> None:
    typer.secho(f"error: {msg}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _open(case_dir: Path, examiner: str | None, command: str) -> Case:
    try:
        case = Case.open(case_dir, examiner=examiner)
    except ForensiDVRError as exc:
        _fail(str(exc))
        raise  # unreachable
    case.log("cli.command", {"command": command, "argv": sys.argv[1:]})
    return case


def _parse_size(text: str | None) -> int | None:
    if text is None:
        return None
    units = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    t = text.strip().lower().rstrip("ib").rstrip("b") if text.lower().endswith("b") else text.lower()
    if t and t[-1] in units:
        return int(float(t[:-1]) * units[t[-1]])
    return int(t)


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(f"{TOOL_NAME} {__version__}")


@app.command("hash")
def hash_cmd(files: list[Path], as_json: AsJson = False) -> None:
    """MD5 + SHA-256 of files (opened read-only)."""
    out = {}
    for f in files:
        h = hash_file(f)
        out[str(f)] = h.to_dict()
        if not as_json:
            typer.echo(f"{h.md5}  {h.sha256}  {h.size:>14}  {f}")
    if as_json:
        typer.echo(pretty_json(out), nl=False)


# -- case -----------------------------------------------------------------------------------
@case_app.command("create")
def case_create(
    case_dir: CaseDir,
    name: Annotated[str, typer.Option("--name", "-n", help="Case name.")],
    examiner: Annotated[str, typer.Option("--examiner", "-e", envvar="FORENSIDVR_EXAMINER")],
    case_number: Annotated[str, typer.Option("--case-number")] = "",
    agency: Annotated[str, typer.Option("--agency")] = "",
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Create a new case directory with its database and custody log."""
    try:
        case = Case.create(
            case_dir,
            name=name,
            examiner=examiner,
            case_number=case_number,
            agency=agency,
            description=description,
        )
    except ForensiDVRError as exc:
        _fail(str(exc))
        return
    typer.echo(f"created case {case.info.case_id} at {case.root}")
    case.close()


@case_app.command("info")
def case_info(case_dir: CaseDir, examiner: Examiner = None, as_json: AsJson = False) -> None:
    """Show case metadata, evidence and custody head."""
    with _open(case_dir, examiner, "case info") as case:
        s = case.summary()
    if as_json:
        typer.echo(pretty_json(s), nl=False)
        return
    c = s["case"]
    typer.echo(f"Case      {c['name']} ({c['case_number'] or 'no number'})  id={c['case_id']}")
    typer.echo(f"Examiner  {c['examiner']}   Agency: {c['agency'] or '-'}   Created: {c['created_utc']}")
    typer.echo(f"Outputs   {s['outputs']} registered")
    if s["custody_head"]:
        typer.echo(f"Custody   head seq={s['custody_head']['seq']} hash={s['custody_head']['hash']}")
    for e in s["evidence"]:
        typer.echo(
            f"  {e['id']}  {e['kind']:<10} {e['format']:<16} {e['size']:>14}  "
            f"sha256={e['sha256']}  {e['label']}"
        )


# -- evidence -------------------------------------------------------------------------------
@evidence_app.command("add")
def evidence_add(
    case_dir: CaseDir,
    image: Annotated[Path, typer.Argument(help="Existing raw/dd, .001 or .E01 image.")],
    label: Annotated[str, typer.Option("--label", "-l")],
    examiner: Examiner = None,
) -> None:
    """Register an image acquired elsewhere (hashed in place, never copied or modified)."""
    from forensidvr.acquisition.workflow import register_existing_image

    with _open(case_dir, examiner, "evidence add") as case:
        try:
            rec = register_existing_image(case, image, label=label)
        except (ForensiDVRError, OSError) as exc:
            case.log("evidence.register.failed", {"path": str(image), "error": str(exc)})
            _fail(str(exc))
            return
    typer.echo(f"{rec.id} registered: {rec.format} {rec.size} bytes")
    typer.echo(f"  MD5    {rec.md5}\n  SHA256 {rec.sha256}")
    if rec.notes:
        typer.echo(f"  {rec.notes}")


@evidence_app.command("list")
def evidence_list(case_dir: CaseDir, examiner: Examiner = None, as_json: AsJson = False) -> None:
    """List registered evidence."""
    with _open(case_dir, examiner, "evidence list") as case:
        items = case.list_evidence()
    if as_json:
        typer.echo(pretty_json([e.__dict__ for e in items]), nl=False)
        return
    for e in items:
        typer.echo(f"{e.id}  {e.kind:<10} {e.format:<16} {e.size:>14}  {e.label}  ({e.path})")


@evidence_app.command("verify")
def evidence_verify(
    case_dir: CaseDir,
    evidence_id: Annotated[str | None, typer.Argument(help="Evidence id; all if omitted.")] = None,
    examiner: Examiner = None,
) -> None:
    """Re-hash evidence and compare with the acquisition hashes."""
    failed = False
    with _open(case_dir, examiner, "evidence verify") as case:
        ids = [evidence_id] if evidence_id else [e.id for e in case.list_evidence()]
        for ev in ids:
            o = case.verify_evidence(ev)
            failed |= not o.ok
            status = typer.style("PASS", fg="green") if o.ok else typer.style("FAIL", fg="red")
            typer.echo(
                f"{ev}  {status}  expected sha256={o.expected.sha256}"
                + (f"  actual={o.actual.sha256}" if o.actual and not o.ok else "")
                + (f"  error={o.error}" if o.error else "")
            )
    if failed:
        raise typer.Exit(2)


@app.command("session")
def session_start(
    case_dir: CaseDir,
    evidence_id: Annotated[str, typer.Argument()],
    examiner: Examiner = None,
) -> None:
    """Start an analysis session (re-verifies the evidence hash; exits 2 on mismatch)."""
    with _open(case_dir, examiner, "session") as case:
        try:
            sid = case.start_session(evidence_id)
        except ForensiDVRError as exc:
            _fail(str(exc), code=2)
            return
    typer.echo(f"session {sid} started; {evidence_id} hash verified")


# -- acquisition ----------------------------------------------------------------------------
@acquire_app.command("disk")
def acquire_disk(
    case_dir: CaseDir,
    source: Annotated[Path, typer.Argument(help="Source device (e.g. /dev/sdb) or file.")],
    label: Annotated[str, typer.Option("--label", "-l")],
    block_size: Annotated[str, typer.Option("--block-size", help="e.g. 1M")] = "1M",
    split_size: Annotated[Optional[str], typer.Option("--split-size", help="e.g. 2G")] = None,  # noqa: UP045
    retries: Annotated[int, typer.Option("--retries")] = 2,
    examiner: Examiner = None,
) -> None:
    """Bit-for-bit raw image with hash-on-the-fly, bad-sector handling and verification."""
    from forensidvr.acquisition.workflow import acquire_to_case

    bs = _parse_size(block_size)
    assert bs is not None
    with _open(case_dir, examiner, "acquire disk") as case:
        try:
            result, rec = acquire_to_case(
                case,
                source,
                label=label,
                block_size=bs,
                split_size=_parse_size(split_size),
                retries=retries,
            )
        except (ForensiDVRError, OSError) as exc:
            case.log("acquisition.failed", {"source": str(source), "error": str(exc)})
            _fail(str(exc))
            return
    a = result.acquisition_hashes
    typer.echo(f"acquired {a.size} bytes -> {', '.join(result.destination)}")
    typer.echo(f"  MD5    {a.md5}\n  SHA256 {a.sha256}")
    typer.echo(
        f"  verification: {'PASS' if result.verified else 'FAIL'}; "
        f"bad sector ranges: {len(result.bad_sectors)}"
    )
    typer.echo(f"  report: {result.report_md}")
    if rec:
        typer.echo(f"  registered as {rec.id}")
    if not result.verified:
        raise typer.Exit(2)


@acquire_app.command("logical")
def acquire_logical(
    case_dir: CaseDir,
    source: Annotated[Path, typer.Argument(help="Exported clips/config/log directory or file.")],
    label: Annotated[str, typer.Option("--label", "-l")],
    examiner: Examiner = None,
) -> None:
    """Import exported files with per-file hashing and a manifest."""
    from forensidvr.acquisition.workflow import import_logical_to_case

    with _open(case_dir, examiner, "acquire logical") as case:
        try:
            result, rec = import_logical_to_case(case, source, label=label)
        except (ForensiDVRError, OSError) as exc:
            case.log("logical.failed", {"source": str(source), "error": str(exc)})
            _fail(str(exc))
            return
    typer.echo(
        f"{rec.id}: imported {len(result.files)} files ({result.total_bytes} bytes); "
        f"skipped {len(result.skipped)}; all verified: {result.all_verified}"
    )
    for rel, why in sorted(result.skipped.items()):
        typer.echo(f"  skipped {rel}: {why}")


# -- custody --------------------------------------------------------------------------------
@custody_app.command("verify")
def custody_verify(case_dir: CaseDir, examiner: Examiner = None) -> None:
    """Verify the hash chain and the database head anchor (exit 3 if tampered)."""
    try:
        case = Case(case_dir.resolve(), examiner=examiner)
    except ForensiDVRError as exc:
        _fail(str(exc))
        return
    with case:
        res = case.verify_custody()
        if res.ok:
            case.log("custody.verify", {"ok": True, "entries": res.entries})
    if res.ok:
        typer.secho(
            f"custody log OK: {res.entries} entries, head seq={res.head_seq} hash={res.head_hash}",
            fg="green",
        )
        for w in res.warnings:
            typer.echo(f"  warning: {w}")
        return
    typer.secho(f"custody log TAMPERED ({len(res.errors)} problems):", fg="red", err=True)
    for e in res.errors:
        typer.echo(f"  {e}", err=True)
    raise typer.Exit(3)


@custody_app.command("show")
def custody_show(
    case_dir: CaseDir,
    tail: Annotated[int, typer.Option("--tail", "-n", help="Show last N entries (0 = all).")] = 20,
    as_json: AsJson = False,
) -> None:
    """Print custody entries (read-only; does not add a record)."""
    try:
        case = Case(case_dir.resolve())
    except ForensiDVRError as exc:
        _fail(str(exc))
        return
    with case:
        entries = list(case.custody.entries())
    shown = entries[-tail:] if tail else entries
    if as_json:
        typer.echo(pretty_json([e.__dict__ for e in shown]), nl=False)
        return
    for e in shown:
        typer.echo(
            f"{e.seq:>5}  {e.timestamp_utc}  {e.actor:<16} {e.action:<28} "
            f"{json.dumps(e.details, sort_keys=True)[:100]}"
        )


# -- identify -------------------------------------------------------------------------------
def _print_identification(r: IdentificationResult) -> None:
    ch = f"{r.channel_count} (estimated from ids {r.channel_ids})" if r.channel_count else "unknown"
    typer.echo(f"status      {r.status.upper()}  confidence={r.confidence:.3f}")
    typer.echo(
        f"vendor      {r.vendor or '-'}   family: {r.vendor_family or '-'}   model: {r.model_family or '-'}"
    )
    typer.echo(
        f"firmware    {r.firmware or '-'}   fs version: {r.fs_version or '-'}   serial: {r.serial or '-'}"
    )
    typer.echo(f"channels    {ch}")
    typer.echo(f"fs plugin   {r.recommended_fs_plugin}")
    cands = ", ".join(f"{c.name}={c.score:.3f}" for c in r.family_candidates[:3]) or "-"
    typer.echo(f"candidates  {cands}")
    typer.echo(f"evidence    {len(r.signals)} signal(s), {r.bytes_scanned} of {r.image_size} bytes scanned")
    for w in r.warnings:
        typer.echo(f"  [{w.severity}] {w.code}: {w.message}")


@app.command("identify")
def identify_cmd(
    case_dir: CaseDir,
    evidence_id: Annotated[str, typer.Argument()],
    examiner: Examiner = None,
    as_json: AsJson = False,
) -> None:
    """Fingerprint vendor/family/model/firmware/channels (re-verifies evidence first; exits 2 on mismatch)."""
    from forensidvr.acquisition.workflow import identify_evidence

    with _open(case_dir, examiner, "identify") as case:
        try:
            result, out = identify_evidence(case, evidence_id)
        except EvidenceIntegrityError as exc:
            _fail(str(exc), code=2)
            return
        except ForensiDVRError as exc:
            _fail(str(exc))
            return
    if as_json:
        typer.echo(pretty_json(result), nl=False)
        return
    _print_identification(result)
    typer.echo(f"saved       {out.path}  sha256={out.sha256}")


# -- image ----------------------------------------------------------------------------------
@image_app.command("info")
def image_info(
    image: Annotated[Path, typer.Argument()],
    compute_hash: Annotated[bool, typer.Option("--hash", help="Also hash the media.")] = False,
) -> None:
    """Show container format, size and (for E01) embedded metadata."""
    from forensidvr.acquisition.readers import open_image
    from forensidvr.core.hashing import hash_source

    try:
        with open_image(image) as r:
            d = r.describe()
            if compute_hash:
                d["media_hashes"] = hash_source(r).to_dict()
    except (ForensiDVRError, OSError) as exc:
        _fail(str(exc))
        return
    typer.echo(pretty_json(d), nl=False)


@image_app.command("identify")
def image_identify(image: Annotated[Path, typer.Argument()], as_json: AsJson = False) -> None:
    """Preview identification of an image outside any case (read-only; nothing is logged)."""
    from forensidvr.acquisition.readers import open_image
    from forensidvr.identify import identify

    try:
        with open_image(image) as r:
            result = identify(r)
    except (ForensiDVRError, OSError) as exc:
        _fail(str(exc))
        return
    if as_json:
        typer.echo(pretty_json(result), nl=False)
    else:
        _print_identification(result)
        typer.echo(
            "note        preview only - not recorded in any case; use `forensidvr identify` for evidence"
        )


# -- plugins --------------------------------------------------------------------------------
@plugins_app.command("list")
def plugins_list() -> None:
    """List discovered file-system and format plugins."""
    from forensidvr.formats import discover_format_plugins
    from forensidvr.fs import discover_fs_plugins
    from forensidvr.identify import discover_identifiers

    for title, rep in (
        ("File-system plugins", discover_fs_plugins()),
        ("Format plugins", discover_format_plugins()),
        ("Identifier plugins", discover_identifiers()),
    ):
        typer.echo(f"{title}:")
        for p in rep.plugins:
            flag = " [EXPERIMENTAL]" if getattr(p, "experimental", False) else ""
            family = getattr(p, "vendor_family", getattr(p, "container", ""))
            pname, pver = getattr(p, "name", p.__name__), getattr(p, "version", "?")
            typer.echo(f"  {pname:<20} v{pver:<8} {family}{flag}")
        if not rep.plugins:
            typer.echo("  (none)")
        for mod, err in rep.failures.items():
            typer.echo(f"  FAILED {mod}: {err}")


if __name__ == "__main__":  # pragma: no cover
    app()
