"""Case-aware acquisition workflows: every step is hashed, registered and custody-logged."""

from __future__ import annotations

import os
import re
from pathlib import Path

from forensidvr.acquisition.imager import AcquisitionResult, ProgressCallback, acquire_raw
from forensidvr.acquisition.logical import LogicalImportResult, import_logical
from forensidvr.acquisition.readers import open_image
from forensidvr.core.case import Case, EvidenceRecord
from forensidvr.core.errors import AcquisitionError
from forensidvr.core.hashing import hash_bytes, hash_source
from forensidvr.core.io import ByteSource


def _slug(label: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("._")
    return s or "evidence"


def acquire_to_case(
    case: Case,
    source: str | os.PathLike[str] | ByteSource,
    *,
    label: str,
    block_size: int = 1024 * 1024,
    sector_size: int = 512,
    retries: int = 2,
    split_size: int | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[AcquisitionResult, EvidenceRecord | None]:
    """Physically image ``source`` into ``<case>/evidence``; register image, log and reports.

    Evidence is registered only if the verification pass succeeds.
    """
    name = _slug(label)
    dest = case.root / "evidence" / f"{name}.dd"
    log_path = case.root / "logs" / f"acquisition-{name}.jsonl"
    if dest.exists() or log_path.exists():
        raise AcquisitionError(f"evidence named {name!r} already exists in this case")
    src_desc = str(Path(source).resolve()) if isinstance(source, str | os.PathLike) else repr(source)
    case.log(
        "acquisition.start",
        {
            "source": src_desc,
            "destination": case.rel(dest),
            "block_size": block_size,
            "split_size": split_size,
        },
    )
    result = acquire_raw(
        source,
        dest,
        block_size=block_size,
        sector_size=sector_size,
        retries=retries,
        split_size=split_size,
        log_path=log_path,
        report_dir=case.root / "reports",
        clock=case._clock,
        progress=progress,
    )
    record = None
    if result.verified:
        record = case.add_evidence(
            result.destination[0],
            label=label,
            kind="disk_image",
            format=result.format,
            hashes=result.acquisition_hashes,
            source_description=src_desc,
            acquisition_id=result.acquisition_id,
        )
    for path, kind in (
        (result.log_path, "acquisition-log"),
        (result.report_json, "acquisition-report-json"),
        (result.report_md, "acquisition-report-md"),
    ):
        if path:
            case.register_output(
                path,
                kind=kind,
                produced_by="acquisition.imager",
                evidence_id=record.id if record else None,
            )
    case.record_acquisition(
        acquisition_id=result.acquisition_id,
        evidence_id=record.id if record else None,
        method="physical-raw",
        source=src_desc,
        started_utc=result.started_utc,
        finished_utc=result.finished_utc,
        hashes=result.acquisition_hashes,
        verified=result.verified,
        bad_sector_count=len(result.bad_sectors),
        report_path=case.rel(result.report_json) if result.report_json else None,
    )
    case.log(
        "acquisition.finish",
        {
            "acquisition_id": result.acquisition_id,
            "verified": result.verified,
            "hashes": result.acquisition_hashes.to_dict(),
            "bad_sector_ranges": len(result.bad_sectors),
            "warnings": result.warnings,
        },
    )
    return result, record


def register_existing_image(case: Case, path: str | os.PathLike[str], *, label: str) -> EvidenceRecord:
    """Register an image acquired elsewhere (raw/split/E01) in place, hashing its media content.

    For E01 the media hash is compared against the MD5 stored inside the container.
    """
    p = Path(path).resolve()
    case.log("evidence.hash.start", {"path": str(p)})
    with open_image(p) as reader:
        hashes = hash_source(reader)
        desc = reader.describe()
        fmt = reader.format_name
    notes = None
    ewf = desc.get("ewf")
    if ewf:
        stored = ewf.get("stored_md5")
        match = stored == hashes.md5 if stored else None
        notes = f"E01 stored MD5 {stored} {'matches' if match else 'DOES NOT MATCH' if stored else 'absent'}"
        case.log(
            "evidence.e01.stored_hash_check",
            {
                "path": str(p),
                "stored_md5": stored,
                "computed_md5": hashes.md5,
                "match": match,
                "warnings": ewf.get("warnings", []),
            },
        )
    return case.add_evidence(
        p,
        label=label,
        kind="disk_image",
        format=fmt,
        hashes=hashes,
        source_description=f"pre-existing {fmt} image",
        notes=notes,
    )


def import_logical_to_case(
    case: Case, source: str | os.PathLike[str], *, label: str
) -> tuple[LogicalImportResult, EvidenceRecord]:
    """Logical acquisition into ``<case>/evidence/<label>/``; the manifest becomes the evidence item."""
    dest = case.root / "evidence" / _slug(label)
    case.log("logical.start", {"source": str(Path(source).resolve()), "destination": case.rel(dest)})
    result = import_logical(source, dest)
    assert result.manifest_path is not None
    manifest = Path(result.manifest_path)
    record = case.add_evidence(
        manifest,
        label=label,
        kind="logical",
        format="logical-manifest",
        hashes=hash_bytes(manifest.read_bytes()),
        source_description=result.source,
        notes=f"{len(result.files)} files, {result.total_bytes} bytes, {len(result.skipped)} skipped",
    )
    case.log(
        "logical.finish",
        {
            "evidence_id": record.id,
            "files": len(result.files),
            "bytes": result.total_bytes,
            "all_verified": result.all_verified,
            "skipped": result.skipped,
            "file_hashes": [{"path": f.relative_path, "sha256": f.sha256} for f in result.files],
        },
    )
    return result, record
