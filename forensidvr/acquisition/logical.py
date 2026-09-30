"""Logical acquisition: import exported clips, configuration backups and logs when the disk
itself is unavailable (USB export, network download, vendor client export).

Each file is read read-only, copied with hash-on-the-fly, the copy is re-hashed, and a
deterministic manifest (sorted by relative path) is written. Files that cannot be read are
recorded and skipped; the import continues.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from forensidvr.core.errors import AcquisitionError
from forensidvr.core.hashing import HashSet, MultiHasher, hash_file
from forensidvr.core.jsonutil import pretty_json
from forensidvr.core.readonly import ReadOnlyFile
from forensidvr.core.timeutil import isoformat_utc

CATEGORIES: dict[str, tuple[str, ...]] = {
    "video": (
        ".mp4",
        ".dav",
        ".264",
        ".h264",
        ".265",
        ".h265",
        ".hevc",
        ".avi",
        ".mkv",
        ".ps",
        ".mov",
        ".ts",
        ".asf",
        ".sdv",
        ".grec",
        ".mpg",
    ),
    "image": (".jpg", ".jpeg", ".png", ".bmp"),
    "config": (".bin", ".cfg", ".conf", ".xml", ".ini", ".json", ".dat"),
    "log": (".log", ".txt", ".csv", ".evt"),
}
COPY_CHUNK = 4 * 1024 * 1024


def categorize(path: Path) -> str:
    ext = path.suffix.lower()
    for cat, exts in CATEGORIES.items():
        if ext in exts:
            return cat
    return "other"


@dataclass(frozen=True)
class LogicalFile:
    relative_path: str
    category: str
    size: int
    md5: str
    sha256: str
    source_mtime_utc: str
    source_mode: str
    verified: bool


@dataclass
class LogicalImportResult:
    source: str
    destination: str
    files: list[LogicalFile] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    manifest_path: str | None = None

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    @property
    def all_verified(self) -> bool:
        return all(f.verified for f in self.files)


def _copy_hashed(src: Path, dst: Path) -> HashSet:
    hasher = MultiHasher()
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o640)
    try:
        with ReadOnlyFile(src) as f:
            offset = 0
            while True:
                data = f.read_at(offset, COPY_CHUNK)
                if not data:
                    break
                hasher.update(data)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                offset += len(data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(dst, 0o444)
    return hasher.result()


def _walk(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    out: list[Path] = []
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs.sort()
        out.extend(Path(root) / f for f in files)
    return sorted(out, key=lambda p: p.relative_to(source).as_posix())


def import_logical(source: str | os.PathLike[str], dest_dir: str | os.PathLike[str]) -> LogicalImportResult:
    """Copy ``source`` (file or directory tree) into ``dest_dir`` with hashing and a manifest."""
    src = Path(source).resolve()
    dst = Path(dest_dir)
    if not src.exists():
        raise AcquisitionError(f"logical source {src} does not exist")
    if dst.exists() and any(dst.iterdir()):
        raise AcquisitionError(f"destination {dst} is not empty")
    dst.mkdir(parents=True, exist_ok=True)
    base = src.parent if src.is_file() else src
    result = LogicalImportResult(source=str(src), destination=str(dst))
    for path in _walk(src):
        rel = path.relative_to(base).as_posix()
        try:
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                result.skipped[rel] = f"symlink to {os.readlink(path)} (not followed)"
                continue
            if not stat.S_ISREG(st.st_mode):
                result.skipped[rel] = "not a regular file"
                continue
            copied = _copy_hashed(path, dst / "files" / rel)
            check = hash_file(dst / "files" / rel)
            from datetime import UTC, datetime

            result.files.append(
                LogicalFile(
                    relative_path=rel,
                    category=categorize(path),
                    size=copied.size,
                    md5=copied.md5,
                    sha256=copied.sha256,
                    source_mtime_utc=isoformat_utc(datetime.fromtimestamp(st.st_mtime, UTC)),
                    source_mode=stat.filemode(st.st_mode),
                    verified=check.matches(copied),
                )
            )
        except OSError as exc:
            result.skipped[rel] = f"{type(exc).__name__}: {exc.strerror or exc}"
    manifest = dst / "manifest.json"
    manifest.write_text(
        pretty_json(
            {
                "source": result.source,
                "files": result.files,
                "skipped": dict(sorted(result.skipped.items())),
                "total_bytes": result.total_bytes,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(manifest, 0o444)
    result.manifest_path = str(manifest)
    return result
