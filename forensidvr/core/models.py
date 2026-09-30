"""Shared result types returned by every plugin.

Every finding carries: source offsets (:class:`SourceRef`), the raw metadata it was decoded from,
a confidence score in ``[0, 1]``, and warnings. Timestamps keep their raw form alongside the
normalised UTC value (hard requirement #4).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _check_confidence(value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"confidence must be within [0, 1], got {value}")
    return float(value)


@dataclass(frozen=True)
class SourceRef:
    """A byte range in a named source (default: the evidence image)."""

    offset: int
    length: int
    source: str = "image"
    note: str = ""

    def __post_init__(self) -> None:
        if self.offset < 0 or self.length < 0:
            raise ValueError("offset and length must be non-negative")

    @property
    def end(self) -> int:
        return self.offset + self.length


class Severity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class PluginWarning:
    """Non-fatal problem encountered while parsing (requirement #7: log, skip, continue)."""

    code: str
    message: str
    offset: int | None = None
    severity: Severity = Severity.WARNING


@dataclass(kw_only=True)
class Finding:
    """Base for every plugin output."""

    sources: list[SourceRef] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    warnings: list[PluginWarning] = field(default_factory=list)
    plugin: str = ""
    plugin_version: str = ""

    def __post_init__(self) -> None:
        self.confidence = _check_confidence(self.confidence)


class TimeConfidence(enum.StrEnum):
    """How much the normalised UTC value can be trusted."""

    HIGH = "high"  # zone/offset known from device config; clock validated
    MEDIUM = "medium"  # zone inferred (e.g. from OSD vs index correlation)
    LOW = "low"  # zone assumed / clock drift suspected
    UNKNOWN = "unknown"  # raw value could not be interpreted


@dataclass(frozen=True)
class TimestampValue:
    """A device timestamp: raw value is always kept, UTC value is optional."""

    raw: str | int
    raw_encoding: str
    utc: datetime | None = None
    tz_name: str | None = None
    utc_offset_seconds: int | None = None
    confidence: TimeConfidence = TimeConfidence.UNKNOWN
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.utc is not None and self.utc.tzinfo is None:
            raise ValueError("TimestampValue.utc must be timezone-aware")


class EventType(enum.StrEnum):
    CONTINUOUS = "continuous"
    MOTION = "motion"
    ALARM = "alarm"
    MANUAL = "manual"
    SMART = "smart"  # line-crossing / intrusion / other IVS events
    UNKNOWN = "unknown"


class RecoveryStatus(enum.StrEnum):
    EXISTING = "EXISTING"
    RECOVERED_INDEXED = "RECOVERED-INDEXED"
    RECOVERED_CARVED = "RECOVERED-CARVED"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True)
class ProbeResult:
    """Answer to "is this image/stream mine?"."""

    plugin: str
    confidence: float
    reasons: tuple[str, ...] = ()
    warnings: tuple[PluginWarning, ...] = ()

    def __post_init__(self) -> None:
        _check_confidence(self.confidence)


@dataclass(kw_only=True)
class MountInfo(Finding):
    """File-system level facts established by :meth:`FSPlugin.mount`."""

    vendor_family: str
    fs_name: str
    block_size: int | None = None
    total_blocks: int | None = None
    channel_count: int | None = None
    firmware: str | None = None
    serial: str | None = None


@dataclass(kw_only=True)
class IndexEntry(Finding):
    """One raw record from an on-disk index/record table (live or stale)."""

    index_name: str
    slot: int
    allocated: bool
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass(kw_only=True)
class Recording(Finding):
    """A recording segment as described by the file-system index (or recovery)."""

    recording_id: str
    channel: int | None
    start: TimestampValue | None
    end: TimestampValue | None
    size: int
    event_type: EventType = EventType.UNKNOWN
    locked: bool | None = None
    overwritten: bool | None = None
    status: RecoveryStatus = RecoveryStatus.EXISTING
    container: str | None = None
    extents: list[SourceRef] = field(default_factory=list)


@dataclass(kw_only=True)
class UnallocatedRegion(Finding):
    """A byte range the file system considers free (input to recovery/carving)."""

    offset: int
    length: int


class FrameKind(enum.StrEnum):
    VIDEO_I = "video_i"
    VIDEO_P = "video_p"
    VIDEO_B = "video_b"
    AUDIO = "audio"
    METADATA = "metadata"
    UNKNOWN = "unknown"


@dataclass(kw_only=True)
class Frame(Finding):
    """One elementary frame located inside a container stream."""

    offset: int
    length: int
    kind: FrameKind
    codec: str | None = None
    channel: int | None = None
    timestamp: TimestampValue | None = None
    sequence: int | None = None


@dataclass(kw_only=True)
class MediaMetadata(Finding):
    """Stream-level metadata (codec, geometry, OSD/watermark text, device identifiers)."""

    container: str
    video_codec: str | None = None
    width: int | None = None
    height: int | None = None
    fps: float | None = None
    duration_seconds: float | None = None
    camera_name: str | None = None
    osd_text: list[str] = field(default_factory=list)
    device_serial: str | None = None


@dataclass(kw_only=True)
class ConversionResult(Finding):
    """Outcome of :meth:`FormatPlugin.to_standard_video`."""

    output_path: str
    method: str  # "remux" | "transcode"
    frames_written: int
    frames_skipped: int = 0
