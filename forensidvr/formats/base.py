"""Container/codec plugin interface (proprietary DAV-style, PS-based, raw H.264/H.265, MP4)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from forensidvr.core.io import ByteSource
from forensidvr.core.models import ConversionResult, Frame, MediaMetadata, ProbeResult


class FormatPlugin(ABC):
    """Parses a recording byte stream (a recording's extents concatenated, or a carved region).

    Same contract as :class:`~forensidvr.fs.base.FSPlugin`: read-only input, no crash on corrupt
    frames (skip + warn), deterministic output.
    """

    name: ClassVar[str]
    version: ClassVar[str]
    #: Container label, e.g. ``"dav"``, ``"hik-ps"``, ``"h264-annexb"``.
    container: ClassVar[str]
    experimental: ClassVar[bool] = True

    @classmethod
    @abstractmethod
    def probe(cls, stream: ByteSource) -> ProbeResult:
        """Confidence that ``stream`` is in this container format. Must not raise."""

    @abstractmethod
    def parse_frames(self, stream: ByteSource) -> Iterator[Frame]:
        """Yield frames in stream order with offsets, kind, codec and embedded timestamps."""

    @abstractmethod
    def extract_metadata(self, stream: ByteSource) -> MediaMetadata:
        """Stream-level metadata: codec, geometry, OSD/watermark text, serials."""

    @abstractmethod
    def to_standard_video(
        self, stream: ByteSource, out_path: Path, *, remux_only: bool = True
    ) -> ConversionResult:
        """Write a standard MP4 (remux, no re-encode, unless ``remux_only`` is False).

        The caller keeps the original stream and hashes/registers ``out_path``.
        """
