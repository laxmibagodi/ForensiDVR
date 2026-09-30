"""Fallback plugin for unknown devices: no file-system knowledge, whole image is carvable."""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from forensidvr.core.io import ByteSource
from forensidvr.core.models import (
    IndexEntry,
    MountInfo,
    PluginWarning,
    ProbeResult,
    Recording,
    SourceRef,
    UnallocatedRegion,
)
from forensidvr.fs.base import FSPlugin

UNALLOCATED_CHUNK = 256 * 1024 * 1024


class GenericCarveFS(FSPlugin):
    """ "Unknown - attempt generic carving": exposes the entire image as unallocated space."""

    name: ClassVar[str] = "generic-carve"
    version: ClassVar[str] = "0.1.0"
    vendor_family: ClassVar[str] = "unknown"
    experimental: ClassVar[bool] = False

    @classmethod
    def probe(cls, image: ByteSource) -> ProbeResult:
        return ProbeResult(
            plugin=cls.name,
            confidence=0.01,
            reasons=("fallback: always applicable, lowest priority",),
        )

    def mount(self, image: ByteSource) -> MountInfo:
        self._image = image
        return MountInfo(
            vendor_family=self.vendor_family,
            fs_name="none",
            confidence=0.01,
            plugin=self.name,
            plugin_version=self.version,
            sources=[SourceRef(0, image.size)],
            warnings=[
                PluginWarning(
                    code="UNKNOWN_FS",
                    message="no file-system plugin matched; only signature carving is possible",
                )
            ],
        )

    def list_recordings(self) -> Iterator[Recording]:
        return iter(())

    def read_index(self) -> Iterator[IndexEntry]:
        return iter(())

    def iter_unallocated(self) -> Iterator[UnallocatedRegion]:
        size = self.image.size
        for offset in range(0, size, UNALLOCATED_CHUNK):
            length = min(UNALLOCATED_CHUNK, size - offset)
            yield UnallocatedRegion(
                offset=offset,
                length=length,
                sources=[SourceRef(offset, length)],
                confidence=1.0,
                plugin=self.name,
                plugin_version=self.version,
            )
