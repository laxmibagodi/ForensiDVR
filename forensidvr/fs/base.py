"""File-system plugin interface. One plugin per vendor *family* (e.g. Hikvision-style HIKBTREE,
Dahua-style); OEM rebrands are mapped to families by the identification engine, not by
duplicating parsers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import ClassVar

from forensidvr.core.io import ByteSource
from forensidvr.core.models import (
    IndexEntry,
    MountInfo,
    ProbeResult,
    Recording,
    SourceRef,
    UnallocatedRegion,
)


class FSPlugin(ABC):
    """Parses a DVR/NVR storage volume.

    Contract:
      * Never write to ``image`` (it is a read-only :class:`ByteSource`).
      * Never raise on corrupt/unknown structures after :meth:`mount` succeeds: record a
        :class:`~forensidvr.core.models.PluginWarning` on the affected finding and continue.
      * Deterministic: iteration order depends only on image contents.
    """

    #: Unique machine name, e.g. ``"hikvision-btree"``.
    name: ClassVar[str]
    #: Semantic version of the parser; recorded in every finding and report.
    version: ClassVar[str]
    #: Family label, e.g. ``"hikvision"``.
    vendor_family: ClassVar[str]
    #: Vendors/brands known to use this family (informational; identification decides).
    vendors: ClassVar[tuple[str, ...]] = ()
    #: True when the layout is heuristic / not backed by citable documentation.
    experimental: ClassVar[bool] = True

    def __init__(self) -> None:
        self._image: ByteSource | None = None

    @property
    def image(self) -> ByteSource:
        if self._image is None:
            raise RuntimeError(f"{self.name}: mount() has not been called")
        return self._image

    @classmethod
    @abstractmethod
    def probe(cls, image: ByteSource) -> ProbeResult:
        """Cheap check (a few reads): how confident is this plugin that it can parse ``image``?

        Must not raise for any input; return confidence 0.0 instead.
        """

    @abstractmethod
    def mount(self, image: ByteSource) -> MountInfo:
        """Read superblock/volume headers and prepare for enumeration.

        May raise :class:`~forensidvr.core.errors.ImageFormatError` if the volume is unusable.
        """

    @abstractmethod
    def list_recordings(self) -> Iterator[Recording]:
        """Recordings referenced by the live index, in on-disk order."""

    @abstractmethod
    def read_index(self) -> Iterator[IndexEntry]:
        """Every raw index/record-table entry, including unallocated/stale slots."""

    @abstractmethod
    def iter_unallocated(self) -> Iterator[UnallocatedRegion]:
        """Byte ranges not referenced by any live recording (input for carving)."""

    def read_extent(self, ref: SourceRef) -> bytes:
        """Read the bytes behind a :class:`SourceRef` from the mounted image."""
        return self.image.read_at(ref.offset, ref.length)
