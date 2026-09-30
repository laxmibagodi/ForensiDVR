"""Identification plugin interface: each plugin inspects a :class:`ScanContext` and emits signals."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from forensidvr.core.models import Finding

if TYPE_CHECKING:
    from forensidvr.identify.context import ScanContext


class SignalKind(enum.StrEnum):
    FS_SIGNATURE = "fs_signature"  # superblock / master-sector magic
    STRUCTURE = "structure"  # a secondary on-disk structure validated (index, log area)
    STREAM = "stream"  # vendor frame headers found in sampled data
    STRING = "string"  # vendor / model / firmware strings
    PARTITION = "partition"  # partition table facts (informational)


@dataclass(kw_only=True)
class Signal(Finding):
    """One piece of identification evidence. ``confidence`` is the signal's weight (0-1).

    ``facts`` may carry ``fs_version``, ``firmware``, ``model``, ``serial`` (str) and ``channels``
    (list of raw channel ids); the engine merges them into the final result.
    """

    kind: SignalKind
    description: str
    family: str | None = None
    vendor: str | None = None
    facts: dict[str, Any] = field(default_factory=dict)


class Identifier(ABC):
    """Base class for auto-discovered identification plugins.

    ``scan`` must be read-only, bounded (use ``ctx.read`` which enforces a byte budget) and must
    not raise for malformed data; the engine still guards every call.
    """

    name: ClassVar[str] = "unnamed"
    version: ClassVar[str] = "0.0.0"
    priority: ClassVar[int] = 50  # lower runs first; structure plugins may add regions for strings
    experimental: ClassVar[bool] = False

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Signal]:
        """Return zero or more signals."""

    def signal(self, **kwargs: Any) -> Signal:
        """Build a :class:`Signal` stamped with this plugin's name and version."""
        return Signal(plugin=self.name, plugin_version=self.version, **kwargs)
