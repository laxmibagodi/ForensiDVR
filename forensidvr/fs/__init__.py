"""File-system plugins (auto-discovered). See :mod:`forensidvr.fs.base`."""

from __future__ import annotations

from forensidvr.core.plugins import DiscoveryReport, discover
from forensidvr.fs.base import FSPlugin


def discover_fs_plugins() -> DiscoveryReport:
    """All built-in and entry-point file-system plugins."""
    return discover(FSPlugin, ["forensidvr.fs"], entry_point_group="forensidvr.fs")
