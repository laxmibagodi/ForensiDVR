"""Container/format plugins (auto-discovered). See :mod:`forensidvr.formats.base`."""

from __future__ import annotations

from forensidvr.core.plugins import DiscoveryReport, discover
from forensidvr.formats.base import FormatPlugin


def discover_format_plugins() -> DiscoveryReport:
    """All built-in and entry-point format plugins."""
    return discover(FormatPlugin, ["forensidvr.formats"], entry_point_group="forensidvr.formats")
