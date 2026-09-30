"""Device identification engine: runs all identifier plugins and combines their signals.

Scoring (documented in docs/identification.md):

* family score = noisy-OR of signal weights ``1 - prod(1 - w)``; vendor-string signals contribute
  ``w * mapping_weight`` to each family the vendor is mapped to in ``oem_signatures.json``;
* vendor = best brand-string vendor compatible with the family, else the family's default vendor
  (flagged ``BRAND_NOT_FOUND``: may be an OEM rebrand);
* without a file-system signature (superblock / master sector) confidence is capped at 0.79;
* status = ``identified`` (>= 0.8), ``probable`` (>= 0.35) or ``unknown`` -> generic carving.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from forensidvr import __version__
from forensidvr.core.io import ByteSource
from forensidvr.core.models import Finding, PluginWarning, ProbeResult, Severity, SourceRef
from forensidvr.core.plugins import DiscoveryReport, discover
from forensidvr.identify.base import Identifier, Signal, SignalKind
from forensidvr.identify.context import ScanContext
from forensidvr.identify.oem import OemTable, load_table

log = logging.getLogger(__name__)

ENGINE_NAME = "identify-engine"
IDENTIFIED = 0.8
PROBABLE = 0.35
NO_FS_SIGNATURE_CAP = 0.79
FALLBACK_PLUGIN = "generic-carve"


@dataclass(frozen=True)
class Candidate:
    name: str
    score: float
    signals: int


@dataclass(kw_only=True)
class IdentificationResult(Finding):
    """Vendor / family / model / firmware / channel-count verdict with all supporting evidence."""

    status: str
    vendor: str | None = None
    vendor_family: str | None = None
    model_family: str | None = None
    firmware: str | None = None
    fs_version: str | None = None
    serial: str | None = None
    channel_count: int | None = None
    channel_ids: list[int] = field(default_factory=list)
    channel_count_estimated: bool = True
    family_candidates: list[Candidate] = field(default_factory=list)
    vendor_candidates: list[Candidate] = field(default_factory=list)
    signals: list[Signal] = field(default_factory=list)
    partitions: list[dict[str, Any]] = field(default_factory=list)
    fs_probes: list[ProbeResult] = field(default_factory=list)
    recommended_fs_plugin: str = FALLBACK_PLUGIN
    image_size: int = 0
    bytes_scanned: int = 0
    identifiers: list[str] = field(default_factory=list)


def discover_identifiers() -> DiscoveryReport:
    """All built-in and entry-point (``forensidvr.identify``) identification plugins."""
    return discover(Identifier, ["forensidvr.identify.signatures"], entry_point_group="forensidvr.identify")


def noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(1.0, w))
    return round(1.0 - p, 6)


def _ranked(scores: dict[str, list[float]]) -> list[Candidate]:
    cands = [Candidate(k, noisy_or(v), len(v)) for k, v in scores.items()]
    return sorted((c for c in cands if c.score > 0), key=lambda c: (-c.score, c.name))


def _pick_fact(signals: list[Signal], key: str, family: str | None, vendor: str | None) -> str | None:
    def rank(s: Signal) -> tuple[int, float, int]:
        consistent = (family is not None and s.family == family) or (
            vendor is not None and s.vendor == vendor
        )
        off = s.sources[0].offset if s.sources else 0
        return (0 if consistent else 1, -s.confidence, off)

    having = sorted((s for s in signals if s.facts.get(key)), key=rank)
    return str(having[0].facts[key]) if having else None


def identify(
    image: ByteSource,
    *,
    identifiers: list[type[Identifier]] | None = None,
    table: OemTable | None = None,
    probe_fs: bool = True,
    ctx: ScanContext | None = None,
) -> IdentificationResult:
    """Identify the device that wrote ``image``. Never raises for malformed content."""
    table = table or load_table()
    ctx = ctx or ScanContext(image)
    warnings: list[PluginWarning] = []
    if identifiers is None:
        report = discover_identifiers()
        identifiers = list(report.plugins)
        warnings += [
            PluginWarning("PLUGIN_LOAD_FAILED", f"{mod}: {err}", severity=Severity.ERROR)
            for mod, err in report.failures.items()
        ]
    ordered = sorted(identifiers, key=lambda c: (c.priority, c.name))

    signals: list[Signal] = []
    for cls in ordered:
        try:
            signals += cls().scan(ctx)
        except Exception as exc:  # requirement #7: a broken plugin never stops identification
            log.warning("identifier %s failed: %s", cls.name, exc)
            warnings.append(
                PluginWarning(
                    "IDENTIFIER_FAILED", f"{cls.name}: {type(exc).__name__}: {exc}", severity=Severity.ERROR
                )
            )
    signals.sort(
        key=lambda s: (s.sources[0].offset if s.sources else -1, s.plugin, s.kind.value, s.description)
    )

    fam_scores: dict[str, list[float]] = {}
    ven_scores: dict[str, list[float]] = {}
    for s in signals:
        if s.family:
            fam_scores.setdefault(s.family, []).append(s.confidence)
        if s.vendor:
            ven_scores.setdefault(s.vendor, []).append(s.confidence)
            sig = table.vendor(s.vendor)
            if sig is not None and s.kind is SignalKind.STRING:
                for fam, m in sig.families.items():
                    fam_scores.setdefault(fam, []).append(s.confidence * m)
    families = _ranked(fam_scores)
    vendors = _ranked(ven_scores)

    family = families[0].name if families and families[0].score >= PROBABLE else None
    fam_score = families[0].score if family else 0.0
    if len(families) > 1 and family and families[1].score >= PROBABLE and families[1].score > 0.8 * fam_score:
        warnings.append(
            PluginWarning(
                "AMBIGUOUS_FAMILY",
                f"{families[0].name}={fam_score} vs {families[1].name}={families[1].score}",
            )
        )

    vendor: str | None = None
    vendor_score = 0.0
    for c in vendors:
        sig = table.vendor(c.name)
        if (
            family is None
            or (sig is not None and family in sig.families)
            or c.name == table.default_vendor(family)
        ):
            vendor, vendor_score = c.name, c.score
            break
    if vendor is None and family is not None:
        vendor = table.default_vendor(family)
        warnings.append(
            PluginWarning(
                "BRAND_NOT_FOUND",
                f"no brand string found; reporting family default vendor {vendor!r} (may be an OEM rebrand)",
                severity=Severity.INFO,
            )
        )
    if vendor is not None and family is None:
        warnings.append(
            PluginWarning(
                "FAMILY_UNKNOWN",
                f"brand {vendor!r} found in strings but no supported file-system structure was recognised",
            )
        )

    confidence = fam_score if family else round(vendor_score * 0.5, 6)
    if family and not any(s.family == family and s.kind is SignalKind.FS_SIGNATURE for s in signals):
        confidence = min(confidence, NO_FS_SIGNATURE_CAP)
        warnings.append(
            PluginWarning(
                "NO_FS_SIGNATURE",
                f"{family} inferred from secondary evidence only (superblock/master sector missing/damaged)",
            )
        )
    status = "identified" if confidence >= IDENTIFIED else "probable" if confidence >= PROBABLE else "unknown"
    if status == "unknown":
        warnings.append(PluginWarning("UNKNOWN_DEVICE", "unknown - attempt generic carving"))

    channel_ids = sorted(
        {int(c) for s in signals if s.family in (family, None) for c in s.facts.get("channels", [])}
    )

    probes: list[ProbeResult] = []
    recommended = FALLBACK_PLUGIN
    if probe_fs:
        from forensidvr.fs import discover_fs_plugins

        for plugin in discover_fs_plugins().plugins:
            try:
                probes.append(plugin.probe(image))  # type: ignore[attr-defined]
            except Exception as exc:
                warnings.append(PluginWarning("FS_PROBE_FAILED", f"{plugin.__name__}: {exc}"))
        probes.sort(key=lambda p: (-p.confidence, p.plugin))
        hint = table.fs_plugin(family) if family else None
        names = {p.plugin for p in probes}
        if status != "unknown" and hint in names:
            recommended = hint or FALLBACK_PLUGIN
        elif probes and probes[0].confidence >= PROBABLE:
            recommended = probes[0].plugin
        if family and hint not in names:
            warnings.append(
                PluginWarning(
                    "NO_FS_PLUGIN",
                    f"family {family!r} recognised but its file-system plugin {hint!r} is not installed yet;"
                    f" falling back to {FALLBACK_PLUGIN}",
                    severity=Severity.INFO,
                )
            )

    partitions = [dict(s.raw_metadata) for s in signals if s.kind is SignalKind.PARTITION]
    sources = sorted(
        {(src.offset, src.length) for s in signals if s.family == family and family for src in s.sources}
    )
    return IdentificationResult(
        status=status,
        vendor=vendor,
        vendor_family=family,
        model_family=_pick_fact(signals, "model", family, vendor),
        firmware=_pick_fact(signals, "firmware", family, vendor),
        fs_version=_pick_fact(signals, "fs_version", family, vendor),
        serial=_pick_fact(signals, "serial", family, vendor),
        channel_count=len(channel_ids) or None,
        channel_ids=channel_ids,
        family_candidates=families,
        vendor_candidates=vendors,
        signals=signals,
        partitions=partitions,
        fs_probes=probes,
        recommended_fs_plugin=recommended,
        image_size=image.size,
        bytes_scanned=ctx.bytes_read,
        identifiers=[f"{c.name}@{c.version}" for c in ordered],
        confidence=confidence,
        warnings=[*ctx.warnings, *warnings],
        sources=[SourceRef(o, n) for o, n in sources],
        plugin=ENGINE_NAME,
        plugin_version=__version__,
    )
