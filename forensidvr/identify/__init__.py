"""Device / vendor / model / firmware fingerprinting (auto-discovered identifier plugins)."""

from forensidvr.identify.engine import IdentificationResult, discover_identifiers, identify

__all__ = ["IdentificationResult", "discover_identifiers", "identify"]
