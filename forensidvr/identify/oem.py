"""Loader for the OEM signature / rebrand table (``oem_signatures.json``)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any


@dataclass(frozen=True)
class VendorSignature:
    vendor: str
    families: dict[str, float]
    weight: float
    patterns: tuple[re.Pattern[str], ...]
    models: tuple[re.Pattern[str], ...] = ()
    unverified: bool = False
    note: str = ""


@dataclass(frozen=True)
class OemTable:
    families: dict[str, dict[str, Any]]
    vendors: tuple[VendorSignature, ...] = field(default_factory=tuple)

    def vendor(self, name: str) -> VendorSignature | None:
        return next((v for v in self.vendors if v.vendor == name), None)

    def default_vendor(self, family: str) -> str | None:
        return self.families.get(family, {}).get("default_vendor")

    def fs_plugin(self, family: str) -> str | None:
        return self.families.get(family, {}).get("fs_plugin")


def parse_table(data: dict[str, Any]) -> OemTable:
    vendors = []
    for v in data.get("vendors", []):
        vendors.append(
            VendorSignature(
                vendor=v["vendor"],
                families={k: float(x) for k, x in v.get("families", {}).items()},
                weight=float(v.get("weight", 0.5)),
                patterns=tuple(re.compile(p, re.IGNORECASE) for p in v.get("patterns", [])),
                models=tuple(re.compile(m["regex"]) for m in v.get("models", [])),
                unverified=bool(v.get("unverified", False)),
                note=v.get("note", ""),
            )
        )
    return OemTable(families=dict(data.get("families", {})), vendors=tuple(vendors))


@lru_cache(maxsize=1)
def load_table() -> OemTable:
    text = resources.files("forensidvr.identify").joinpath("oem_signatures.json").read_text("utf-8")
    return parse_table(json.loads(text))
