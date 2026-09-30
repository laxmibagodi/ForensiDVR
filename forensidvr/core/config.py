"""Runtime configuration (TOML file + environment overrides)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any

ENV_PREFIX = "FORENSIDVR_"


@dataclass(frozen=True)
class Config:
    """Tunable settings. Defaults are safe for forensic use."""

    examiner: str | None = None
    chunk_size: int = 4 * 1024 * 1024
    acquisition_block_size: int = 1024 * 1024
    sector_size: int = 512
    read_retries: int = 2
    redact_passwords: bool = True

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> Config:
        """Load from ``path`` (TOML, optional ``[forensidvr]`` table) then apply env overrides."""
        cfg = cls()
        values: dict[str, Any] = {}
        if path is not None and Path(path).exists():
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
            values.update(data.get("forensidvr", data))
        for f in fields(cls):
            env = os.environ.get(ENV_PREFIX + f.name.upper())
            if env is not None:
                values[f.name] = env
        typed: dict[str, Any] = {}
        for f in fields(cls):
            if f.name not in values:
                continue
            raw = values[f.name]
            default = getattr(cfg, f.name)
            if isinstance(default, bool):
                typed[f.name] = raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "yes")
            elif isinstance(default, int):
                typed[f.name] = int(raw)
            else:
                typed[f.name] = None if raw in ("", None) else str(raw)
        return replace(cfg, **typed)
