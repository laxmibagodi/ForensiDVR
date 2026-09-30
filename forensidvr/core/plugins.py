"""Plugin auto-discovery.

Built-in plugins live in ``forensidvr.fs`` and ``forensidvr.formats`` and are found by scanning
those packages. Third-party plugins register ``importlib.metadata`` entry points in the groups
``forensidvr.fs`` / ``forensidvr.formats``. Adding a vendor never touches core code.

A plugin that fails to import is logged and skipped (requirement #7).
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from types import ModuleType
from typing import TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T", bound=type)


@dataclass
class DiscoveryReport:
    """Plugins found plus modules that failed to load."""

    plugins: list[type] = field(default_factory=list)
    failures: dict[str, str] = field(default_factory=dict)


def _iter_modules(package: ModuleType) -> list[str]:
    path = getattr(package, "__path__", None)
    if path is None:
        return []
    return sorted(m.name for m in pkgutil.walk_packages(path, prefix=package.__name__ + "."))


def discover(base: T, packages: list[str], entry_point_group: str | None = None) -> DiscoveryReport:
    """Import ``packages`` recursively plus entry points and return concrete subclasses of ``base``.

    Result order is deterministic (sorted by plugin ``name`` then qualified class name).
    """
    report = DiscoveryReport()
    modules: list[str] = []
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except Exception as exc:
            report.failures[pkg_name] = f"{type(exc).__name__}: {exc}"
            log.warning("plugin package %s failed to import: %s", pkg_name, exc)
            continue
        modules.append(pkg_name)
        modules.extend(_iter_modules(pkg))

    loaded: list[ModuleType] = []
    for mod_name in modules:
        try:
            loaded.append(importlib.import_module(mod_name))
        except Exception as exc:
            report.failures[mod_name] = f"{type(exc).__name__}: {exc}"
            log.warning("plugin module %s failed to import: %s", mod_name, exc)

    found: dict[str, type] = {}
    for mod in loaded:
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, base) and obj is not base and not inspect.isabstract(obj):
                found[f"{obj.__module__}.{obj.__qualname__}"] = obj

    if entry_point_group:
        for ep in entry_points(group=entry_point_group):
            try:
                obj = ep.load()
            except Exception as exc:
                report.failures[f"entrypoint:{ep.name}"] = f"{type(exc).__name__}: {exc}"
                log.warning("entry point %s failed to load: %s", ep.name, exc)
                continue
            if inspect.isclass(obj) and issubclass(obj, base) and not inspect.isabstract(obj):
                found[f"{obj.__module__}.{obj.__qualname__}"] = obj
            else:
                report.failures[f"entrypoint:{ep.name}"] = f"not a concrete {base.__name__}"

    report.plugins = sorted(
        found.values(),
        key=lambda c: (str(getattr(c, "name", "")), f"{c.__module__}.{c.__qualname__}"),
    )
    return report
