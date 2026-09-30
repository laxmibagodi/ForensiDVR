"""Shared pytest fixtures."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forensidvr.core.case import Case
from tests.fixtures.images import write_pattern_image


@pytest.fixture
def fixed_clock() -> Callable[[], datetime]:
    """Deterministic clock: 2026-01-01T00:00:00Z advancing one second per call."""
    counter = itertools.count()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    return lambda: start + timedelta(seconds=next(counter))


@pytest.fixture
def image_path(tmp_path: Path) -> Path:
    """A 3 MiB + 512 B deterministic raw image."""
    return write_pattern_image(tmp_path / "source.dd", 3 * 1024 * 1024 + 512, seed=7)


@pytest.fixture
def case(tmp_path: Path, fixed_clock: Callable[[], datetime]) -> Case:
    c = Case.create(
        tmp_path / "case",
        name="Test Case",
        examiner="examiner1",
        case_number="SIH-001",
        agency="Test Lab",
        clock=fixed_clock,
    )
    yield c
    c.close()
