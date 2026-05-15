"""Tests for ddrescue mapfile parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from exfat_impacted import MapfileError, parse_ddrescue_map

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_sample_map(sample_map_path: Path) -> None:
    result = parse_ddrescue_map(str(sample_map_path))
    assert len(result.ranges) == 3
    statuses = {r[2] for r in result.ranges}
    assert statuses == {"-", "?"}


def test_parse_hex_offsets(tmp_path: Path) -> None:
    m = tmp_path / "hex.map"
    m.write_text("0x1000 0x200 -\n")
    result = parse_ddrescue_map(str(m))
    assert result.ranges == [(0x1000, 0x1000 + 0x200, "-")]


def test_skip_comments_and_bad_lines(tmp_path: Path) -> None:
    m = tmp_path / "mixed.map"
    m.write_text(
        "# comment\n"
        "not valid\n"
        "0 4096 ?\n"
        "incomplete line\n"
    )
    result = parse_ddrescue_map(str(m))
    assert result.ranges == [(0, 4096, "?")]
    assert result.skipped_lines == 2
    assert result.total_data_lines == 1


def test_all_finished_map(tmp_path: Path) -> None:
    m = tmp_path / "good.map"
    m.write_text("0 4096 +\n10000 512 +\n")
    result = parse_ddrescue_map(str(m))
    assert result.ranges == []
    assert result.total_data_lines == 2


def test_missing_mapfile_raises() -> None:
    with pytest.raises(MapfileError, match="cannot open mapfile"):
        parse_ddrescue_map("/nonexistent/path/to.map")
