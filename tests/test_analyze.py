"""Tests for analyze() and text formatting."""

from __future__ import annotations

from pathlib import Path

import pytest

from exfat_impacted import Exfat, ImageError, analyze, format_text


def test_exfat_context_manager_closes(minimal_exfat_path: Path) -> None:
    with Exfat(str(minimal_exfat_path)) as fs:
        assert fs.bytes_per_sector == 512
    assert fs.f.closed


def test_invalid_image_signature(tmp_path: Path) -> None:
    bad = tmp_path / "not_exfat.img"
    bad.write_bytes(b"\x00" * 512)
    with pytest.raises(ImageError, match="exFAT"):
        with Exfat(str(bad)):
            pass


def test_format_text_contains_sections(minimal_exfat_path: Path, sample_map_path: Path) -> None:
    result = analyze(str(minimal_exfat_path), str(sample_map_path))
    text = format_text(result)
    assert "exFAT geometry" in text
    assert "likely impacted files/directories" in text
    assert "/README.TXT" in text
