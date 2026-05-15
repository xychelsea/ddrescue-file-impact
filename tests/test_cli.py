"""CLI and integration tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from exfat_impacted import ImageError, analyze, cli

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "exfat_impacted.py"


def test_analyze_minimal_fixture(minimal_exfat_path: Path, sample_map_path: Path) -> None:
    result = analyze(str(minimal_exfat_path), str(sample_map_path))
    assert result.geometry.cluster_size == 32768
    assert result.geometry.cluster_heap_offset == 0x4000
    assert result.warnings == []
    assert result.unresolved_by_status

    paths = {e.path for e in result.impacted}
    assert "/README.TXT" in paths

    readme = next(e for e in result.impacted if e.path == "/README.TXT")
    assert readme.kind == "file"
    assert 3 in readme.hit_clusters


def test_analyze_missing_image(sample_map_path: Path) -> None:
    with pytest.raises(ImageError, match="image not found"):
        analyze("/nonexistent/image.exfat", str(sample_map_path))


def test_cli_json_output(minimal_exfat_path: Path, sample_map_path: Path) -> None:
    code = cli([str(minimal_exfat_path), str(sample_map_path), "--json"])
    assert code == 0


def test_cli_json_stdout(minimal_exfat_path: Path, sample_map_path: Path, capsys) -> None:
    code = cli([str(minimal_exfat_path), str(sample_map_path), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "geometry" in data
    assert "impacted" in data
    assert any(e["path"] == "/README.TXT" for e in data["impacted"])


def test_cli_quiet_text(minimal_exfat_path: Path, sample_map_path: Path, capsys) -> None:
    code = cli([str(minimal_exfat_path), str(sample_map_path), "--quiet"])
    assert code == 0
    out = capsys.readouterr().out
    assert "exFAT geometry" not in out
    assert "likely impacted files/directories" in out


def test_cli_missing_args(capsys) -> None:
    code = cli([])
    assert code == 2


def test_cli_missing_image(sample_map_path: Path) -> None:
    code = cli(["/nonexistent/image.exfat", str(sample_map_path)])
    assert code == 1


def test_subprocess_help() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0
    assert "mapfile" in proc.stdout


def test_subprocess_json(minimal_exfat_path: Path, sample_map_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), str(minimal_exfat_path), str(sample_map_path), "--json"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["geometry"]["cluster_size"] == 32768


def test_warnings_all_finished_map(minimal_exfat_path: Path, tmp_path: Path, capsys) -> None:
    m = tmp_path / "all_good.map"
    m.write_text("0 999999 +\n")
    code = cli([str(minimal_exfat_path), str(m), "--json"])
    assert code == 0
    captured = capsys.readouterr()
    assert "warning:" in captured.err
    data = json.loads(captured.out)
    assert "warnings" in data
    assert any("no unresolved" in w for w in data["warnings"])
