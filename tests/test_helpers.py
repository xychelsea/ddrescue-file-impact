"""Tests for helper functions."""

from __future__ import annotations

from exfat_impacted import chain_to_ranges, cluster_overlaps_ranges, decode_name


def test_chain_to_ranges_contiguous() -> None:
    assert chain_to_ranges([5, 6, 7, 10, 11]) == [(5, 7), (10, 11)]


def test_chain_to_ranges_empty() -> None:
    assert chain_to_ranges([]) == []


def test_cluster_overlaps_ranges() -> None:
    assert cluster_overlaps_ranges(6, [(5, 7), (10, 11)])
    assert not cluster_overlaps_ranges(8, [(5, 7), (10, 11)])


def test_decode_name() -> None:
    entry_c1 = bytearray(32)
    entry_c1[0] = 0xC1
    name = "README.TXT".encode("utf-16le")
    entry_c1[2 : 2 + len(name)] = name
    assert decode_name([bytes(entry_c1)]) == "README.TXT"


def test_decode_name_empty() -> None:
    assert decode_name([]) is None
