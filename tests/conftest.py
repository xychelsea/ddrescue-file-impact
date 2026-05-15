"""Shared fixtures for exfat_impacted tests."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).parent / "fixtures"


def _utf16_name(name: str) -> bytes:
    return name.encode("utf-16le")


def build_minimal_exfat() -> bytes:
    """
    Build a tiny exFAT image with one file (README.TXT) in the root directory.

    Geometry: 512 bytes/sector, 64 sectors/cluster (32 KiB clusters).
    Cluster heap at sector 32 (offset 0x4000); root = cluster 2; file data = cluster 3.
    """
    bytes_per_sector = 512
    sectors_per_cluster = 64
    cluster_size = bytes_per_sector * sectors_per_cluster
    fat_offset_sectors = 24
    fat_length_sectors = 8
    cluster_heap_offset_sectors = 32
    cluster_count = 16
    root_cluster = 2

    image_size = cluster_heap_offset_sectors * bytes_per_sector + cluster_count * cluster_size
    img = bytearray(image_size)

    # Boot sector
    bs = bytearray(512)
    bs[3:11] = b"EXFAT   "
    struct.pack_into("<I", bs, 0x50, fat_offset_sectors)
    struct.pack_into("<I", bs, 0x54, fat_length_sectors)
    struct.pack_into("<I", bs, 0x58, cluster_heap_offset_sectors)
    struct.pack_into("<I", bs, 0x5C, cluster_count)
    struct.pack_into("<I", bs, 0x60, root_cluster)
    bs[0x6C] = 9  # 512-byte sectors
    bs[0x6D] = 6  # 64 sectors per cluster
    bs[510] = 0x55
    bs[511] = 0xAA
    img[0:512] = bs

    # FAT: mark cluster 2 (root) as end-of-chain
    fat_offset = fat_offset_sectors * bytes_per_sector
    struct.pack_into("<I", img, fat_offset + root_cluster * 4, 0xFFFFFFFF)

    # Root directory (cluster 2): README.TXT
    heap = cluster_heap_offset_sectors * bytes_per_sector
    root_off = heap  # cluster 2

    entry85 = bytearray(32)
    entry85[0] = 0x85
    entry85[1] = 2  # two secondary entries
    struct.pack_into("<H", entry85, 4, 0x0020)  # archive file

    entry_c0 = bytearray(32)
    entry_c0[0] = 0xC0
    entry_c0[1] = 0x02  # no FAT chain (contiguous)
    struct.pack_into("<I", entry_c0, 20, 3)  # first cluster
    struct.pack_into("<Q", entry_c0, 24, 11)  # data length

    entry_c1 = bytearray(32)
    entry_c1[0] = 0xC1
    name_bytes = _utf16_name("README.TXT")
    entry_c1[2 : 2 + len(name_bytes)] = name_bytes

    end_entry = bytearray(32)  # 0x00 type terminates listing

    img[root_off : root_off + 32] = entry85
    img[root_off + 32 : root_off + 64] = entry_c0
    img[root_off + 64 : root_off + 96] = entry_c1
    img[root_off + 96 : root_off + 128] = end_entry

    return bytes(img)


@pytest.fixture(scope="session")
def minimal_exfat_path(tmp_path_factory) -> Path:
    path = FIXTURES / "minimal.exfat"
    if not path.exists():
        path.write_bytes(build_minimal_exfat())
    return path


@pytest.fixture
def sample_map_path() -> Path:
    return FIXTURES / "sample.map"
