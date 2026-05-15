#!/usr/bin/env python3
"""
Correlate GNU ddrescue unresolved byte ranges with exFAT file/directory extents.

Read-only, best-effort analysis of a partition image and its ddrescue mapfile.
Supports exFAT only; damaged directory metadata may yield incomplete paths.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field

EOC = 0xFFFFFFF8
MAX_DIR_ENTRIES_PER_CLUSTER = 256

STATUS_LABELS = {
    "-": "confirmed bad-sector",
    "/": "non-scraped",
    "*": "non-trimmed",
    "?": "non-tried",
}


# --- Exceptions ---


class DdrescueFileImpactError(Exception):
    """Base error for this tool."""


class UsageError(DdrescueFileImpactError):
    """Invalid command-line usage."""


class ImageError(DdrescueFileImpactError):
    """Partition image is missing, unreadable, or not a valid exFAT image."""


class MapfileError(DdrescueFileImpactError):
    """ddrescue mapfile is missing or unreadable."""


# --- Binary helpers ---


def u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def chain_to_ranges(chain: list[int]) -> list[tuple[int, int]]:
    if not chain:
        return []
    ranges: list[tuple[int, int]] = []
    start = prev = chain[0]
    for c in chain[1:]:
        if c == prev + 1:
            prev = c
        else:
            ranges.append((start, prev))
            start = prev = c
    ranges.append((start, prev))
    return ranges


def cluster_overlaps_ranges(cluster: int, ranges: list[tuple[int, int]]) -> bool:
    for a, b in ranges:
        if a <= cluster <= b:
            return True
    return False


# --- Mapfile parsing ---


@dataclass
class MapParseResult:
    """Unresolved ddrescue ranges and parse statistics."""

    ranges: list[tuple[int, int, str]]
    skipped_lines: int = 0
    total_data_lines: int = 0


def parse_ddrescue_map(path: str) -> MapParseResult:
    """
    Return unresolved ranges from a GNU ddrescue mapfile.

    Statuses:
      + finished/good
      - bad-sector
      / non-scraped
      * non-trimmed
      ? non-tried
    """
    ranges: list[tuple[int, int, str]] = []
    skipped_lines = 0
    total_data_lines = 0

    try:
        f = open(path, "r", errors="replace")
    except OSError as exc:
        raise MapfileError(f"cannot open mapfile {path!r}: {exc}") from exc

    with f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 3:
                skipped_lines += 1
                continue
            total_data_lines += 1
            try:
                pos = int(parts[0], 0)
                size = int(parts[1], 0)
                status = parts[2]
            except ValueError:
                skipped_lines += 1
                continue
            if status != "+":
                ranges.append((pos, pos + size, status))

    return MapParseResult(
        ranges=ranges,
        skipped_lines=skipped_lines,
        total_data_lines=total_data_lines,
    )


# --- exFAT image ---


class Exfat:
    """Read-only accessor for an exFAT partition image."""

    def __init__(self, imgpath: str) -> None:
        self.imgpath = imgpath
        try:
            self.f = open(imgpath, "rb")
        except OSError as exc:
            raise ImageError(f"cannot open image {imgpath!r}: {exc}") from exc

        try:
            bs = self.read_at(0, 512)
        except ImageError:
            self.f.close()
            raise

        if bs[3:11] != b"EXFAT   ":
            self.f.close()
            raise ImageError("This does not look like an exFAT partition image.")

        sector_shift = bs[0x6C]
        cluster_shift = bs[0x6D]
        if sector_shift > 31 or cluster_shift > 31:
            self.f.close()
            raise ImageError("invalid sector or cluster size shift in boot sector.")

        self.fat_offset_sectors = u32(bs, 0x50)
        self.fat_length_sectors = u32(bs, 0x54)
        self.cluster_heap_offset_sectors = u32(bs, 0x58)
        self.cluster_count = u32(bs, 0x5C)
        self.root_cluster = u32(bs, 0x60)
        self.bytes_per_sector = 1 << sector_shift
        self.sectors_per_cluster = 1 << cluster_shift
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        if self.cluster_size == 0:
            self.f.close()
            raise ImageError("cluster size is zero.")

        self.fat_offset = self.fat_offset_sectors * self.bytes_per_sector
        self.fat_length = self.fat_length_sectors * self.bytes_per_sector
        self.cluster_heap_offset = self.cluster_heap_offset_sectors * self.bytes_per_sector

    def __enter__(self) -> Exfat:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        if self.f and not self.f.closed:
            self.f.close()

    def read_at(self, off: int, size: int) -> bytes:
        self.f.seek(off)
        data = self.f.read(size)
        if len(data) < size:
            raise ImageError(
                f"short read at offset {off:#x}: expected {size} bytes, got {len(data)}"
            )
        return data

    def cluster_offset(self, cluster: int) -> int:
        return self.cluster_heap_offset + (cluster - 2) * self.cluster_size

    def offset_to_cluster(self, off: int) -> int | None:
        if off < self.cluster_heap_offset:
            return None
        n = (off - self.cluster_heap_offset) // self.cluster_size
        if n < 0 or n >= self.cluster_count:
            return None
        return 2 + n

    def fat_next(self, cluster: int) -> int:
        off = self.fat_offset + cluster * 4
        return u32(self.read_at(off, 4), 0)

    def cluster_chain(self, first_cluster: int, max_clusters: int | None = None) -> list[int]:
        if first_cluster < 2:
            return []
        seen: set[int] = set()
        chain: list[int] = []
        c = first_cluster
        limit = max_clusters or (self.cluster_count + 2)
        while 2 <= c < EOC and c not in seen and len(chain) < limit:
            seen.add(c)
            chain.append(c)
            nxt = self.fat_next(c)
            if nxt >= EOC or nxt == 0:
                break
            c = nxt
        return chain

    def contiguous_chain(self, first_cluster: int, data_len: int) -> list[int]:
        if first_cluster < 2 or data_len == 0:
            return []
        count = math.ceil(data_len / self.cluster_size)
        return list(range(first_cluster, first_cluster + count))

    def read_clusters(self, clusters: list[int], max_bytes: int | None = None) -> bytes:
        chunks: list[bytes] = []
        remaining = max_bytes
        for c in clusters:
            size = self.cluster_size if remaining is None else min(self.cluster_size, remaining)
            if size <= 0:
                break
            chunks.append(self.read_at(self.cluster_offset(c), size))
            if remaining is not None:
                remaining -= size
        return b"".join(chunks)


# --- Filesystem walk ---


def decode_name(entries: list[bytes]) -> str | None:
    chars: list[bytes] = []
    for e in entries:
        if e[0] == 0xC1:
            raw = e[2:32]
            for i in range(0, len(raw), 2):
                ch = raw[i : i + 2]
                if ch == b"\x00\x00":
                    continue
                chars.append(ch)
    if not chars:
        return None
    return b"".join(chars).decode("utf-16le", errors="replace")


def parse_directory(
    fs: Exfat,
    clusters: list[int],
    path: str,
    files: list[dict],
    dirs_seen: set[int],
) -> None:
    data = fs.read_clusters(clusters)
    entries = [data[i : i + 32] for i in range(0, len(data) - 31, 32)]
    if len(entries) > MAX_DIR_ENTRIES_PER_CLUSTER:
        entries = entries[:MAX_DIR_ENTRIES_PER_CLUSTER]

    i = 0
    while i < len(entries):
        e = entries[i]
        etype = e[0]

        if etype == 0x00:
            break

        if etype == 0x85:
            secondary_count = e[1]
            group_end = i + 1 + secondary_count
            if group_end > len(entries):
                i += 1
                continue

            attrs = u16(e, 4)
            group = entries[i:group_end]

            stream = None
            name_entries: list[bytes] = []
            for ge in group[1:]:
                if ge[0] == 0xC0:
                    stream = ge
                elif ge[0] == 0xC1:
                    name_entries.append(ge)

            name = decode_name(name_entries)
            if stream and name:
                flags = stream[1]
                no_fat_chain = bool(flags & 0x02)
                first_cluster = u32(stream, 20)
                data_len = u64(stream, 24)
                is_dir = bool(attrs & 0x10)

                fullpath = path.rstrip("/") + "/" + name if path != "/" else "/" + name

                if data_len == 0 or first_cluster < 2:
                    chain: list[int] = []
                elif no_fat_chain:
                    chain = fs.contiguous_chain(first_cluster, data_len)
                else:
                    maxc = math.ceil(data_len / fs.cluster_size) if data_len else None
                    chain = fs.cluster_chain(first_cluster, maxc)

                files.append(
                    {
                        "path": fullpath,
                        "is_dir": is_dir,
                        "first_cluster": first_cluster,
                        "data_len": data_len,
                        "clusters": chain,
                        "ranges": chain_to_ranges(chain),
                        "no_fat_chain": no_fat_chain,
                    }
                )

                if is_dir and chain and first_cluster not in dirs_seen:
                    dirs_seen.add(first_cluster)
                    parse_directory(fs, chain, fullpath, files, dirs_seen)

            i += 1 + secondary_count
        else:
            i += 1


# --- Analysis result ---


@dataclass
class Geometry:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    cluster_heap_offset: int
    fat_offset: int
    fat_length: int
    root_cluster: int


@dataclass
class MetadataHit:
    start: int
    end: int
    status: str
    reason: str


@dataclass
class ImpactedEntry:
    path: str
    kind: str
    size: int
    first_cluster: int
    hit_clusters: list[int]


@dataclass
class Result:
    geometry: Geometry
    unresolved_by_status: dict[str, int]
    metadata_hits: list[MetadataHit]
    impacted: list[ImpactedEntry]
    warnings: list[str] = field(default_factory=list)


def _check_path(path: str, label: str) -> None:
    if not os.path.isfile(path):
        raise (ImageError if label == "image" else MapfileError)(
            f"{label} not found or not a file: {path!r}"
        )


def _build_warnings(map_result: MapParseResult) -> list[str]:
    warnings: list[str] = []
    if map_result.skipped_lines:
        warnings.append(f"skipped {map_result.skipped_lines} malformed mapfile line(s)")
    if not map_result.ranges:
        if map_result.total_data_lines == 0:
            warnings.append("mapfile contains no data lines")
        else:
            warnings.append("mapfile has no unresolved ranges (all regions marked +)")
    return warnings


def analyze(image: str, mapfile: str) -> Result:
    """
    Correlate ddrescue unresolved ranges with exFAT file extents.

    Raises ImageError or MapfileError on missing/invalid inputs.
    """
    _check_path(image, "image")
    _check_path(mapfile, "mapfile")

    map_result = parse_ddrescue_map(mapfile)
    warnings = _build_warnings(map_result)

    with Exfat(image) as fs:
        geometry = Geometry(
            bytes_per_sector=fs.bytes_per_sector,
            sectors_per_cluster=fs.sectors_per_cluster,
            cluster_size=fs.cluster_size,
            cluster_heap_offset=fs.cluster_heap_offset,
            fat_offset=fs.fat_offset,
            fat_length=fs.fat_length,
            root_cluster=fs.root_cluster,
        )

        impacted_clusters_by_status: dict[str, set[int]] = defaultdict(set)
        metadata_hits: list[MetadataHit] = []

        for start, end, status in map_result.ranges:
            if end <= fs.cluster_heap_offset:
                metadata_hits.append(
                    MetadataHit(
                        start=start,
                        end=end,
                        status=status,
                        reason="before cluster heap: boot/FAT/metadata area",
                    )
                )
                continue

            c1 = fs.offset_to_cluster(start)
            c2 = fs.offset_to_cluster(end - 1)

            if c1 is None or c2 is None:
                metadata_hits.append(
                    MetadataHit(
                        start=start,
                        end=end,
                        status=status,
                        reason="outside known cluster heap",
                    )
                )
                continue

            for c in range(c1, c2 + 1):
                impacted_clusters_by_status[status].add(c)

        impacted_clusters: set[int] = set()
        for clusters in impacted_clusters_by_status.values():
            impacted_clusters |= clusters

        root_chain = fs.cluster_chain(fs.root_cluster)
        files: list[dict] = []
        parse_directory(fs, root_chain, "/", files, {fs.root_cluster})

        impacted: list[ImpactedEntry] = []
        for rec in files:
            if not rec["clusters"]:
                continue
            hits = sorted(
                c for c in impacted_clusters if cluster_overlaps_ranges(c, rec["ranges"])
            )
            if hits:
                impacted.append(
                    ImpactedEntry(
                        path=rec["path"],
                        kind="dir" if rec["is_dir"] else "file",
                        size=rec["data_len"],
                        first_cluster=rec["first_cluster"],
                        hit_clusters=hits,
                    )
                )

        impacted.sort(key=lambda e: e.path)

        return Result(
            geometry=geometry,
            unresolved_by_status={
                s: len(clusters) for s, clusters in sorted(impacted_clusters_by_status.items())
            },
            metadata_hits=metadata_hits,
            impacted=impacted,
            warnings=warnings,
        )


# --- Output formatting ---


def format_text(result: Result, quiet: bool = False) -> str:
    lines: list[str] = []
    g = result.geometry

    if not quiet:
        lines.extend(
            [
                "exFAT geometry",
                f"  bytes_per_sector:      {g.bytes_per_sector}",
                f"  sectors_per_cluster:   {g.sectors_per_cluster}",
                f"  cluster_size:          {g.cluster_size}",
                f"  cluster_heap_offset:   {g.cluster_heap_offset}",
                f"  FAT offset:            {g.fat_offset}",
                f"  FAT length:            {g.fat_length}",
                f"  root cluster:          {g.root_cluster}",
                "",
            ]
        )

    if not quiet:
        lines.append("unresolved ddrescue areas")
        if result.unresolved_by_status:
            for status, count in sorted(result.unresolved_by_status.items()):
                label = STATUS_LABELS.get(status, status)
                lines.append(f"  {status} {label}: {count} clusters")
        else:
            lines.append("  (none in cluster heap)")
        lines.append("")

    if result.metadata_hits:
        lines.append("metadata / non-file-area hits")
        for hit in result.metadata_hits[:100]:
            lines.append(f"  {hit.status} {hit.start:#x}-{hit.end - 1:#x}  {hit.reason}")
        if len(result.metadata_hits) > 100:
            lines.append(f"  ... {len(result.metadata_hits) - 100} more")
        lines.append("")

    lines.append("likely impacted files/directories")
    if not result.impacted:
        lines.append("  none found from allocated file extents")
    else:
        for entry in result.impacted:
            kind = "DIR " if entry.kind == "dir" else "FILE"
            lines.append(f"{kind} {entry.path}")
            lines.append(
                f"     size={entry.size} first_cluster={entry.first_cluster} "
                f"hit_clusters={len(entry.hit_clusters)}"
            )
            shown = ",".join(map(str, entry.hit_clusters[:20]))
            lines.append(f"     first_hit_clusters={shown}")
            if len(entry.hit_clusters) > 20:
                lines.append(f"     ... {len(entry.hit_clusters) - 20} more")
    lines.append("")

    return "\n".join(lines)


def format_json(result: Result) -> str:
    payload = {
        "geometry": {
            "bytes_per_sector": result.geometry.bytes_per_sector,
            "sectors_per_cluster": result.geometry.sectors_per_cluster,
            "cluster_size": result.geometry.cluster_size,
            "cluster_heap_offset": result.geometry.cluster_heap_offset,
            "fat_offset": result.geometry.fat_offset,
            "fat_length": result.geometry.fat_length,
            "root_cluster": result.geometry.root_cluster,
        },
        "unresolved_by_status": result.unresolved_by_status,
        "metadata_hits": [
            {
                "start": h.start,
                "end": h.end,
                "status": h.status,
                "reason": h.reason,
            }
            for h in result.metadata_hits
        ],
        "impacted": [
            {
                "path": e.path,
                "kind": e.kind,
                "size": e.size,
                "first_cluster": e.first_cluster,
                "hit_clusters": e.hit_clusters,
            }
            for e in result.impacted
        ],
    }
    if result.warnings:
        payload["warnings"] = result.warnings
    return json.dumps(payload, indent=2) + "\n"


def _emit_warnings(warnings: list[str]) -> None:
    for msg in warnings:
        print(f"warning: {msg}", file=sys.stderr)


# --- CLI ---


def build_parser(prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Correlate GNU ddrescue unresolved regions with exFAT file/directory extents."
        ),
    )
    parser.add_argument("image", help="exFAT partition image path")
    parser.add_argument("mapfile", help="GNU ddrescue mapfile path")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON on stdout",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress geometry and unresolved-area summary in text mode",
    )
    return parser


def cli(argv: list[str] | None = None) -> int:
    """Run the tool. Returns a process exit code."""
    parser = build_parser(prog=os.path.basename(sys.argv[0]) if argv is None else "exfat_impacted.py")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        result = analyze(args.image, args.mapfile)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except DdrescueFileImpactError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if result.warnings:
        _emit_warnings(result.warnings)

    if args.json:
        sys.stdout.write(format_json(result))
    else:
        sys.stdout.write(format_text(result, quiet=args.quiet))

    return 0


def main() -> None:
    sys.exit(cli())


if __name__ == "__main__":
    main()
