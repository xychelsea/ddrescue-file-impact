# ddrescue-file-impact

Correlate **GNU ddrescue** unresolved byte ranges with **exFAT** file and directory extents on a partition image. Given a rescued image and its ddrescue mapfile, the tool reports which paths likely overlap damaged or not-yet-recovered regions.

## Requirements

- Python 3.10 or newer
- An exFAT partition image (read-only)
- A [GNU ddrescue](https://www.gnu.org/software/ddrescue/) mapfile for that image

No third-party Python packages are required at runtime.

## Usage

```bash
./exfat_impacted.py partition.img partition.log
```

Human-readable report (default):

```bash
./exfat_impacted.py partition.img partition.log
```

Machine-readable JSON:

```bash
./exfat_impacted.py partition.img partition.log --json
```

Quiet text mode (skip geometry and unresolved-area summary; still lists impacted paths):

```bash
./exfat_impacted.py partition.img partition.log --quiet
```

### Example text output

```
exFAT geometry
  bytes_per_sector:      512
  sectors_per_cluster:   64
  cluster_size:          32768
  ...

unresolved ddrescue areas
  - confirmed bad-sector: 1 clusters
  ? non-tried: 1 clusters

likely impacted files/directories
FILE /Photos/vacation.jpg
     size=1234567 first_cluster=42 hit_clusters=2
     first_hit_clusters=42,43
```

### Example JSON output

```json
{
  "geometry": {
    "bytes_per_sector": 512,
    "cluster_size": 32768,
    "cluster_heap_offset": 16384,
    "root_cluster": 2
  },
  "unresolved_by_status": { "-": 1, "?": 1 },
  "metadata_hits": [],
  "impacted": [
    {
      "path": "/README.TXT",
      "kind": "file",
      "size": 11,
      "first_cluster": 3,
      "hit_clusters": [3]
    }
  ]
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (including when no impacted files are found) |
| `1` | Runtime error (missing file, invalid image, short read, etc.) |
| `2` | Usage error (missing or invalid arguments) |

Warnings (e.g. mapfile with no unresolved ranges) are printed to stderr; the process still exits `0`.

## ddrescue mapfile statuses

| Status | Meaning |
|--------|---------|
| `+` | Finished / good (ignored by this tool) |
| `-` | Bad sector |
| `/` | Non-scraped |
| `*` | Non-trimmed |
| `?` | Non-tried |

## Limitations

- **exFAT only** — other filesystems are not supported.
- **Read-only** — the image is never modified.
- **Best-effort** — damaged directory metadata may produce incomplete or missing paths.
- Hits in the boot sector, FAT, or other metadata areas are reported separately; they do not map to file paths.

## Development

```bash
pip install -r requirements-dev.txt
pytest -v
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
