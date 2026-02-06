# Dupes Tool

`forge dupes` finds duplicate regular files by content hash.

## Command

- `forge dupes [flags] [path]`

`path` defaults to the current directory.

## Output Modes

Use `-output` to choose format:
- `table` (default): summary `key=value` lines plus tabular rows.
- `json`: single JSON document with `root`, `summary`, and `groups`.
- `paths`: duplicate paths, newline-delimited.
- `paths0`: duplicate paths, NUL-delimited.

## Detection Strategy

1. Walk regular files.
2. Group by file size.
3. Hash only size groups with at least 2 files.
4. Group by `(size, blake3)` and report groups with at least 2 files.

This avoids hashing files that are unique by size.

## Hash and Cache Behavior

- Content hash algorithm: BLAKE3.
- Cache keys:
  - `user.checksum.blake3`
  - `user.checksum.mtime`
- With `-cache=true` (default), a cached hash is used only when cached mtime matches file mtime.
- With `-update-cache=true`, newly hashed files attempt to update both cache xattrs.

## Output

Primary fields:
- `root`
- `groups`
- `duplicate_files`
- `wasted_bytes`
- `scanned`
- `hashed`
- `cache_hits`
- `skipped_too_small`
- `errors`

Tabular rows:
- `group`, `hash`, `size`, `path`
