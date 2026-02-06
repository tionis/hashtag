# Forge

`forge` is a multi-tool CLI workspace for filesystem workflows.

Current tools:
- `forge hash`: concurrent file hashing with xattr caching (`user.checksum.*`).
- `forge dupes`: duplicate-file detection by content hash.
- `forge snapshot`: metadata-only filesystem snapshots with history, diff, inspect, and tag query.
- `forge hashmap`: map external digests back to BLAKE3 identities.

## Install

```bash
go install github.com/tionis/forge@latest
```

## CLI Overview

```bash
forge <command> [options]
```

Top-level commands:
- `forge hash`
- `forge dupes`
- `forge snapshot`
- `forge hashmap`
- `forge completion`

## Hash Tool

```bash
forge hash [flags] [path]
```

Flags:
- `-w`: number of workers (default `NumCPU`)
- `-v`: verbose output
- `-algos`: comma-separated algorithms (default `blake3`)
- `-clean`: force cache invalidation and re-hash
- `-remove`: remove all `user.checksum.*` xattrs

Examples:

```bash
forge hash .
forge hash -algos blake3,sha256 /data
forge hash -remove /data
```

## Dupes Tool

```bash
forge dupes [flags] [path]
```

Flags:
- `-min-size`: only consider files with size >= `min-size` bytes (default `1`)
- `-cache`: use `user.checksum.blake3` + `user.checksum.mtime` cache when valid (default `true`)
- `-update-cache`: write missing/stale BLAKE3 cache values while scanning (default `false`)
- `-output`: output mode `table|json|paths|paths0` (default `table`)
- `-v`: verbose output

`-output` modes:
- `table`: summary `key=value` lines plus `group/hash/size/path` table
- `json`: full structured JSON document
- `paths`: duplicate file paths, one per line
- `paths0`: duplicate file paths, NUL-delimited (`\0`)

Summary fields:
- `groups`: number of duplicate-content groups
- `duplicate_files`: total number of files that belong to duplicate groups
- `wasted_bytes`: estimated duplicate storage (`sum(size * (copies-1))`)

## Snapshot Tool

Create snapshot:

```bash
forge snapshot [flags] [path]
# or
forge snapshot create [flags] [path]
```

History:

```bash
forge snapshot history [flags] [path]
```

Diff:

```bash
forge snapshot diff [flags] [path]
```

Inspect tree entries:

```bash
forge snapshot inspect -tree <tree_hash> [flags]
```

Query entries by tags:

```bash
forge snapshot query -tree <tree_hash> -tags tag1,tag2 [flags]
```

Snapshot flags:
- `-db`: snapshot DB path (default from `${FORGE_SNAPSHOT_DB}` or `${XDG_DATA_HOME}/forge/snapshot.db`, fallback `~/.local/share/forge/snapshot.db`)
- `-v`: verbose output (create)
- `-limit`: max rows (history)
- `-from`: older snapshot time in unix ns (diff)
- `-to`: newer snapshot time in unix ns (diff)
- `-tree`: tree hash selector (inspect/query)
- `-recursive`: include descendant tree entries (inspect)
- `-tags`: required tags filter (query)
- `-kind`: query kind filter (`file|symlink|tree|all`, default `file`)

Diff behavior:
- Without `-from/-to`: compares the two newest snapshots for the path.
- With `-from` and `-to`: compares those specific snapshots.

Diff codes:
- `A`: added path
- `D`: removed path
- `M`: modified path (hash and/or metadata)
- `T`: type changed (`file`/`tree`/`symlink`)

Snapshot metadata:
- `user.xdg.tags` is ingested as normalized tags and stored as first-class relational data.
- Tree hashes are content-addressed using BLAKE3 over canonical tree serialization (`forge.tree.v1`).

Snapshot database tables:
- `trees`
- `tree_entries`
- `tags`
- `tree_entry_tags`
- `pointers`
- `hash_mappings` (minimal `(blake3, algo) -> digest` mapping table)

## Hashmap Tool

Ingest checksum xattrs into the mapping table:

```bash
forge hashmap ingest [flags] [path]
```

Lookup BLAKE3 by external digest:

```bash
forge hashmap lookup -algo sha256 -digest <sha256>
```

Show external digests known for a BLAKE3:

```bash
forge hashmap show -blake3 <blake3>
```

Hashmap flags:
- `-db`: snapshot DB path (same default resolution as `forge snapshot`)
- `-v`: verbose output (ingest)
- `-algo`: algorithm name (lookup)
- `-digest`: digest value (lookup)
- `-blake3`: BLAKE3 digest value (show)

## Documentation

- Docs index: [`docs/README.md`](docs/README.md)
- Dupes tool: [`docs/dupes_tool.md`](docs/dupes_tool.md)
- Snapshot architecture: [`docs/snapshot_architecture.md`](docs/snapshot_architecture.md)
- Hashmap tool: [`docs/hashmap_tool.md`](docs/hashmap_tool.md)
- Tool rules: [`docs/tool_rules.md`](docs/tool_rules.md)
- Adding tools: [`docs/adding_tools.md`](docs/adding_tools.md)
- Hash metadata spec: [`docs/file_hashing_via_xattrs.md`](docs/file_hashing_via_xattrs.md)

## License

MIT (`LICENSE`).
