# Forge

`forge` is a multi-tool CLI workspace for filesystem workflows.

Current tools:
- `forge hash`: concurrent file hashing with xattr caching (`user.checksum.*`).
- `forge dupes`: duplicate-file detection by content hash.
- `forge snapshot`: metadata-only filesystem snapshots with history, diff, inspect, and tag query.
- `forge hashmap`: map external digests back to BLAKE3 identities.
- `forge tags`: manage `user.xdg.tags` metadata on files/paths.
- `forge remote`: global S3 backend configuration shared across Forge features.
- `forge blob`: deterministic encrypted blob storage with plaintext local cache + optional S3 remote sync.

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
- `forge tags`
- `forge remote`
- `forge blob`
- `forge completion`

Output mode convention:
- Many commands support `-output auto|pretty|kv|json`.
- `auto` chooses `pretty` for interactive terminals and `kv` for non-interactive/scripted output.

## Local Path Environment Overrides

Forge stores local state under XDG paths by default. These env vars override specific local paths:

- `FORGE_SNAPSHOT_DB` (default `${XDG_DATA_HOME}/forge/snapshot.db`, fallback `~/.local/share/forge/snapshot.db`)
- `FORGE_BLOB_DB` (default `${XDG_DATA_HOME}/forge/blob.db`, fallback `~/.local/share/forge/blob.db`)
- `FORGE_BLOB_CACHE` (default `${XDG_CACHE_HOME}/forge/blobs`, fallback `~/.cache/forge/blobs`)
- `FORGE_REMOTE_DB` (default `${XDG_DATA_HOME}/forge/remote.db`, fallback `~/.local/share/forge/remote.db`)

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
- `-output`: output mode `auto|pretty|kv|json` (default `auto`)

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
- `-output`: output mode `auto|pretty|table|json|paths|paths0` (default `auto`)
- `-v`: verbose output

`-output` modes:
- `auto`: `pretty` on terminal, `table` otherwise
- `pretty`: human-friendly summary + ASCII tables
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

Create snapshot from an rclone remote:

```bash
forge snapshot remote [flags] <remote:path>
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
- `-output`: output mode `auto|pretty|kv|json` (create/history/diff/inspect/query, default `auto`)
- `-v`: verbose output (create/remote create)
- `-strict`: fail immediately on recoverable scan/hash warnings (create/remote create)
- `-basic-tree`: zero entry `mode`/`mod_time_ns` and exclude entry tags from tree snapshots (create/remote create)
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

Snapshot create error behavior:
- Default: permission-denied, transient missing-path scan errors, and file-changed-during-hash races are skipped with warnings; snapshot is still committed.
- Default warning exit code: `2` (partial success).
- Strict mode (`-strict`): these warnings become hard errors and snapshot creation fails with exit code `1`.

Remote snapshot notes:
- `forge snapshot remote` uses `rclone lsjson -R --hash --metadata` to enumerate remote files.
- Forge captures `rclone` `stdout` and `stderr` separately to keep listing JSON parse-safe.
- If recursive listing fails, Forge falls back to directory-by-directory listing.
- If some subtrees fail during fallback listing, Forge skips those subtrees with warnings (or fails in `-strict`).
- Remote xattrs are not required.
- Forge keeps a local `remote_hash_cache` table in the snapshot DB for remote hash reuse.
- If remote BLAKE3 is unavailable and no mapping exists, Forge computes BLAKE3 by streaming object content.
- If content hashing fails, snapshot creation fails (no metadata fallback identity is used).
- Remote pointers are stored as `rclone:<remote:path>` and can be passed to `snapshot history`/`snapshot diff`.

Snapshot metadata:
- `user.xdg.tags` is ingested as normalized tags and stored as first-class relational data.
- Tree hashes are content-addressed using BLAKE3 over canonical tree serialization (`forge.tree.v1`).
- `-basic-tree` keeps canonical tree hashing but stores `mode=0`, `mod_time_ns=0`, and no entry tags for each entry, which helps cross-filesystem comparisons when metadata drifts during upload/sync.

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
- `-output`: output mode `auto|pretty|kv|json` (default `auto`)
- `-v`: verbose output (ingest)
- `-algo`: algorithm name (lookup)
- `-digest`: digest value (lookup)
- `-blake3`: BLAKE3 digest value (show)

## Remote Tool

Initialize global remote config object in S3:

```bash
forge remote config init [flags]
```

Show global remote config object from S3:

```bash
forge remote config show [flags]
```

Remote config is loaded from S3 using environment bootstrap:
- `FORGE_S3_BUCKET` (required)
- `FORGE_S3_REGION` (default `us-east-1`)
- `FORGE_S3_ENDPOINT_URL` (optional)
- `FORGE_S3_ACCESS_KEY_ID` + `FORGE_S3_SECRET_ACCESS_KEY` (optional as pair)
- `FORGE_S3_SESSION_TOKEN` (optional)
- `FORGE_S3_FORCE_PATH_STYLE` (optional bool)
- `FORGE_REMOTE_CONFIG_KEY` (default `forge/config.json`)
- `FORGE_REMOTE_DB` (optional local config-cache DB path; default `${XDG_DATA_HOME}/forge/remote.db`)

`forge remote config init` probes and records S3 capability flags by default (`If-None-Match`, `If-Match`, and `response_checksums`). Use `-probe-capabilities=false` with `-cap-if-none-match` / `-cap-if-match` / `-cap-response-checksums` to override manually.
`forge remote config init -config-cache-ttl <seconds>` sets `cache.remote_config_ttl_seconds`; remote-backed operations use local SQLite cache and refresh from S3 when this TTL expires.

## Blob Tool

Put/encrypt a blob from a local file:

```bash
forge blob put [flags] <path>
```

Get/decrypt a blob to a local file:

```bash
forge blob get [flags] -cid <cid> -out <path>
# or
forge blob get [flags] -oid <oid> -out <path>
```

List known local blob mappings:

```bash
forge blob ls [flags]
```

Remove blob data:

```bash
forge blob rm [flags] -cid <cid>
# or
forge blob rm [flags] -oid <oid>
```

Blob flags:
- `-db`: blob metadata DB path (default from `${FORGE_BLOB_DB}` or `${XDG_DATA_HOME}/forge/blob.db`)
- `-cache`: local plaintext blob cache dir (default from `${FORGE_BLOB_CACHE}` or `${XDG_CACHE_HOME}/forge/blobs`)
- `-remote`: upload/fetch/delete encrypted blob objects using configured S3 remote (`put/get/rm`)
- `-cid`: cleartext BLAKE3 content hash selector for `blob get`/`blob rm`
- `-oid`: encrypted object ID selector for `blob get`/`blob rm`
- `-out`: output plaintext path for `blob get` (required)
- `-local`: local cache + `blob_map` deletion toggle for `blob rm` (default `true`)
- `-limit`: max rows for `blob ls`
- `-output`: output mode `auto|pretty|kv|json` (put/get/ls/rm)
- `-v`: verbose output (put/get/rm)

Blob notes:
- Encryption is deterministic/convergent using XChaCha20-Poly1305 material derived from plaintext CID.
- OIDs are deterministic from CID, enabling idempotent dedupe writes across clients.
- Local cache stores plaintext by CID for filesystem-level dedupe; remote payloads are encrypted.
- Remote objects are written under a deterministic key layout derived from global remote config.
- Local `blob put` tries CoW reflink clone into cache first (when supported), then falls back to regular copy with hash verification.
- Metadata is stored in separate tables:
  - `blob_map`: known cleartext CID -> encrypted object mapping + cache metadata.
  - `remote_blob_inventory`: observed remote objects (including objects without local cleartext mapping).

## Tags Tool

Manage `user.xdg.tags` directly:

```bash
forge tags get [flags] [path]
forge tags set -tags tag1,tag2 [flags] [path]
forge tags add -tags tag3 [flags] [path]
forge tags remove -tags tag2 [flags] [path]
forge tags clear [flags] [path]
```

Tags flags:
- `-output`: output mode `auto|pretty|kv|json` (default `auto`)
- `-tags`: comma/semicolon-separated tag list (required for `set`/`add`/`remove`)

Notes:
- Tags are normalized before storage (trimmed, deduplicated, sorted).
- Empty tags are cleared by `forge tags clear`.
- Path defaults to current directory if omitted.

## Documentation

- Docs index: [`docs/README.md`](docs/README.md)
- Dupes tool: [`docs/dupes_tool.md`](docs/dupes_tool.md)
- Snapshot architecture: [`docs/snapshot_architecture.md`](docs/snapshot_architecture.md)
- Relay architecture: [`docs/relay_architecture.md`](docs/relay_architecture.md)
- Hashmap tool: [`docs/hashmap_tool.md`](docs/hashmap_tool.md)
- Tags tool: [`docs/tags_tool.md`](docs/tags_tool.md)
- Remote tool: [`docs/remote_tool.md`](docs/remote_tool.md)
- Blob tool: [`docs/blob_tool.md`](docs/blob_tool.md)
- Tool rules: [`docs/tool_rules.md`](docs/tool_rules.md)
- Output modes: [`docs/output_modes.md`](docs/output_modes.md)
- Adding tools: [`docs/adding_tools.md`](docs/adding_tools.md)
- Hash metadata spec: [`docs/file_hashing_via_xattrs.md`](docs/file_hashing_via_xattrs.md)

## License

MIT (`LICENSE`).
