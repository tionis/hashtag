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
- `forge vector`: embedding coordinator service and ingestion client workflows.

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
- `forge config`
- `forge remote`
- `forge blob`
- `forge vector`
- `forge completion`

Output mode convention:
- Many commands support `-output auto|pretty|kv|json`.
- `auto` chooses `pretty` for interactive terminals and `kv` for non-interactive/scripted output.

## Local Path Configuration

Forge stores local state under XDG paths by default.

Base path overrides:

- `FORGE_DATA_DIR` (default `${XDG_DATA_HOME}/forge`, fallback `~/.local/share/forge`)
- `FORGE_CACHE_DIR` (default `${XDG_CACHE_HOME}/forge`, fallback `~/.cache/forge`)

Fine-grained path overrides:

- `FORGE_PATH_SNAPSHOT_DB` (default `${FORGE_DATA_DIR}/snapshot.db`)
- `FORGE_PATH_BLOB_DB` (default `${FORGE_DATA_DIR}/blob.db`)
- `FORGE_PATH_BLOB_CACHE` (default `${FORGE_CACHE_DIR}/blobs`)
- `FORGE_PATH_REMOTE_DB` (default `${FORGE_DATA_DIR}/remote.db`)
- `FORGE_PATH_VECTOR_EMBED_DB` (default `${FORGE_DATA_DIR}/vector/embeddings.db`)
- `FORGE_PATH_VECTOR_QUEUE_DB` (default `${FORGE_DATA_DIR}/vector/queue.db`)
- `FORGE_PATH_VECTOR_TEMP_DIR` (default `${FORGE_CACHE_DIR}/vector/tmp`)
- `FORGE_PATH_VECTOR_HYDRATED_DB` (default `${FORGE_DATA_DIR}/embeddings.db`)

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
- `-db`: snapshot DB path (default from `${FORGE_PATH_SNAPSHOT_DB}` or `${FORGE_DATA_DIR}/snapshot.db`)
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

## Config Tool

Inspect effective local and remote-derived configuration:

```bash
forge config show [flags]
```

Config show flags:
- `-effective`: print resolved effective values (currently must be `true`)
- `-output`: output mode `auto|pretty|kv|json` (default `auto`)

## Remote Tool

Initialize global remote config object in S3:

```bash
forge remote config init [flags]
```

Show global remote config object from S3:

```bash
forge remote config show [flags]
```

Update mutable global remote config values:

```bash
forge remote config set [flags]
```

Manage trust nodes in global remote config:

```bash
forge remote config node list [flags]
forge remote config node add [flags]
forge remote config node update [flags]
forge remote config node remove [flags]
```

Remote config is loaded from S3 using environment bootstrap:
- `FORGE_S3_BUCKET` (required)
- `FORGE_S3_REGION` (default `us-east-1`)
- `FORGE_S3_ENDPOINT_URL` (optional)
- `FORGE_S3_ACCESS_KEY_ID` + `FORGE_S3_SECRET_ACCESS_KEY` (optional as pair)
- `FORGE_S3_SESSION_TOKEN` (optional)
- `FORGE_S3_FORCE_PATH_STYLE` (optional bool)
- `FORGE_REMOTE_CONFIG_KEY` (default `forge/config.json`)
- `FORGE_PATH_REMOTE_DB` (optional local config-cache DB path; default `${FORGE_DATA_DIR}/remote.db`)
- `FORGE_TRUST_SIGNING_KEY` (optional default path for `forge remote config init -signing-key`)
- `FORGE_TRUST_SIGNING_KEY_PASSPHRASE` (optional default passphrase for encrypted keys)

Forge trust roots are non-overridable and are compiled from `forge.pub`.

`forge remote config init` probes and records S3 capability flags by default (`If-None-Match`, `If-Match`, and `response_checksums`). Use `-probe-capabilities=false` with `-cap-if-none-match` / `-cap-if-match` / `-cap-response-checksums` to override manually.
`forge remote config init -config-cache-ttl <seconds>` sets `cache.remote_config_ttl_seconds`; remote-backed operations use local SQLite cache and refresh from S3 when this TTL expires.
`forge remote config init` also configures writer-lease policy for replicated services:
- `-vector-lease-mode auto|hard|soft|off`
- `-vector-lease-resource <resource-key>`
- `-vector-lease-duration <seconds>`
- `-vector-lease-renew-interval <seconds>`

Remote config is signed:
- `forge remote config init -signing-key <path>` signs the config envelope using an OpenSSH private key.
- `-signing-key-passphrase <value>` unlocks encrypted OpenSSH private keys.
- If passphrase is required and omitted, Forge prompts interactively (hidden input) when stdin is a TTY.
- Optional: `-doc-version <int64>` and `-doc-expires-seconds <seconds>` (`0` disables expiry).
- Optional trust map input: `-trust-nodes-file <json>` + `-root-node-name <name>`.
- Forge verifies signatures against compiled trust roots and enforces local anti-rollback state in `${FORGE_PATH_REMOTE_DB}` (default `${FORGE_DATA_DIR}/remote.db`).
- `forge remote config set` and `forge remote config node ...` use the same signed write path.

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

Garbage collect unreferenced local blob metadata/cache:

```bash
forge blob gc [flags]
```

Remove blob data:

```bash
forge blob rm [flags] -cid <cid>
# or
forge blob rm [flags] -oid <oid>
```

Blob flags:
- `-db`: blob metadata DB path (default from `${FORGE_PATH_BLOB_DB}` or `${FORGE_DATA_DIR}/blob.db`)
- `-cache`: local plaintext blob cache dir (default from `${FORGE_PATH_BLOB_CACHE}` or `${FORGE_CACHE_DIR}/blobs`)
- `-remote`: upload/fetch/delete encrypted blob objects using configured S3 remote (`put/get/rm`)
- `-cid`: cleartext BLAKE3 content hash selector for `blob get`/`blob rm`
- `-oid`: encrypted object ID selector for `blob get`/`blob rm`
- `-out`: output plaintext path for `blob get` (required)
- `-local`: local cache + `blob_map` deletion toggle for `blob rm` (default `true`)
- `-limit`: max rows for `blob ls`
- `-output`: output mode `auto|pretty|kv|json` (put/get/ls/rm)
- `-v`: verbose output (put/get/rm)

Blob GC flags:
- `-db`: blob metadata DB path to collect
- `-cache`: local blob cache directory to collect
- `-snapshot-db`: snapshot DB root source (`tree_entries.kind='file'`)
- `-vector-queue-db`: vector queue DB root source (`jobs.file_path` payload refs)
- `-include-error-jobs`: include vector `status=error` jobs as roots (default `true`)
- `-no-snapshot-refs`: disable snapshot roots
- `-no-vector-refs`: disable vector queue roots
- `-apply`: apply deletions (default is dry-run)
- `-output`: output mode `auto|pretty|kv|json`
- `-v`: verbose output

Blob notes:
- Encryption is deterministic/convergent using XChaCha20-Poly1305 material derived from plaintext CID.
- OIDs are deterministic from CID, enabling idempotent dedupe writes across clients.
- Local cache stores plaintext by CID for filesystem-level dedupe; remote payloads are encrypted.
- Remote objects are written under a deterministic key layout derived from global remote config.
- Local `blob put` tries CoW reflink clone into cache first (when supported), then falls back to regular copy with hash verification.
- `blob gc` is local-only and does not remove remote objects.
- node refs publishing is being replaced by Litestream-replicated per-node SQLite refs DBs for scalable large pinsets.
- Metadata is stored in separate tables:
  - `blob_map`: known cleartext CID -> encrypted object mapping + cache metadata.
  - `remote_blob_inventory`: observed remote objects (including objects without local cleartext mapping).

## Vector Tool

Run the coordinator service:

```bash
forge vector serve
```

Run local ingestion client:

```bash
forge vector ingest \
  -server http://localhost:8080 \
  -root /path/to/files \
  -kind image \
  -algo blake3 \
  -workers 16
```

Inspect current vector writer-lease state (for replicated mode):

```bash
forge vector lease-status [flags]
```

`forge vector serve` runtime environment:
- `FORGE_VECTOR_LISTEN_ADDR` (default `:8080`)
- `FORGE_VECTOR_IMAGE_WORKER_URL` (default `http://localhost:3003`; falls back to `FORGE_VECTOR_WORKER_URL`)
- `FORGE_VECTOR_TEXT_WORKER_URL` (default `FORGE_VECTOR_IMAGE_WORKER_URL`)
- `FORGE_VECTOR_WORKER_CONCURRENCY` (default `20`)
- `FORGE_VECTOR_LOOKUP_CHUNK_SIZE` (default `500`)
- `FORGE_VECTOR_QUEUE_ACK_TIMEOUT_MS` (default `5000`)
- `FORGE_VECTOR_MAX_PENDING_JOBS` (default `5000`)
- `FORGE_VECTOR_MAX_JOB_ATTEMPTS` (default `3`)
- `FORGE_VECTOR_REPLICA_RESTORE_ON_START` (default `true`)

Local vector storage paths use:
- `FORGE_PATH_VECTOR_EMBED_DB`
- `FORGE_PATH_VECTOR_QUEUE_DB`
- `FORGE_PATH_VECTOR_TEMP_DIR`

Vector payload spool storage uses the shared blob store paths:
- `FORGE_PATH_BLOB_DB`
- `FORGE_PATH_BLOB_CACHE`

Replication behavior:
- By default, `forge vector serve` runs local-only (no replication).
- Use `forge vector serve -replication` to derive Litestream replica URL from Forge remote config (`forge remote config ...`) and stream to S3.

`forge vector ingest` flags:
- `-server` coordinator base URL (default `http://localhost:8080`)
- `-root` local scan root (default `.`)
- `-kind` embedding kind (`image|text`, default `image`)
- `-algo` hash algorithm for xattr cache (`blake3`, default `blake3`)
- `-hydrated-db` hydrated embeddings DB path (default `${FORGE_PATH_VECTOR_HYDRATED_DB}` or `${FORGE_DATA_DIR}/embeddings.db`)
- `-workers` worker count (default `NumCPU`)
- `-lookup-batch` hashes per lookup request (default `500`)
- `-http-timeout` request timeout (default `120s`)
- `-v` verbose logging

Vector upload queue behavior:
- Uploads are staged briefly under `FORGE_PATH_VECTOR_TEMP_DIR`.
- Payloads are then stored in local blob cache (`blob_map` + `FORGE_PATH_BLOB_CACHE`) and queue records store payload CIDs.
- Worker reads payload content by CID from blob cache (with legacy file-path fallback for pre-migration queue rows).

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
- Backend coordination: [`docs/backend_coordination.md`](docs/backend_coordination.md)
- Hashmap tool: [`docs/hashmap_tool.md`](docs/hashmap_tool.md)
- Tags tool: [`docs/tags_tool.md`](docs/tags_tool.md)
- Remote tool: [`docs/remote_tool.md`](docs/remote_tool.md)
- Blob tool: [`docs/blob_tool.md`](docs/blob_tool.md)
- Vector tool: [`docs/vector_tool.md`](docs/vector_tool.md)
- Tool rules: [`docs/tool_rules.md`](docs/tool_rules.md)
- Output modes: [`docs/output_modes.md`](docs/output_modes.md)
- Adding tools: [`docs/adding_tools.md`](docs/adding_tools.md)
- Hash metadata spec: [`docs/file_hashing_via_xattrs.md`](docs/file_hashing_via_xattrs.md)

## License

MIT (`LICENSE`).
