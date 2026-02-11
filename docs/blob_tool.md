# Blob Tool

`forge blob` provides deterministic convergent blob handling with plaintext local cache and encrypted remote storage.

## Commands

- `forge blob put [options] <path>`
- `forge blob get [options] -cid <cid> -out <path>`
- `forge blob get [options] -oid <oid> -out <path>`
- `forge blob ls [options]`
- `forge blob gc [options]`
- `forge blob rm [options] -cid <cid>`
- `forge blob rm [options] -oid <oid>`
- `forge blob inventory publish [options]`

## Behavior

- Plaintext content identity (`cid`) is `blake3(plaintext)`.
- Encryption is deterministic/convergent using XChaCha20-Poly1305 with key/nonce material derived from CID.
- Encrypted object identity (`oid`) is deterministic from CID.
- Local blob cache stores plaintext by CID.
- Remote backend stores encrypted payloads by OID in S3.
- Local `blob put` attempts a CoW reflink clone into cache first, then falls back to a regular copy.
- Remote access for `put/get/rm` is enabled with `-remote` and uses global config from `forge remote config`.
- `blob gc` is local-only and prunes unreferenced `blob_map` rows/cache objects from local GC roots.
- local refs are tracked in `${FORGE_PATH_REFS_DB}` and streamed by `forge replicate daemon` for global GC workers.
- remote inventory base cache is stored in `${FORGE_PATH_S3_BLOBS_DB}` and refreshed from `gc_info` generation changes.
- local overlay cache is stored in `${FORGE_PATH_S3_BLOBS_OVERLAY_DB}` for discoveries/uploads between GC generations.

## Metadata Tables

- `blob_map`
  - known cleartext CID to encrypted object mapping
  - includes `plain_size`, `cipher_size`, `cipher_hash`, cache path, and timestamps
- `remote_blob_inventory`
  - observed remote objects (`backend`, `bucket`, `object_key`) with OID and cipher metadata
  - decoupled from `blob_map` so remote rescans/cleanup can be handled independently
- `blob_refs`
  - per-node keep-set references (`source`, `ref_key`, `cid`) replicated via `refs.db`
  - local keep refs are upserted on `blob put/get` and removed on local `blob rm`
  - GC-derived snapshot/vector references are refreshed by `blob gc`

## Output Modes

`put`, `get`, `ls`, `gc`, and `rm` support `-output auto|pretty|kv|json`.

## Local GC Roots

`forge blob gc` computes live CIDs from local references:

- Snapshot DB `tree_entries.target_hash` rows where `kind='file'`.
- Vector queue DB `jobs.file_path` payload refs where status is `pending|processing` (and optionally `error`).
- During each run, these sources are synced into `refs.db` (`snapshot.tree_entries`, `vector.queue`).
- On applied deletes, stale local keep refs (`blob.local.keep`) for removed CIDs are pruned.
- For weak backends (without `If-None-Match`), remote existence checks use `base UNION overlay` inventory cache.

## Inventory Publish

`forge blob inventory publish` acts as the GC worker publish step:

- scans remote blob objects under the configured blob prefix
- writes an immutable SQLite inventory snapshot
- uploads snapshot to `<object_prefix>/gc/inventory/<generation>/inventory.db`
- updates `<object_prefix>/gc/gc_info.json` pointer

By default `blob gc` is dry-run and only reports a delete plan. Use `-apply` to delete local rows/files.

Scalability direction:

- keep refs DBs unsigned by design (write/delete-capable attackers can already remove remote blobs directly)
- let GC workers hydrate/attach node refs DBs and compute keep/remove sets with SQL (`ATTACH`, `UNION`, CTEs)
- publish GC-generation inventory snapshots (`gc_info` + immutable `inventory.db`).
- clients hydrate base inventory into `${FORGE_DATA_DIR}/s3-blobs.db` and maintain local-only updates in `${FORGE_DATA_DIR}/s3-blobs-overlay.db`.
- clients reset overlay when generation changes.

## Remote Prerequisite

Before using `-remote`, initialize the global remote config object:

- `forge remote config init`
- `forge remote config show`
