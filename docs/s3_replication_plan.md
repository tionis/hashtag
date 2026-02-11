# S3 Replication and Hydration Plan

This document captures the current and planned S3-only replication model for Forge.

## Scope

- Keep S3 as the only backend for now.
- Defer event streaming databases and relay-specific persistence.
- Use Litestream for database streaming and hydration.
- Use age encryption where confidentiality is required.

## Assumptions

- Blob deletions on S3 are performed only by the GC worker.
- `remote.db` remains a local cache and is not replicated.
- Weak S3 backends are supported using soft-lease mode where required.

## Database Matrix

| Database | Local Path | Planned Replication Target | Encryption | Planned Restore Behavior | Status |
|---|---|---|---|---|---|
| `snapshot.db` | `${FORGE_PATH_SNAPSHOT_DB}` | `<object_prefix>/db/snapshot` | age to node key + master/root key | Daemon stream-up enabled (`forge replicate daemon`) | Implemented |
| `vector/embeddings.db` | `${FORGE_PATH_VECTOR_EMBED_DB}` | `<object_prefix>/vector/embeddings` | age (Litestream) | Auto-restore on `forge vector serve` startup | Implemented |
| `vector/queue.db` | `${FORGE_PATH_VECTOR_QUEUE_DB}` | `<object_prefix>/vector/queue` | age (Litestream) | Auto-restore on `forge vector serve` startup | Implemented |
| `embeddings.db` (hydrated ingest cache) | `${FORGE_PATH_VECTOR_HYDRATED_DB}` | Hydrated from embeddings replica stream | none (local cache) | Refreshed before/for ingest lookup prechecks | Implemented (best effort) |
| `blob.db` | `${FORGE_PATH_BLOB_DB}` | none | n/a | Local-only metadata DB | Implemented local-only |
| `refs.db` | `${FORGE_DATA_DIR}/refs.db` | `<object_prefix>/gc/node-refs/<node_id>/refs` | none | Maintained by blob flows + daemon stream-up (`forge replicate daemon`) | Implemented |
| `s3-blobs.db` (remote inventory base) | `${FORGE_DATA_DIR}/s3-blobs.db` | Published by GC worker under immutable generation key | none | Rehydrate when `gc_info.generation` changes | Implemented |
| `s3-blobs-overlay.db` | `${FORGE_DATA_DIR}/s3-blobs-overlay.db` | none (local-only) | n/a | Reset on generation change | Implemented |
| `remote.db` | `${FORGE_PATH_REMOTE_DB}` | none | n/a | Local cache/trust state only | Implemented local-only |

## Flows

### 1. Background Daemon Replication (Implemented)

- `forge replicate daemon` streams `snapshot.db` to S3 using Litestream + age recipients:
  - node SSH key recipient
  - master/root SSH key recipient
- `forge replicate daemon` streams `refs.db` to S3 without encryption.
- Daemon is responsible for long-running replication and retry behavior.

### 2. Vector Service Replication

- `forge vector serve` uses replication by default (no `-replication` flag).
- On startup:
  - acquire writer lease first
  - restore `vector/embeddings.db`
  - restore `vector/queue.db`
  - run recovery/reconciliation for queue states
- During runtime:
  - stream both DBs continuously
  - terminate write-serving path on lease loss

### 3. Ingest Hydration

- `forge vector ingest` hydrates/refreshes `${FORGE_PATH_VECTOR_HYDRATED_DB}` from the embeddings replica stream.
- Hydration is best effort: restore failures fall back to local existing cache (if present) or skip precheck cache with warning logs.
- Use hydrated DB for local precheck to reduce upload/lookup churn.

### 4. Remote Blob Inventory Cache (Implemented)

- GC worker publishes:
  - immutable `inventory.db` at generation-specific key
  - mutable `gc_info` pointer document with generation metadata
- Clients:
  - hydrate `s3-blobs.db` when missing or generation changes
  - write local discoveries/uploads into `s3-blobs-overlay.db`
  - answer existence checks from `base UNION overlay`
  - clear overlay and rehydrate on generation bump

Recommended `gc_info` fields:

- `generation`
- `completed_at_utc`
- `inventory_db_key`
- `inventory_db_hash`
- `inventory_db_format_version`
- `gc_worker_id`
- `deleted_count`
- `scanned_count`

## Notes

- Unsigned refs DBs are intentional in this model:
  - a principal able to tamper refs and trigger GC damage typically also has direct blob delete capability on S3.
- Lease/fencing and replication encryption are separate concerns:
  - leases protect correctness for single-writer services
  - age/Litestream protects confidentiality of replicated DB content
