# Vector Tool

`forge vector` replaces standalone `vectorforge` service/client workflows inside the Forge CLI.

## Commands

- `forge vector serve [-replication]`
- `forge vector ingest [flags]`

## Service: `forge vector serve`

Runs the embedding coordinator:

- HTTP API (`/api/v1/lookup`, `/api/v1/upload`, `/healthz`)
- durable queue ACK before `202 Accepted`
- queue dedupe by `(file_hash, kind)`
- worker dispatch + ingestion into `embeddings.db`
- crash recovery of `processing -> pending` at startup
- optional Litestream replication for `embeddings.db`

Runtime env:

- `LISTEN_ADDR` (default `:8080`)
- `IMAGE_WORKER_URL` (default `http://localhost:3003`, fallback `WORKER_URL`)
- `TEXT_WORKER_URL` (default `IMAGE_WORKER_URL`)
- `WORKER_CONCURRENCY` (default `20`)
- `LOOKUP_CHUNK_SIZE` (default `500`)
- `QUEUE_ACK_TIMEOUT_MS` (default `5000`)
- `MAX_PENDING_JOBS` (default `5000`)
- `MAX_JOB_ATTEMPTS` (default `3`)
- `FORGE_VECTOR_REPLICA_RESTORE_ON_START` (default `true`)

Local storage env overrides:

- `FORGE_VECTOR_EMBED_DB` (default `${XDG_DATA_HOME}/forge/vector/embeddings.db`)
- `FORGE_VECTOR_QUEUE_DB` (default `${XDG_DATA_HOME}/forge/vector/queue.db`)
- `FORGE_VECTOR_TEMP_DIR` (default `${XDG_CACHE_HOME}/forge/vector/tmp`)
- `FORGE_BLOB_DB` (default `${XDG_DATA_HOME}/forge/blob.db`)
- `FORGE_BLOB_CACHE` (default `${XDG_CACHE_HOME}/forge/blobs`)

Replication:

- Default is local-only (no remote streaming).
- `-replication` enables remote replica URL derivation from Forge global remote config.
- Requires remote bootstrap env (`FORGE_S3_BUCKET` and related S3 env used by `forge remote config`).
- Replica target path is derived as `<object_prefix>/vector/embeddings`.
- On startup, if replication is enabled and local embeddings DB is missing, restore is attempted first.
- Replicated mode acquires and renews an S3-backed writer lease; on lease loss, service write path is stopped to avoid multi-writer overwrite scenarios.
- Lease behavior is configured in remote config under `coordination.vector_writer_lease` (mode/resource/duration/renew interval).

## Client: `forge vector ingest`

Scans local files, hashes with xattr cache, performs batch lookup, uploads only missing hashes.

Flags:

- `-server` coordinator URL (default `http://localhost:8080`)
- `-root` scan root (default `.`)
- `-kind` `image|text` (default `image`)
- `-algo` `blake3` (default `blake3`)
- `-hydrated-db` local hydrated DB precheck path (default `${XDG_DATA_HOME}/forge/embeddings.db`, override `FORGE_VECTOR_HYDRATED_DB`)
- `-workers` worker count (default `NumCPU`)
- `-lookup-batch` lookup batch size (default `500`)
- `-http-timeout` request timeout (default `120s`)
- `-v` verbose logs

Notes:

- Upload validation compares `X-File-Hash` to uploaded content BLAKE3.

## API Contract

`POST /api/v1/lookup`

- Body: `{"kind":"image|text","hashes":["..."]}`
- Response: `{"status":{"<hash>":"present|processing|missing"}}`

`POST /api/v1/upload`

- Required headers: `X-File-Hash`, `X-Embedding-Kind`
- Body: raw file bytes (`application/octet-stream`)
- Success:
  - `202`: accepted and queued
  - `200`: already present in embeddings DB
- Expected non-success:
  - `400`: invalid headers/body/hash mismatch
  - `429`: queue backlog over `MAX_PENDING_JOBS`
  - `503`: queue ACK timeout

`GET /healthz`

- Response: `{"status":"ok"}`

## Worker Contract

Workers are called at `<IMAGE_WORKER_URL|TEXT_WORKER_URL>/predict` with:

- headers: `X-Embedding-Kind`, `X-File-Hash`
- body: raw file bytes

Accepted worker responses:

- JSON array vector directly (for example `[0.1, 0.2, ...]`)
- JSON object containing one of `embedding`, `vector`, or `data` with a vector array payload

## Storage Model

Local files:

- `embeddings.db`: final vectors (`image_embeddings`, `text_embeddings`)
- `queue.db`: queue state (`jobs`)
- `FORGE_VECTOR_TEMP_DIR`: short-lived upload staging
- `blob.db` + `FORGE_BLOB_CACHE`: payload spool by CID (queue stores CID refs)

Remote files:

- Only `embeddings.db` Litestream replica (when `-replication` is enabled).
- Queue DB and payload spool are local-only.

GC boundary:

- `forge vector serve` should not delete blob payload objects.
- Blob lifecycle cleanup belongs to dedicated GC workflows.
