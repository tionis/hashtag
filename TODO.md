# TODO

## S3 Replication and Hydration Roadmap

### Path Conventions

- `FORGE_PATH_VECTOR_EMBED_DB`, `FORGE_PATH_VECTOR_QUEUE_DB`, and `FORGE_PATH_VECTOR_HYDRATED_DB` are explicit override env vars.
- Default behavior derives these from `FORGE_DATA_DIR`:
  - `${FORGE_DATA_DIR}/vector/embeddings.db`
  - `${FORGE_DATA_DIR}/vector/queue.db`
  - `${FORGE_DATA_DIR}/embeddings.db`
- Unless stated otherwise, roadmap items assume default derived paths.

### Phase 1: Vector Service Replication Defaults

- [x] Remove `forge vector serve -replication`; make replication/restore default behavior.
- [x] Restore both `${FORGE_PATH_VECTOR_EMBED_DB}` and `${FORGE_PATH_VECTOR_QUEUE_DB}` on service startup.
- [x] Acquire writer lease before entering write-serving mode.
- [x] Keep lease renewal/fencing active during runtime; stop write-serving on lease loss.
- [x] Stream both vector DBs continuously with Litestream.

### Phase 2: Ingest Hydration

- [x] Add hydration flow for `${FORGE_PATH_VECTOR_HYDRATED_DB}` during/for `forge vector ingest`.
- [x] Use hydrated DB state for local precheck filtering before server lookup/upload.
- [x] Add stale/missing hydration fallback behavior with clear logging.

### Phase 3: Background Daemon Replication

- [ ] Add background replication daemon command/workflow.
- [ ] Stream `${FORGE_PATH_SNAPSHOT_DB}` with Litestream + age encryption.
- [ ] Configure snapshot replica recipients: node SSH key + master/root SSH key.
- [ ] Stream `${FORGE_DATA_DIR}/refs.db` without encryption.
- [ ] Define per-db replica key layout under S3 `object_prefix`.

### Phase 4: refs.db Integration

- [ ] Create refs DB schema for node keep-set tracking.
- [ ] Integrate refs updates into blob put/get/rm flows where appropriate.
- [ ] Integrate refs updates into local blob GC root updates.
- [ ] Ensure refs DB writes are idempotent and crash-safe.

### Phase 5: Remote Inventory Cache

- [ ] Implement GC worker output for immutable generation inventory DB snapshots.
- [ ] Implement `gc_info` pointer publish/update flow.
- [ ] Add client cache hydration into `${FORGE_DATA_DIR}/s3-blobs.db` on generation change.
- [ ] Add local overlay cache `${FORGE_DATA_DIR}/s3-blobs-overlay.db` for discoveries/uploads.
- [ ] Switch remote existence checks to `base UNION overlay`.

### Phase 6: Hardening

- [ ] Add integration tests for lease loss and restart recovery with dual DB restore.
- [ ] Add integration tests for generation bumps and overlay reset behavior.
- [ ] Add guardrails for out-of-band remote deletes (strict mode / verification fallback).
- [ ] Add operational docs for daemon lifecycle and key rotation/rekeying.
