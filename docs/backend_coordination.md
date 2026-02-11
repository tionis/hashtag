# Backend Coordination and GC Design

This document captures backend coordination and blob lifecycle decisions across Forge features.

## Goals

- Keep object storage as the primary backend.
- Avoid requiring a relay/control-plane server for baseline correctness.
- Prevent catastrophic multi-writer overwrites for replicated databases.
- Keep blob garbage collection safe across multiple nodes.

## Shared Backend Session

Forge should converge on a shared backend/session layer used by all remote-aware components.

Session responsibilities:

- load S3 bootstrap env
- load global remote config (via local TTL cache)
- expose capability flags (`If-None-Match`, `If-Match`, response checksums)
- expose normalized object key/prefix helpers
- expose backend policy knobs (encryption requirements, coordination mode)

Rationale:

- removes duplicated config/capability loading logic
- keeps all features consistent when backend policy changes
- reduces subtle feature drift between blob/vector/snapshot/other tools

Status:

- shared remote backend session loading is implemented for vector replication and blob remote store paths
- node reference-set publication is moving to per-node SQLite refs DBs replicated via Litestream for remote/global blob GC workers

## Trust Foundation

Remote configuration now uses signed documents:

- root keys are pinned locally and compiled into the Forge binary
- remote config envelope carries `version`, optional `expires_at_utc`, signer key, and signature
- payload includes `trust.nodes` (`node_name -> public_key`) metadata
- local SQLite stores verified version/hash state to detect rollback/conflict attacks

This provides integrity/authenticity for control-plane settings even when object storage is untrusted.

## Lease/Fencing Without Relay

When running replicated single-writer services (for example `forge vector serve -replication`), Forge uses an S3-backed lease with capability-driven behavior, configured via global remote config (`coordination.vector_writer_lease`).

### Modes

- `hard`: requires conditional writes with `If-Match` and `If-None-Match`; enforce fencing semantics.
- `soft`: advisory lease using best-effort checks/renewals where strict CAS is unavailable.
- `off`: no lease enforcement.

Mode selection can be explicit in config or derived from capability flags.

### Writer Lease Model

Lease object fields:

- resource key
- owner id
- lease id (instance session id)
- expires-at timestamp
- observed ETag/fencing state

Core behavior:

1. acquire lease before DB restore/open/start writes
2. renew periodically while serving
3. on lease loss, stop accepting writes and terminate cleanly

Hard mode requirement:

- all renew/takeover operations must be conditional on current object version (ETag/CAS)
- stale writer must be rejected by failed conditional update

Soft mode note:

- no strict split-brain protection; use only when backend lacks required CAS semantics

## Vector Payload and GC Boundaries

Current vector behavior:

- upload payloads are staged locally and stored in local blob cache by CID
- vector queue stores payload CID refs
- worker reads payloads locally by CID
- only `embeddings.db` is replicated to S3 (when enabled)

Policy:

- `forge vector serve` should not perform blob deletion
- blob cleanup should be handled by dedicated GC workflows

## Global Blob GC Approaches

### Option A: Published Reference DBs via Litestream (Recommended)

Each node maintains a local SQLite refs DB (`cid` keep-set) and replicates it to object storage with Litestream under a node-scoped location.

Suggested object layout:

- `<object_prefix>/gc/node-refs/<node_id>/refs.db` (+ Litestream generation/state objects)

GC worker:

- hydrates/mirrors per-node refs DBs locally
- uses `ATTACH` + `UNION`/CTEs to compute live union/deltas
- deletes remote blobs not referenced by any active set

Pros:

- incremental replication bandwidth (changed SQLite pages only)
- avoids decrypting all node databases
- SQL-native set operations for large unions/diffs
- no per-blob claim object overhead
- deterministic and scalable

Cons:

- each node must maintain/publish a reference DB
- requires Litestream restore/hydration handling in GC workers

Signing note:

- per-node refs DBs are intentionally unsigned in this model
- rationale: any actor with write/delete access sufficient to forge refs can also directly delete blobs in object storage

### Option B: Master-Key Worker

GC worker uses master key to read/decrypt per-node databases and derives references directly.

Pros:

- no extra reference-publish DB per node

Cons:

- higher blast radius (worker requires master key)
- heavier coupling to all database schemas

### Option C: S3 Object Metadata Claims

Nodes write blob-claim metadata directly onto blob objects (or sidecar claim files).

Pros:

- no extra centralized reference table

Cons:

- unsafe on weak S3 backends (claim overwrite races)
- high API overhead at scale
- poor composability for multi-node updates

## Recommendation

Short-term:

- implement lease/fencing for replicated services using S3 capabilities (hard/soft/off)
- keep vector payload blobs local-only for service runtime

Medium-term:

- migrate from JSON ref snapshots to Litestream-replicated per-node refs DBs
- implement a dedicated GC worker that computes live sets via hydrated SQLite + CTEs

Long-term:

- optional relay can still be added later for stronger coordination/event fanout, but it is not required for baseline Forge operation
