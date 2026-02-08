# Relay Architecture

This document defines a Nostr-inspired relay/control-plane for Forge-family tools (`forge`, `blobforge`, `vectorforge`).

## Motivation

Forge uses object storage as the data plane. Some backends are missing full conditional-write support (`If-Match`), which makes strict multi-writer coordination difficult.

The relay provides:
- signed event streaming
- lock leasing with fencing tokens
- optional request/response routing and webhooks

This keeps object storage focused on immutable blobs/manifests while coordination moves to a dedicated control plane.

## Goals

- Support weak S3-style backends with minimal assumptions.
- Keep data-path objects immutable and content-addressed.
- Provide strongly consistent coordination primitives where required.
- Reuse existing node keys for authentication/signing.
- Keep encrypted payloads end-to-end (relay verifies signatures but does not decrypt payloads).

## Non-Goals

- Replacing object storage for large blob data.
- Full CRDT/document sync engine in v1.
- General-purpose queue semantics beyond event and lock primitives.

## Identity Model

### Node ID

Use the public key directly as the node identifier.

Benefits:
- no second lookup from node ID to key
- signatures can be verified immediately
- identity and authorization key are the same primitive

### Canonical Encoding

To avoid key-format ambiguity, normalize keys to one canonical identifier string:

- `node_id`: `ed25519:<lowercase-hex-32-byte-pubkey>`

Clients may load keys from OpenSSH formats, but must convert to the canonical form before sending events/lock requests.

### Key Rotation

Key rotation is modeled as a signed replaceable event authored by the old key that delegates to the new key. ACLs can optionally require admin approval of rotation events.

## Event Model (Nostr-Inspired)

### Event Envelope

Each event has:
- `id`: hash of canonical serialized event fields
- `pubkey`: canonical `node_id`
- `created_at_ns`: unix nanoseconds
- `kind`: integer kind code
- `tags`: list of string arrays
- `content`: opaque string/bytes payload (plain or encrypted)
- `sig`: signature over canonical event bytes

Recommended hash: `blake3`.

## Event Kinds

- `normal`: immutable, always append.
- `replaceable`: latest event wins by `(pubkey, kind, d_tag)` key.
- `addressable`: parameterized replaceable event addressed by a stable coordinate.
- `ephemeral`: fanout only, not persisted (or persisted with short TTL only for debugging).

`d_tag` is taken from `["d", "<value>"]` in tags when present.

For `addressable` events, `d_tag` is required.

## Addressable Events

Addressable events provide a stable key for mutable resources while preserving append-only history.

Coordinate format:
- `addr = <kind>:<pubkey>:<d_tag>`

Rules:
- `kind` and `pubkey` come from event fields.
- `d_tag` comes from `["d", "..."]`.
- The latest event for a coordinate is resolved by `(created_at_ns, id)` tie-break.
- All previous events remain queryable by event `id`.

Use cases:
- mutable pointers (for example `site/prod`)
- service configuration records
- singleton job scheduler state

Reference style:
- immutable reference: `event_id`
- mutable reference: `addr`

## Signature

Relay verifies signatures on write.

Two acceptable signing modes:
- Native Ed25519 signature over canonical bytes (recommended default).
- OpenSSH `sshsig` envelope over canonical bytes (optional compatibility mode).

If `sshsig` is enabled, use a fixed namespace string (for example `forge-relay-event-v1`) to prevent cross-protocol confusion.

## Encryption

For private payloads, `content` can carry age-encrypted ciphertext.

Recipient keys are referenced in tags:
- `["p", "<node_id>"]`

Relay stores and forwards ciphertext as opaque bytes.

## Relay Responsibilities

- Validate event structure, ID derivation, and signature.
- Persist normal/replaceable events.
- Fan out events to subscribers.
- Enforce authorization policy per key/tenant/namespace.
- Serve query APIs for replay and backfill.
- Provide lock and fencing token API.
- Optionally provide webhook fanout and request/response correlation.

## Lock and Fencing Model

Locks are lease-based and scoped by resource key (for example `db/main`, `site/prod-pointer`).

Operations:
- `acquire(resource, owner, lease_ms)`
- `renew(resource, owner, token, lease_ms)`
- `release(resource, owner, token)`
- `inspect(resource)`

Each successful acquire returns a monotonically increasing `fencing_token`.

Rules:
- Only active lease owner may renew/release.
- Expired leases may be taken by another owner.
- Any protected write must carry the fencing token.
- Consumers must reject stale tokens (`token <= last_seen_token`).

This prevents split-brain writes after lease timeout.

## API Surface (v1)

HTTP:
- `POST /v1/events`
- `GET /v1/events`
- `GET /v1/events/:id`
- `GET /v1/events/address/:kind/:pubkey/:d_tag`
- `GET /v1/events/address/:kind/:pubkey/:d_tag/history`
- `POST /v1/locks/acquire`
- `POST /v1/locks/renew`
- `POST /v1/locks/release`
- `GET /v1/locks/:resource`

WebSocket:
- `GET /v1/stream` for subscriptions, live fanout, optional presence/heartbeat channels.

Optional:
- `POST /v1/request` and streamed response events for request/response mapping.
- `POST /v1/webhooks` management for server-side fanout integrations.

## Storage Model

Suggested relational schema:

- `events(id PK, pubkey, kind, created_at_ns, content, sig, tags_json, received_at_ns)`
- `replaceable_index(pubkey, kind, d_tag, event_id, created_at_ns, PRIMARY KEY(pubkey, kind, d_tag))`
- `address_alias(addr PK, pubkey, kind, d_tag, event_id, created_at_ns)`
- `locks(resource PK, owner_pubkey, fencing_token, lease_expires_at_ns, updated_at_ns)`
- `lock_history(id PK, resource, owner_pubkey, fencing_token, action, at_ns)`
- `subscriptions` (optional persisted subscription state)

Notes:
- `events` is append-only for immutable auditability.
- `replaceable_index` is a projection index, not source of truth.
- `address_alias` is an optional convenience index for direct `addr` lookups.
- `locks` updates must be transactional and strongly consistent.

## Consistency Model

- Event ingestion/query: eventually consistent to subscribers, durable after commit.
- Lock API: linearizable within the active relay leader/database transaction scope.
- Replaceable event resolution: deterministic by `(created_at_ns, id)` tie-break.
- Addressable event resolution uses the same deterministic tie-break.

## Integration by Use Case

- Distributed jobs (`blobforge`):
  - use events for job publish/state transitions
  - use lease lock only for singleton schedulers when needed
- Single-writer DB streaming:
  - relay events reduce polling latency for replicas
  - correctness still relies on single writer
- Multi-writer DB:
  - require lock + fencing on commit/pointer promotion
  - do not rely on soft locks alone
- Blob store:
  - unchanged, stays hash-addressed in object storage
- File sharing/hosting:
  - publish immutable releases as objects/events
  - store mutable "current" pointer as an addressable event
  - protect pointer updates via lock+fencing or single designated writer

## Authorization and Multi-Tenancy

At minimum:
- namespace-level ACL by `pubkey` for write/read/lock actions
- per-tenant quotas and retention policies
- rate limits on event ingestion and ephemeral fanout

## Deployment and Rollout

### Phase 0

- Single relay instance.
- Durable DB backend.
- Event ingest/query/stream + lock API.

### Phase 1

- Add webhook fanout and request/response mapping.
- Add replay cursors and backfill endpoints.

### Phase 2

- High availability with leader election for lock linearizability.
- Cross-region replication and disaster recovery playbooks.

## Operational Notes

- Keep relay payload limits strict; large files belong in object storage.
- Add observability: event lag, write latency, lock contention, expired lease takeover count.
- Add abuse controls: auth challenge, per-key token bucket, payload size limits.

## Open Questions

- Default signing format in v1: native Ed25519 only, or Ed25519 + OpenSSH `sshsig` from day one.
- Relay storage engine choice for production scale (Postgres vs SQLite+single-writer deployment).
- Retention policy for immutable events and lock history.
- Whether ephemeral events should support bounded short-term replay.
- Whether addressable history should be fully retained or compacted by policy.
