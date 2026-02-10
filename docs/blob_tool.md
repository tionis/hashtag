# Blob Tool

`forge blob` provides deterministic convergent blob handling with plaintext local cache and encrypted remote storage.

## Commands

- `forge blob put [options] <path>`
- `forge blob get [options] -cid <cid> -out <path>`
- `forge blob get [options] -oid <oid> -out <path>`
- `forge blob ls [options]`
- `forge blob rm [options] -cid <cid>`
- `forge blob rm [options] -oid <oid>`
- `forge blob serve [options]`

## Behavior

- Plaintext content identity (`cid`) is `blake3(plaintext)`.
- Encryption is deterministic/convergent using XChaCha20-Poly1305 with key/nonce material derived from CID.
- Encrypted object identity (`oid`) is deterministic from CID.
- Local blob cache stores plaintext by CID.
- Remote backend stores encrypted payloads by OID.
- Local `blob put` attempts a CoW reflink clone into cache first, then falls back to a regular copy.

## Metadata Tables

- `blob_map`
  - known cleartext CID to encrypted object mapping
  - includes `plain_size`, `cipher_size`, `cipher_hash`, cache path, and timestamps
- `remote_blob_inventory`
  - observed remote objects (`backend`, `bucket`, `object_key`) with OID and cipher metadata
  - decoupled from `blob_map` so remote rescans/cleanup can be handled independently

## Output Modes

`put`, `get`, `ls`, and `rm` support `-output auto|pretty|kv|json`.

## Minimal Backend Server

`forge blob serve` exposes:

- `GET /healthz`
- `PUT /v1/blobs/{oid}`
- `GET /v1/blobs/{oid}`
- `HEAD /v1/blobs/{oid}`
- `DELETE /v1/blobs/{oid}`

Server stores encrypted payloads only and can verify payload/OID consistency.
