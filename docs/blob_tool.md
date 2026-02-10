# Blob Tool

`forge blob` provides deterministic convergent blob handling with plaintext local cache and encrypted remote storage.

## Commands

- `forge blob put [options] <path>`
- `forge blob get [options] -cid <cid> -out <path>`
- `forge blob get [options] -oid <oid> -out <path>`
- `forge blob ls [options]`
- `forge blob gc [options]`
- `forge blob refs publish [options]`
- `forge blob rm [options] -cid <cid>`
- `forge blob rm [options] -oid <oid>`

## Behavior

- Plaintext content identity (`cid`) is `blake3(plaintext)`.
- Encryption is deterministic/convergent using XChaCha20-Poly1305 with key/nonce material derived from CID.
- Encrypted object identity (`oid`) is deterministic from CID.
- Local blob cache stores plaintext by CID.
- Remote backend stores encrypted payloads by OID in S3.
- Local `blob put` attempts a CoW reflink clone into cache first, then falls back to a regular copy.
- Remote access for `put/get/rm` is enabled with `-remote` and uses global config from `forge remote config`.
- `blob gc` is local-only and prunes unreferenced `blob_map` rows/cache objects from local GC roots.
- `blob refs publish` builds a node-scoped live CID set from local roots and publishes it to S3 for global GC workers.

## Metadata Tables

- `blob_map`
  - known cleartext CID to encrypted object mapping
  - includes `plain_size`, `cipher_size`, `cipher_hash`, cache path, and timestamps
- `remote_blob_inventory`
  - observed remote objects (`backend`, `bucket`, `object_key`) with OID and cipher metadata
  - decoupled from `blob_map` so remote rescans/cleanup can be handled independently

## Output Modes

`put`, `get`, `ls`, `gc`, and `rm` support `-output auto|pretty|kv|json`.
`blob refs publish` also supports `-output auto|pretty|kv|json`.

## Local GC Roots

`forge blob gc` computes live CIDs from local references:

- Snapshot DB `tree_entries.target_hash` rows where `kind='file'`.
- Vector queue DB `jobs.file_path` payload refs where status is `pending|processing` (and optionally `error`).

By default `blob gc` is dry-run and only reports a delete plan. Use `-apply` to delete local rows/files.

`forge blob refs publish` uses the same root discovery inputs and writes:

- object path: `<object_prefix>/gc/node-refs/<node_id>.json`
- schema: `forge.blob_refs.v1`
- payload: sorted `cids`, `cid_set_hash`, root stats, timestamps, optional expiry (`-ttl`)

## Remote Prerequisite

Before using `-remote`, initialize the global remote config object:

- `forge remote config init`
- `forge remote config show`
