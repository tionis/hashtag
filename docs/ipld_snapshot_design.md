# IPLD Snapshot Design

This document proposes a breaking replacement for Forge's current custom snapshot tree hashing.

It assumes:

- no backward compatibility with existing snapshot/tree/blob identifiers
- new snapshots may use a new on-disk schema
- CLI and JSON field names may change

## Goals

- Make snapshot structure natively IPLD-compatible.
- Make CAR a first-class import/export format for snapshot graphs.
- Keep BLAKE3 as Forge's canonical content hash.
- Keep SQLite for query/index workloads without making it the source of truth for snapshot structure.

## Non-Goals

- Preserving existing `tree_hash` values or blob hex-`cid` values.
- Using UnixFS as the native snapshot model.
- Making `forge snapshot` a full file-content archive in the first cut.

## Why DAG-CBOR, Not UnixFS

Forge snapshots are metadata-first and include behavior that does not map cleanly to UnixFS:

- normalized tag sets
- `basic-tree` normalization rules
- explicit `special` node handling
- local/remote snapshot parity without requiring file chunk graphs

UnixFS remains a possible future export target for full file-content packaging, but the native snapshot graph should use a small Forge-specific schema encoded as DAG-CBOR.

## Terminology Changes

The current naming collides with IPLD terminology. Native IPLD mode should rename concepts as follows:

- `cid`: always means a real CID string
- `digest`: raw hash bytes rendered as lowercase hex when shown to humans
- `root_cid`: CID of a snapshot manifest node
- `node_cid`: CID of a filesystem metadata node
- `content_cid`: CID of plaintext file content in the blob/content layer
- `oid`: encrypted remote object identifier derived from content identity

Terms to remove from the public contract:

- `tree_hash`
- `target_hash`
- hex-only blob `cid`

## Native CID and Codec Policy

- CID version: CIDv1 only
- Multibase text form: base32 lowercase
- Native multihash: BLAKE3
- Metadata codec: `dag-cbor`
- Plaintext content codec: `raw`

This keeps Forge aligned with its existing BLAKE3-first identity model while making every native identifier a real CID.

Note: the multicodec table currently marks BLAKE3 as `draft`. Forge should still use it natively because BLAKE3 is a project-level design choice, but we should treat SHA-256 export modes as a possible later interoperability feature if ecosystem pressure warrants it.

## Snapshot Graph Model

The snapshot graph is metadata-complete on its own. It does not require file-content blocks to be present in order to traverse directories, inspect metadata, diff snapshots, or query tags.

### Root Node: Snapshot Manifest

Codec: `dag-cbor`

JSON-shaped form:

```json
{
  "type": "forge.snapshot.manifest/v2",
  "source": {
    "kind": "local",
    "path": "/data/project"
  },
  "snapshot_time_ns": 1760000000000000000,
  "root": {"/": "bafy..."},
  "options": {
    "basic_tree": false
  }
}
```

Rules:

- `root` links to the top-level directory node.
- `snapshot_time_ns` is part of the manifest and therefore part of the manifest CID.
- source path/remote path is preserved in the manifest instead of an external pointer row being the only place it exists.

### Directory Node

Codec: `dag-cbor`

```json
{
  "type": "forge.fs.dir/v2",
  "entries": [
    {
      "name": "notes.txt",
      "kind": "file",
      "node": {"/": "bafy..."},
      "mode": 33188,
      "mtime_ns": 1760000000000000000,
      "tags": ["work", "draft"]
    },
    {
      "name": "src",
      "kind": "dir",
      "node": {"/": "bafy..."},
      "mode": 16877,
      "mtime_ns": 1760000000000000000,
      "tags": []
    }
  ]
}
```

Rules:

- entries are sorted by `name` ascending before encoding
- `kind` is one of `dir`, `file`, `symlink`, `special`
- `mode`, `mtime_ns`, and `tags` are path-entry metadata, not intrinsic content data
- `basic-tree` is applied before node creation by forcing `mode=0`, `mtime_ns=0`, and `tags=[]`

### File Node

Codec: `dag-cbor`

```json
{
  "type": "forge.fs.file/v2",
  "content_cid": "bafk...",
  "size": 12345,
  "digest": {
    "algo": "blake3",
    "hex": "0123abcd..."
  }
}
```

Rules:

- `content_cid` is the plaintext-content CID from the blob/content layer
- `content_cid` is stored as data, not as an IPLD link, so the metadata graph is complete even when content blocks are not bundled
- `size` lives on the file node because it is content-specific

### Symlink Node

Codec: `dag-cbor`

```json
{
  "type": "forge.fs.symlink/v2",
  "target": "../shared/config"
}
```

### Special Node

Codec: `dag-cbor`

```json
{
  "type": "forge.fs.special/v2",
  "fingerprint": {
    "algo": "blake3",
    "hex": "abcd..."
  },
  "size": 0
}
```

`fingerprint` replaces the current special-file synthetic hash and remains content-addressed metadata rather than a portable file-payload representation.

## Bundle Root for Multi-Snapshot CAR Exports

For exports that include more than one snapshot, Forge should not emit multiple unrelated CAR roots. Instead it should create a bundle root node.

Codec: `dag-cbor`

```json
{
  "type": "forge.snapshot.bundle/v1",
  "snapshots": [
    {"/": "bafy..."},
    {"/": "bafy..."}
  ]
}
```

Rules:

- single-snapshot export root: manifest CID
- multi-snapshot export root: bundle CID
- roots inside `snapshots` are sorted by `(source.path, snapshot_time_ns, root_cid)` before encoding

## Local Storage Model

Snapshot structure should move to a native blockstore plus SQLite indexes.

### Blockstore

Store raw block bytes in a filesystem blockstore under `${FORGE_CACHE_DIR}/ipld/blocks`.

Recommended path layout:

- shard by digest prefix
- file name is CID text plus codec suffix when useful for debugging

Example:

- `${FORGE_CACHE_DIR}/ipld/blocks/ab/cd/bafy....block`

The blockstore is the source of truth for snapshot structure.

### SQLite Indexes

SQLite remains an index/cache for fast queries and history lookups.

Recommended tables:

- `ipld_blocks(cid PRIMARY KEY, codec, multihash_code, digest_hex, size, block_path, created_at_ns)`
- `snapshot_heads(source_path, snapshot_time_ns, manifest_cid, root_cid, PRIMARY KEY(source_path, snapshot_time_ns))`
- `snapshot_entries(manifest_cid, path, kind, node_cid, mode, mtime_ns, size, content_cid)`
- `snapshot_entry_tags(manifest_cid, path, tag, PRIMARY KEY(manifest_cid, path, tag))`

Properties:

- every index row is derivable from blockstore data
- indexes may be rebuilt from roots when missing or stale
- diff/query/inspect operate against indexes, not by walking the DAG on every command

## Blob Layer Alignment

The blob/content layer should adopt real CIDs too.

Native blob rules:

- plaintext content identity is `content_cid`, not hex `cid`
- `content_cid` uses codec `raw` plus BLAKE3 multihash
- local plaintext cache is keyed by `content_cid`
- remote encrypted object `oid` is derived from the BLAKE3 digest bytes, not from the CID string text

This keeps encrypted object naming stable if multibase text rendering changes while still making content identity IPLD-native.

## CAR Rules

Forge should support CAR v1 first.

### Export

`forge snapshot export-car` should:

- accept one or more manifest CIDs or source/time selectors
- materialize a single root CID as described above
- traverse linked metadata nodes depth-first
- emit each CID at most once
- write blocks in deterministic traversal order

Deterministic traversal order:

1. bundle root or manifest root first
2. directory entries in `name` ascending order
3. child nodes in entry order
4. duplicate CIDs suppressed after first emission

`-with-content` is out of scope for the first cut. The first version exports a complete metadata CAR.

### Import

`forge snapshot import-car` should:

- read CAR roots
- validate that each root is either `forge.snapshot.manifest/v2` or `forge.snapshot.bundle/v1`
- store all blocks in the local blockstore
- rebuild SQLite indexes from imported roots

## CLI Surface

Breaking changes are acceptable, so the public contract should become CID-first rather than dual-mode.

### Snapshot Commands

- `forge snapshot create [path]`
  - output `manifest_cid`, `root_cid`, `source_path`, `snapshot_time_ns`
- `forge snapshot remote <remote:path>`
  - same output shape as local create
- `forge snapshot history [path]`
  - list manifest CIDs, root CIDs, and timestamps
- `forge snapshot inspect -cid <manifest-or-node-cid>`
- `forge snapshot query -cid <manifest-cid> ...`
- `forge snapshot export-car ...`
- `forge snapshot import-car ...`

Field names to use in JSON:

- `manifest_cid`
- `root_cid`
- `node_cid`
- `content_cid`

Field names to stop using:

- `tree_hash`
- `target_hash`

### Blob Commands

- `forge blob put <path>`
  - returns `content_cid` and `oid`
- `forge blob get -cid <content_cid> -out <path>`
- `forge blob rm -cid <content_cid>`
- add `-digest` only where raw BLAKE3 hex lookup is explicitly needed for debugging

## Migration and Rollout

Because compatibility is not required, migration can be simple:

1. Introduce a new schema version and blockstore.
2. Remove old snapshot/tree hash terminology from CLI and JSON.
3. Recreate snapshots under the new CID-first model.
4. Update blob cache naming and blob DB schema to use `content_cid`.
5. Add CAR export/import once native block creation is stable.

Do not implement a hash-preserving translation layer from the old tree model.

## Recommended Implementation Order

1. Add an internal IPLD package for node schemas, DAG-CBOR encoding, and CID generation.
2. Add blockstore write/read primitives.
3. Replace snapshot creation so it emits DAG-CBOR nodes and manifest CIDs.
4. Add index rebuilders from manifest roots.
5. Switch inspect/query/diff/history to index-on-blockstore semantics.
6. Rename blob identity surfaces to `content_cid`.
7. Add CAR export/import.

## Open Follow-Ups

- Decide whether future full-content archive export should use:
  - a Forge-specific archival bundle schema, or
  - a separate UnixFS export path
- Decide whether to add an optional SHA-256 CID export mode for external interoperability
- Decide whether large-directory sharding is needed beyond simple sorted-entry DAG-CBOR lists

## External References

- CAR v1: <https://ipld.io/specs/transport/car/carv1/>
- DAG-CBOR: <https://ipld.io/specs/codecs/dag-cbor/spec/>
- UnixFS: <https://specs.ipfs.tech/unixfs/>
- CID spec: <https://github.com/multiformats/cid>
- multicodec table: <https://raw.githubusercontent.com/multiformats/multicodec/master/table.csv>
