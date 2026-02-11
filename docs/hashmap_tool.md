# Hashmap Tool

`forge hashmap` manages reverse mappings from external digests to canonical BLAKE3 file identities.

## Why It Exists

`forge hash` can cache multiple digests in xattrs (`user.checksum.*`).  
`forge snapshot` uses BLAKE3 as canonical file identity.  
`forge hashmap` bridges these so external hashes (for example SHA-256) can be resolved to the same BLAKE3 identity used in snapshots.

## Commands

- `forge hashmap ingest [flags] [path]`
  - Walk regular files under `path` (default `.`).
  - Read cached checksum xattrs when mtime cache is current.
  - Upsert mappings into `hash_mappings` as `(blake3, algo) -> digest`.
- `forge hashmap lookup -algo <name> -digest <value> [flags]`
  - Return matching BLAKE3 digests for that `(algo, digest)`.
- `forge hashmap show -blake3 <digest> [flags]`
  - Return all known `(algo, digest)` mappings for that BLAKE3.

## Data Contract

Table:
- `hash_mappings(blake3 TEXT, algo TEXT, digest TEXT, PRIMARY KEY(blake3, algo))`

Implications:
- one digest per `(blake3, algo)` pair
- digest updates overwrite previous value for that pair
- multiple BLAKE3 values may share the same `(algo, digest)` if collisions or duplicates are present

## Shared Flags

- `-db`: path to snapshot database (`FORGE_PATH_SNAPSHOT_DB` default applies)
- `-v`: verbose ingest logging (`ingest` only)
