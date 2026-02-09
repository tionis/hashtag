# Snapshot Architecture

This document defines the on-disk database model and deterministic hashing behavior used by `forge snapshot`.

## Scope

The snapshot system is metadata-only:
- It stores references to file content hashes and child tree hashes.
- It stores path/time pointers to snapshot targets.
- It does not store file blobs.

CLI subcommands:
- `forge snapshot create`
- `forge snapshot remote`
  - Primary listing path: `rclone lsjson -R --hash --metadata`
  - On recursive listing failure: directory-by-directory `lsjson` fallback with warning accounting
  - Subtree listing failures in fallback mode are skipped with warnings (strict mode fails)
- `forge snapshot history`
- `forge snapshot diff`
- `forge snapshot inspect`
- `forge snapshot query`

## Hash Algorithms

- File content identity: `blake3(content)` (hex).
- Tree identity: `blake3(canonical_tree_serialization)` (hex).

## Tree Hashing (Canonical)

Tree hash version marker: `forge.tree.v1`.

Serialization order:
1. Write version marker string.
2. Write entry count (`uint32`, big-endian).
3. For each entry sorted by `name` ascending:
   - `name` (length-prefixed bytes)
   - `kind` (`tree`/`file`/`symlink`/`special`)
   - `target_hash`
   - `mode` (`uint32`, big-endian)
   - `mod_time_ns` (`int64`, big-endian)
   - `size` (`int64`, big-endian)
   - `link_target`
   - tag count (`uint32`, big-endian)
   - each normalized tag string in ascending order

`-basic-tree` mode:
- keeps the same canonical serialization format
- forces entry `mode=0` and `mod_time_ns=0` before hashing and persistence
- clears entry tag lists before hashing and persistence

All variable-length fields are encoded as:
- `uint32(len(bytes))` + raw bytes.

Resulting digest is stored as lowercase hex.

## Tag Normalization

Snapshot ingests `user.xdg.tags` and normalizes as follows:
1. Read xattr value as UTF-8 text.
2. Replace `;` with `,`.
3. Split by `,`.
4. Trim whitespace per token.
5. Drop empty tokens.
6. Deduplicate exact matches.
7. Sort ascending.

The normalized set is:
- embedded into tree hash input
- stored relationally in `tags` + `tree_entry_tags`

## SQLite Schema

Core tables:
- `trees(hash PK, hash_algo, created_at_ns, entry_count)`
- `tree_entries(tree_hash, name, kind, target_hash, mode, mod_time_ns, size, link_target)`
  - PK: `(tree_hash, name)`
  - FK: `tree_hash -> trees(hash)` with `ON DELETE CASCADE`
- `tags(id PK, name UNIQUE)`
- `tree_entry_tags(tree_hash, name, tag_id)`
  - PK: `(tree_hash, name, tag_id)`
  - FK: `(tree_hash, name) -> tree_entries(tree_hash, name)` with `ON DELETE CASCADE`
  - FK: `tag_id -> tags(id)` with `ON DELETE CASCADE`
- `pointers(id PK, path, snapshot_time_ns, target_kind, target_hash, hash_algo)`
- `hash_mappings(blake3, algo, digest)`
  - PK: `(blake3, algo)`
- `remote_hash_cache(remote_path, object_path, size, mod_time_ns, etag, hash_algo, hash_digest, source, confidence, updated_at_ns)`
  - PK: `(remote_path, object_path, hash_algo)`

Indexes:
- `pointers(path, snapshot_time_ns DESC)`
- `pointers(target_hash)`
- `tree_entry_tags(tag_id, tree_hash)`
- `tree_entry_tags(tree_hash, tag_id)`
- `hash_mappings(algo, digest)`
- `remote_hash_cache(remote_path, object_path)`

## Safety Pragmas

During DB initialization:
- `PRAGMA journal_mode=WAL;`
- `PRAGMA synchronous=NORMAL;`
- `PRAGMA foreign_keys=ON;`

After init, foreign key enforcement is verified via `PRAGMA foreign_keys;` and startup fails if disabled.

## Versioning Note

- The current canonical tree hash marker is `forge.tree.v1`.
