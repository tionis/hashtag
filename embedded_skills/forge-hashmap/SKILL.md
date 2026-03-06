# Forge Hashmap Skill

Use this skill to maintain and query digest mapping metadata.

## Primary Commands

- Ingest mappings: `forge hashmap ingest [path] -output json`
- Lookup BLAKE3: `forge hashmap lookup -algo sha256 -digest <hex> -output json`
- Show known digests: `forge hashmap show -blake3 <hex> -output json`

## Key Flags

- `-db`: snapshot/hashmap database path.
- `-algo`: external digest algorithm for lookup.
- `-digest`: digest value for lookup.
- `-blake3`: canonical BLAKE3 digest for reverse lookup.
- `-output`: `auto|pretty|kv|json`.
