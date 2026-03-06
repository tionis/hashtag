# Forge Hash Skill

Use this skill for content hashing and xattr checksum cache maintenance.

## Primary Commands

- Hash tree: `forge hash [path] -algos blake3 -output json`
- Force rehash: `forge hash [path] -clean -output json`
- Remove checksum xattrs: `forge hash [path] -remove -output json`

## Key Flags

- `-workers`: hashing concurrency.
- `-algos`: comma-separated algorithms.
- `-clean`: ignore existing cache.
- `-remove`: delete `user.checksum.*` attributes.
- `-output`: `auto|pretty|kv|json`.
