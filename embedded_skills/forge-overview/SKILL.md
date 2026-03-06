# Forge Overview Skill

Use this skill to route a request to the correct Forge subcommand.

## Command Router

- `forge hash`: hash files and optionally cache xattrs.
- `forge dupes`: find duplicate files by content.
- `forge snap`: inspect and restore snapper/btrfs snapshots.
- `forge snapshot`: create and diff Forge content-addressed snapshots.
- `forge hashmap`: map external digests to BLAKE3.
- `forge tags`: read/write `user.xdg.tags`.
- `forge config show`: inspect effective local+remote configuration.
- `forge remote config ...`: manage signed remote S3 config.
- `forge blob ...`: local plaintext blob cache + encrypted remote blobs.
- `forge vector ...`: run vector service and ingest jobs.
- `forge replicate daemon`: replicate node databases to S3.
- `forge skills ...`: list/install embedded Forge skills.

## Interaction Rules

- For data commands, prefer `-output json` when automation is needed.
- For mutating commands, prefer preview or explicit execution flags when available.
- Keep command output bounded (`-limit`, selectors) for large datasets.
