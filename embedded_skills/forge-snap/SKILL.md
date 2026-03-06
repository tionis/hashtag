# Forge Snap Skill

Use this skill for snapper/btrfs-native workflows.

## Primary Commands

- List configs: `forge snap configs -output json`
- Snapshot history: `forge snap log -path . -output json`
- Working tree status: `forge snap status -path . -output json`
- Text diff: `forge snap diff -path .`
- Undo changes: `forge snap restore -path . -apply -output json`
- Create snapshot: `forge snap save -path . -description "..." -output json`

## Key Flags

- `-path`: resolve snapper config from path.
- `-config`: explicit snapper config.
- `-from`/`-to`: revision selectors.
- `-apply`: execute restore (default is preview).
- `-output`: `auto|pretty|kv|json` where supported.
