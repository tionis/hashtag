# Forge Snap Skill

Use this skill for snapper/btrfs-native workflows.

## Primary Commands

- List configs: `forge snap configs -output json`
- Snapshot history: `forge snap log -path . -output json`
- Snapshot history in range: `forge snap log -path . -since -24h -until now -output json`
- Snapshot history with changed files: `forge snap log -path . -files -files-limit 100 -output json`
- Working tree status: `forge snap status -path . -output json`
- Working tree status by time: `forge snap status -path . -from-time 2026-03-01T10:00:00Z -to-time now -output json`
- Text diff: `forge snap diff -path .`
- Text diff by time: `forge snap diff -path . -from-time -6h -to-time now`
- Undo changes: `forge snap restore -path . -apply -output json`
- Create snapshot: `forge snap save -path . -description "..." -output json`

## Key Flags

- `-path`: resolve snapper config from path.
- `-path`: for `snap log`, also scopes stat/file output to that subtree.
- `-config`: explicit snapper config.
- `-from`/`-to`: revision selectors.
- `-from-time`/`-to-time`: time selectors for `status`/`diff` (cannot be combined with `-from`/`-to`).
- `-since`/`-until`: time-expression bounds for `snap log`.
- `-files`: include per-snapshot changed file list in `snap log`.
- `-files-limit`: cap changed files shown per snapshot (`0` means all).
- `-apply`: execute restore (default is preview).
- `-output`: `auto|pretty|kv|json` where supported.
