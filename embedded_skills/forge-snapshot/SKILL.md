# Forge Snapshot Skill

Use this skill for Forge's content-addressed snapshot database.

## Primary Commands

- Create local snapshot: `forge snapshot create [path] -output json`
- Create remote snapshot: `forge snapshot remote <remote:path> -output json`
- History: `forge snapshot history [path] -limit 20 -output json`
- Diff: `forge snapshot diff [path] -from <ts> -to <ts> -output json`
- Inspect: `forge snapshot inspect -tree <hash> -output json`
- Query by tags: `forge snapshot query -tree <hash> -tags a,b -output json`

## Key Flags

- `-db`: snapshot database path.
- `-strict`: fail on recoverable scan/list/hash warnings.
- `-basic-tree`: zero mode/modtime and exclude tags in tree entries.
- `-output`: `auto|pretty|kv|json`.
