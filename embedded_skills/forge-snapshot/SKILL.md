# Forge Snapshot Skill

Use this skill for Forge's content-addressed snapshot database.

## Primary Commands

- Create local snapshot: `forge snapshot create [path] -output json`
- Create remote snapshot: `forge snapshot remote <remote:path> -output json`
- History: `forge snapshot history [path] -limit 20 -output json`
- Diff: `forge snapshot diff [path] -from <ts> -to <ts> -output json`
- Inspect: `forge snapshot inspect -tree <hash> -output json`
- Query by tags: `forge snapshot query -tree <hash> -tags a,b -output json`
- Preview missing image embeddings: `forge snapshot embed [path] -output json`
- Create missing image embeddings: `forge snapshot embed -apply [path] -output json`
- Find similar embedded images: `forge snapshot similar [path] -image photo.jpg -limit 20 -output json`

## Key Flags

- `-db`: snapshot database path.
- `-embed-db`: image embeddings database path.
- `-strict`: fail on recoverable scan/list/hash warnings.
- `-apply`: execute image embedding generation (default is preview for `snapshot embed`).
- `-basic-tree`: zero mode/modtime and exclude tags in tree entries.
- `-image`: query image path for `snapshot similar`.
- `-output`: `auto|pretty|kv|json`.
