# Forge Vector Skill

Use this skill for vector embedding service and ingestion.

## Primary Commands

- Start service: `forge vector serve`
- Ingest files: `forge vector ingest -server http://localhost:8080 -root . -output json`
- Show lease status: `forge vector lease-status -output json`

## Key Flags

- `-server`: vector coordinator URL for ingest client.
- `-root`: scan root.
- `-kind`: `image|text`.
- `-hydrated-db`: local hydrated embeddings DB path.
- `-workers`: ingest concurrency.
