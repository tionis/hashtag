# Forge Docs

This folder contains architecture notes and tool contracts for Forge.

## Structure

- `tool_rules.md`: cross-tool behavioral rules and conventions.
- `output_modes.md`: shared output-mode contract (`auto`, `pretty`, `kv`, `json`) and compatibility guidance.
- `adding_tools.md`: command scaffolding and contribution workflow for new tools.
- `dupes_tool.md`: `forge dupes` duplicate-detection behavior and output.
- `snapshot_architecture.md`: snapshot schema, canonical hashing, tag normalization, and safety constraints.
- `relay_architecture.md`: Nostr-inspired relay design for events, locking, and coordination primitives.
- `backend_coordination.md`: S3 coordination/lease model and global blob GC design options.
- `hashmap_tool.md`: `forge hashmap` command model and mapping-table semantics.
- `tags_tool.md`: `forge tags` xattr tag-management behavior and output.
- `remote_tool.md`: `forge remote` global S3 backend configuration.
- `blob_tool.md`: `forge blob` deterministic encrypted blob commands and backend behavior.
- `vector_tool.md`: `forge vector` embedding coordinator and ingestion workflows.
- `file_hashing_via_xattrs.md`: hash cache metadata spec used by `forge hash`.

## Design Goals

- One binary, multiple composable tools.
- Consistent command UX and output formats.
- Shared contracts so tools interoperate cleanly.
