# Forge Docs

This folder contains architecture notes and tool contracts for Forge.

## Structure

- `tool_rules.md`: cross-tool behavioral rules and conventions.
- `adding_tools.md`: command scaffolding and contribution workflow for new tools.
- `file_hashing_via_xattrs.md`: hash cache metadata spec used by `forge hash`.

## Design Goals

- One binary, multiple composable tools.
- Consistent command UX and output formats.
- Shared contracts so tools interoperate cleanly.
