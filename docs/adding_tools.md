# Adding Tools

Forge uses `cobra` for command scaffolding.
Review `project_architecture.md` before introducing new modules or cross-tool abstractions.

## Where to Add Commands

- Root command setup: `cli.go`
- Existing tool implementation:
  - hash: `main.go`
  - dupes: `dupes.go`
  - snapshot: `snapshot.go`
  - snapshot query/inspect helpers: `snapshot_query.go`
  - hash mappings: `hashmap.go`
  - tag management: `tags.go`

## Steps

1. Add a new command constructor in `cli.go` (similar to `newHashCommand` / `newSnapshotCommand`).
2. Register it in `newRootCommand()`.
3. Keep command logic in a dedicated file (`<tool>.go`) with test coverage in `<tool>_test.go`.
4. Use `RunE` and return errors (do not call `os.Exit` from tool logic).
5. Add docs and usage examples in `README.md` and link from `docs/README.md`.

## Recommended Patterns

- Use `DisableFlagParsing: true` when reusing existing `flag.FlagSet` handlers.
- Prefer explicit subcommands for non-trivial tools (`create`, `history`, `diff`, etc.).
- Keep tool-specific persistence logic encapsulated per file.
- For commands with structured output, add `-output auto|pretty|kv|json` and follow `docs/tool_rules.md`.
- In `auto` mode, prefer `pretty` on terminals and a script-safe mode for non-interactive stdout.

## Checklist

- [ ] Command help is clear.
- [ ] Errors are actionable.
- [ ] Output format follows `docs/tool_rules.md`.
- [ ] Script-safe output (`kv`/`json` or equivalent) is documented and tested.
- [ ] Tests cover happy path and key failure modes.
- [ ] README and docs updated.
