# Adding Tools

Forge uses `cobra` for command scaffolding.

## Where to Add Commands

- Root command setup: `cli.go`
- Existing tool implementation:
  - hash: `main.go`
  - snapshot: `snapshot.go`
  - snapshot query/inspect helpers: `snapshot_query.go`
  - hash mappings: `hashmap.go`

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

## Checklist

- [ ] Command help is clear.
- [ ] Errors are actionable.
- [ ] Output format follows `docs/tool_rules.md`.
- [ ] Tests cover happy path and key failure modes.
- [ ] README and docs updated.
