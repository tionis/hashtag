# Tool Rules

These rules define how Forge tools should behave so commands can be composed reliably.

## Command Shape

- Top-level pattern: `forge <tool> <subcommand> [flags] [args]`.
- Each tool should provide a concise `Short` description and useful help text.
- Keep command names stable once released.

## Path Handling

- Resolve user-provided filesystem paths to absolute paths before persistence.
- Output canonical paths in command results.
- Avoid implicit CWD-dependent state in persisted data.

## Output Conventions

- Prefer machine-readable line output for primary fields (`key=value`).
- Use tabular sections only for repeated rows.
- Keep field names stable across versions when possible.

## Error Behavior

- Return structured, actionable errors.
- Avoid partial writes when an operation fails mid-run.
- If fallbacks are used, keep them explicit and deterministic.

## Data and Hashing

- Use deterministic serialization for hashed objects.
- Include an explicit schema/version marker in hash input formats.
- Record hash algorithm alongside stored hashes.

## Database Practices

- Use schema migrations or idempotent schema init.
- Add indexes for expected lookup paths.
- Keep writes transactional for multi-step operations.

## Compatibility

- Preserve existing stable command behavior unless intentionally versioned.
- Additive changes are preferred over breaking changes.
- Document incompatible changes in `README.md` and release notes.
