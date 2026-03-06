# Human-First, Agent-Friendly CLI Design

This document distills ideas from Justin Poehnelt's article:
<https://justin.poehnelt.com/posts/rewrite-your-cli-for-ai-agents/>

Forge's policy is human-primary UX with a stable machine contract.

## Goals

- Keep the default CLI excellent for humans (readable help, sensible defaults, concise output).
- Make automation and LLM usage reliable without scraping human text.
- Keep behavior deterministic and safe for destructive operations.

## Core Principles

1. Separate presentation from contract.
- Human output (`pretty`, help text) is for people.
- Machine output (`json` or `kv`) is the integration contract.
- Never require agents to parse prose/help text.

2. Always provide structured output for data commands.
- New commands that return data must support `-output json`.
- JSON shape should be stable and explicit.
- Keep field names predictable and avoid breaking renames.

3. Keep human defaults, add machine escape hatches.
- Default mode remains human-friendly (`auto -> pretty` on TTY).
- Add machine controls where needed:
  - `-output json`
  - `-limit` / pagination for large lists
  - selectors (`-from`, `-to`, `-kind`, etc.) to constrain scope

4. Provide structured input for complex operations.
- For nested or bulk input, add a raw JSON/file path option in addition to convenience flags.
- Keep "quick path" flags for humans; add "full fidelity" input for agents.

5. Make mutating operations safe and explicit.
- Prefer preview-first or explicit apply gates for destructive actions.
- Use patterns like:
  - preview by default, then `-apply`
  - `-dry-run` + `-apply`
- Return deterministic non-zero exits on failure.

6. Keep errors machine-usable.
- Error text should be clear and specific.
- For commands with JSON mode, return parseable JSON on success; avoid mixing extra prose into stdout.
- Use stderr for diagnostics not part of the data contract.

7. Reduce context-window pressure.
- Avoid dumping unbounded text by default.
- Provide summary + filtering options.
- For long outputs, support deterministic slicing (`-limit`, paging, or ID range filters).

8. Prefer explicit schemas over implied parsing.
- If downstream tooling depends on output structure, lock it with tests.
- Add tests for JSON shape (required fields, types, and key semantics).

## Forge Implementation Guidance

When adding or changing a command:

1. Human UX:
- Ensure `--help` is readable and task-oriented.
- Keep default output practical for terminal use.

2. Machine UX:
- Add `-output json` (and `kv` where it already fits Forge patterns).
- Ensure output fields are stable and documented.

3. Safety:
- If the command changes state, include preview/apply semantics or a dry-run path.

4. Scale:
- Add scope controls (`-limit`, selectors) for list/history outputs.

5. Tests:
- Add/extend tests for JSON output and critical error behavior.

6. Docs:
- Update `README.md` and relevant tool docs with machine-usage examples.

## Suggested Adoption Backlog

P0:
- Enforce `-output json` on all new data-returning commands.
- Enforce preview/apply semantics for all new destructive commands.

P1:
- Add structured input (`-input-json` or `-input-file`) where flag-only UX is too lossy.
- Add consistent pagination/limit controls for all high-cardinality listings.

P2:
- Add optional introspection command(s) for command schemas/capabilities if needed (e.g., `forge describe ...`).

