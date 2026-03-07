# AGENTS.md

Repository-specific instructions for coding agents working on Forge.

## Primary Policy

- Humans are the primary CLI consumers.
- Agent-friendly behavior is required as a first-class secondary goal.
- Prefer additive machine interfaces over replacing human-oriented UX.

## Project Purpose

- Forge is a single binary for filesystem-heavy local tools plus remote-backed workflows.
- Canonical content identity is BLAKE3; metadata/state is SQLite-first.
- Remote/shared behavior is driven by signed S3-backed global config.

## Required Reading

- `docs/project_architecture.md` (purpose, assumptions, architecture, module boundaries)
- `docs/output_modes.md` (output contract)
- `docs/ai_cli_design.md` (human-first + agent-safe CLI design)
- tool-specific docs for any touched command surface

## Architecture and Module Boundaries

1. CLI composition
- `cli.go` owns command tree and flag wiring.
- `runXCommand(args []string)` functions own parsing + execution for command surfaces.

2. Domain command modules
- Top-level files generally map 1:1 to tool domains (`snap.go`, `snapshot.go`, `blob.go`, `remote_*.go`, `vector.go`, etc.).
- Keep domain logic close to command modules unless shared reuse is substantial.

3. Internal reusable packages
- `internal/forgeconfig`: path/env resolution.
- `internal/vectorforge`: vector service internals.
- `internal/ingestclient`: ingest/hydration helpers.
- Add new `internal/*` modules only for clear multi-surface reuse.

4. Remote/trust/replication
- Keep backend session, trust validation, lease logic, and replication coordination centralized.
- Do not duplicate remote capability handling across tools.

## Implementation Patterns

1. Command implementation pattern
- Wire flags in `cli.go`.
- Parse with `pflag` in `runXCommand`.
- Apply `applyCommandFlagConventions(fs)` and `normalizePFlagArgs(fs, args)`.
- Render via typed output structs and dedicated `render...Output()` functions.

2. Contract pattern
- Treat JSON output as stable API.
- Add bounded selectors (`-limit`, ranges, filters) for large outputs.
- Keep machine output deterministic and parse-safe.

3. Safety pattern
- For mutation/destructive flows, require explicit execution (`-apply`, `-dry-run`, strict flags as relevant).

## Required Rules For CLI Changes

1. Keep human defaults.
- Preserve readable terminal UX and task-oriented `--help`.
- Do not force humans into JSON-first workflows.

2. Provide stable machine output.
- Any new command that returns structured data must support `-output json`.
- Treat JSON output as a compatibility contract.
- Add/update tests that validate JSON shape for new fields/commands.

3. Keep mutation safe.
- For destructive/state-changing actions, implement preview-first (`-apply`) or `-dry-run`.
- Avoid implicit destructive behavior without an explicit execution flag.

4. Bound output for large data.
- Add controls such as `-limit`, selectors, or range filters for list/history commands.
- Avoid unbounded defaults that are hostile to both humans and LLM context windows.

5. Use structured input when flags become lossy.
- If command input is nested/bulk, add a JSON/file input path in addition to convenience flags.

6. Keep machine parsing deterministic.
- Do not rely on parsing human-readable tables/prose in automation.
- In JSON mode, keep stdout parseable and avoid unrelated noise.

## Design Reference

- See `docs/ai_cli_design.md` for the distilled approach and rollout guidance.

## Embedded Skills

- Forge ships built-in skills in the binary for exposed feature areas.
- Use `forge skills list` to discover bundled skills.
- Use `forge skills install -dir <path>` to materialize them to a runtime skill directory.

## Skill Maintenance Rules

1. Add skills for new exposed features.
- If a change introduces a new top-level command, subcommand family, or materially new workflow, add or extend the corresponding embedded skill under `embedded_skills/<name>/SKILL.md`.

2. Keep skills aligned with behavior changes.
- If flags, defaults, output contract, safety semantics, or operational caveats change, update affected skill files in the same change.

3. Treat skills as part of the CLI contract.
- Skill docs are user/agent-facing operational guidance and must stay accurate.
- Do not merge behavior changes that make related skill content stale.

4. Verify coverage in PR scope.
- For CLI-affecting work, explicitly check whether one or more skills need updates.
- Include skill updates in the same commit series as the behavior/documentation change when relevant.

## Change Checklist (Required)

For behavior, contract, or architecture-impacting changes, update all relevant artifacts in the same change set:

1. Code and tests
- Add/adjust tests for new flags, selector logic, and JSON output contracts.

2. Human docs
- Update `README.md` for user-facing CLI behavior and flags.
- Update tool/architecture docs under `docs/`.

3. Agent docs
- Update `AGENTS.md` when contributor workflow or constraints change.
- Update embedded skills under `embedded_skills/` when command semantics change.

4. Module placement
- Validate that new code respects module boundaries from `docs/project_architecture.md`.
