# AGENTS.md

Repository-specific instructions for coding agents working on Forge.

## Primary Policy

- Humans are the primary CLI consumers.
- Agent-friendly behavior is required as a first-class secondary goal.
- Prefer additive machine interfaces over replacing human-oriented UX.

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
