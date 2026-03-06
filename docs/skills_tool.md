# Skills Tool

`forge skills` exposes embedded skill definitions that ship in the Forge binary.

## Goals

- Keep skill setup portable across machines.
- Allow agent runtimes to bootstrap from the same command docs used by humans.
- Avoid out-of-band skill packaging.

## Commands

List bundled skills:

```bash
forge skills list -output json
```

Install all bundled skills:

```bash
forge skills install -dir ~/.codex/skills
```

Install a subset:

```bash
forge skills install -dir ~/.codex/skills -skills forge-hash,forge-snapshot
```

Preview writes:

```bash
forge skills install -dir ~/.codex/skills -dry-run -output json
```

## Output Contract

`forge skills list` output fields:

- `count`
- `skills[]` with:
  - `name`
  - `file_count`

`forge skills install` output fields:

- `destination`
- `force`
- `dry_run`
- `requested`
- `embedded`
- `selected`
- `installed`
- `planned`
- `skipped`
- `files_written`
- `skills[]` with:
  - `name`
  - `status`
  - `path`
  - `file_count`

Status values:

- `installed`
- `overwritten`
- `would_install`
- `would_overwrite`
- `skipped_exists`

## Embedded Skill Names

- `forge-overview`
- `forge-hash`
- `forge-dupes`
- `forge-snap`
- `forge-snapshot`
- `forge-hashmap`
- `forge-tags`
- `forge-config`
- `forge-remote`
- `forge-blob`
- `forge-vector`
- `forge-replicate`
