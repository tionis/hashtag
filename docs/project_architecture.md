# Forge Project Architecture

This document is the contributor baseline for both humans and coding agents.

## Purpose

Forge is a single binary that bundles heavily opinionated filesystem and data-workflow utilities.

Primary goals:

- provide fast local workflows (`hash`, `dupes`, `snap`, `snapshot`, `tags`, `hashmap`)
- provide shared backend workflows (remote config, encrypted blob storage, replication, vector service)
- keep command UX human-first while preserving stable machine contracts (`-output json`)

## Design Assumptions

- Linux-first environment and filesystem-heavy workflows.
- BLAKE3 is the canonical content identity across components.
- SQLite is the default metadata/state substrate.
- S3-compatible object storage is the current backend baseline.
- Security model uses signed remote config + SSH/age key material for trust and encryption paths.
- Remote backends may have weak conditional-write semantics; coordination features must degrade safely.

## High-Level Architecture

1. CLI Composition Layer
- `main.go`: entrypoint and shared hash command.
- `cli.go`: Cobra command tree and flag wiring.
- Pattern: each subcommand delegates to `runXCommand(args []string)`.

2. Tool Domain Layer
- Top-level files grouped by tool/workflow:
  - `snap.go`, `snapshot.go`, `snapshot_query.go`
  - `blob.go`, `blob_refs.go`, `blob_inventory_cache.go`
  - `remote_config.go`, `remote_config_manage.go`, `remote_*`
  - `vector.go`, `replication_daemon.go`
  - `dupes.go`, `hashmap.go`, `tags.go`, `config_show.go`

3. Internal Packages
- `internal/forgeconfig`: local path/env resolution.
- `internal/vectorforge`: vector service internals (queue/worker/http/replication).
- `internal/ingestclient`: local ingest/hydration helpers.

4. Persistence and Backend Layer
- Local SQLite DBs under `${FORGE_DATA_DIR}`.
- Local caches under `${FORGE_CACHE_DIR}`.
- Remote S3 object layout configured via signed global remote config.

## Local State Model

Default path roots:

- data: `${XDG_DATA_HOME:-~/.local/share}/forge`
- cache: `${XDG_CACHE_HOME:-~/.cache}/forge`

Typical DB roles:

- `snapshot.db`: content-addressed snapshot trees/pointers/tags/hash mappings
- `blob.db`: local CID/OID mapping and blob metadata
- `refs.db`: local keep-set references used for GC/replication workflows
- `remote.db`: local cache/trust state for remote config
- `s3-blobs.db` + `s3-blobs-overlay.db`: remote blob inventory cache and local overlay
- `vector/queue.db`, `vector/embeddings.db`, `embeddings.db` (hydrated read path)

## Remote/Trust Model

- Remote config is signed and verified against compiled trust roots (`forge.pub`).
- Runtime behavior for remote-aware tools is driven by remote config (prefixes, capabilities, lease policy).
- Replication uses Litestream + age/SSH recipient strategy depending on DB/workflow.

## CLI and Output Contracts

- Human defaults remain primary.
- Data-producing commands must support `-output json`.
- `json` output is a compatibility contract; avoid breaking key names/types.
- Use `kv` as secondary machine-friendly mode where already established.
- Use bounded output controls (`-limit`, selectors, filters) for high-cardinality results.

## Command Implementation Pattern

When adding/changing a command:

1. Add Cobra wiring in `cli.go`.
2. Implement `runXCommand(args []string)` with `pflag` parsing.
3. Apply `applyCommandFlagConventions(fs)` + `normalizePFlagArgs(fs, args)`.
4. Return typed output structs and render via `render...Output(mode, out)`.
5. Keep machine output deterministic and parse-safe.
6. Add/extend tests for JSON contract and failure behavior.
7. Update docs and embedded skills if behavior changed.

## Module Boundaries

- Keep cross-tool helpers small and generic; avoid hidden coupling.
- Prefer extending existing domain files over introducing broad shared abstractions too early.
- Create a new `internal/<module>` package when logic is substantial and reused by multiple command surfaces.
- Keep backend/session/trust behavior centralized (`remote_*`, replication helpers) to avoid drift.

## Testing Expectations

- Unit tests next to command/domain files (`*_test.go`).
- Mock external tools/services where possible (`snapper`, remote stores).
- Cover:
  - JSON output shapes
  - selector/flag conflict logic
  - safety semantics (`-apply`, `-dry-run`, strict modes)
  - deterministic fallback/degradation behavior

## Documentation Contract

Any behavior or contract change must update, in the same change set where relevant:

- `README.md` (user-facing flags/usage)
- tool docs in `docs/*.md`
- `AGENTS.md` (agent workflow rules)
- `embedded_skills/<skill>/SKILL.md` for affected tool surfaces

## How To Extend Safely

Before merging a feature:

1. Confirm module placement follows boundaries above.
2. Confirm output contract stability and tests.
3. Confirm docs + skill updates are included.
4. Confirm remote/security assumptions are explicit for backend-facing changes.
