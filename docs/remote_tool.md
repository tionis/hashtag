# Remote Tool

`forge remote` manages the global S3 configuration object used by backend-aware Forge features.

## Commands

- `forge remote config init [options]`
- `forge remote config show [options]`

`forge remote config init` probes S3 conditional-write behavior by default and stores detected capability flags in the config object:
- `conditional_if_none_match`
- `conditional_if_match`
- `response_checksums`
- `cache.remote_config_ttl_seconds`

You can disable probing and set capability flags manually:
- `-probe-capabilities=false`
- `-cap-if-none-match=<bool>`
- `-cap-if-match=<bool>`
- `-cap-response-checksums=<bool>`

Set config-cache TTL during init:
- `-config-cache-ttl=<seconds>`

## Bootstrap Environment

Remote config is read/written via S3 using environment bootstrap:

- `FORGE_S3_BUCKET` (required)
- `FORGE_S3_REGION` (default `us-east-1`)
- `FORGE_S3_ENDPOINT_URL` (optional)
- `FORGE_S3_ACCESS_KEY_ID` + `FORGE_S3_SECRET_ACCESS_KEY` (optional as pair)
- `FORGE_S3_SESSION_TOKEN` (optional)
- `FORGE_S3_FORCE_PATH_STYLE` (optional bool)
- `FORGE_REMOTE_CONFIG_KEY` (default `forge/config.json`)
- `FORGE_REMOTE_DB` (optional local SQLite cache path; default `${XDG_DATA_HOME}/forge/remote.db`)

Remote-backed operations read remote config through local SQLite cache and refresh from S3 once TTL expires.

## Config Intent

The object stores global backend capabilities and policy used across tools, including:

- S3 conditional write support flags
- Global object prefixes
- Encryption policy for non-config data

## Coordination Direction

For replicated single-writer services (for example `forge vector serve -replication`), Forge uses S3-backed writer leases with capability-driven behavior:

- `hard` mode: CAS/fencing with `If-Match` + `If-None-Match`
- `soft` mode: best-effort advisory lease for weak S3 backends
- `off` mode: no lease

The global remote config is the intended place to carry these coordination defaults so all tools can enforce a consistent policy.
