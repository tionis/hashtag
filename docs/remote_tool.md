# Remote Tool

`forge remote` manages the global S3 configuration object used by backend-aware Forge features.

## Commands

- `forge remote config init [options]`
- `forge remote config show [options]`
- `forge remote config set [options]`
- `forge remote config node list [options]`
- `forge remote config node add [options]`
- `forge remote config node update [options]`
- `forge remote config node remove [options]`

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

Set vector writer lease policy during init:
- `-vector-lease-mode=auto|hard|soft|off`
- `-vector-lease-resource=<resource-key>`
- `-vector-lease-duration=<seconds>`
- `-vector-lease-renew-interval=<seconds>`

Signed config controls:

- `-signing-key=<path>` OpenSSH private key used to sign the config document
- `-signing-key-passphrase=<value>` passphrase for encrypted OpenSSH private key
- when passphrase is required and not provided, Forge prompts interactively (hidden input) on TTY sessions
- `-doc-version=<int64>` signed document version (`auto` if omitted)
- `-doc-expires-seconds=<seconds>` optional signed document expiry (`0` disables expiry)
- `-trust-nodes-file=<path>` optional JSON trust node list
- `-root-node-name=<name>` node name assigned to signing root key in trust map

Mutable update controls:

- `forge remote config set` updates selected config fields without rewriting all values.
- `forge remote config node ...` manages `trust.nodes` entries directly.
- update commands share signing controls and support `-doc-expires-seconds=-1` to preserve current expiry.

## Bootstrap Environment

Remote config is read/written via S3 using environment bootstrap:

- `FORGE_S3_BUCKET` (required)
- `FORGE_S3_REGION` (default `us-east-1`)
- `FORGE_S3_ENDPOINT_URL` (optional)
- `FORGE_S3_ACCESS_KEY_ID` + `FORGE_S3_SECRET_ACCESS_KEY` (optional as pair)
- `FORGE_S3_SESSION_TOKEN` (optional)
- `FORGE_S3_FORCE_PATH_STYLE` (optional bool)
- `FORGE_REMOTE_CONFIG_KEY` (default `forge/config.json`)
- `FORGE_PATH_REMOTE_DB` (optional local SQLite cache path; default `${FORGE_DATA_DIR}/remote.db`)
- `FORGE_TRUST_SIGNING_KEY` (optional default for `-signing-key`)
- `FORGE_TRUST_SIGNING_KEY_PASSPHRASE` (optional default for `-signing-key-passphrase`)

Trust roots are non-overridable and compiled from `forge.pub`.

Remote-backed operations read remote config through local SQLite cache and refresh from S3 once TTL expires.

## Trust Model

The remote config object is a signed envelope (`forge.signed_document.v1`) with:

- `document_type=remote_config`
- monotonic `version`
- optional `expires_at_utc`
- signer public key + detached signature
- canonical JSON payload (`remoteGlobalConfig`)

Forge verifies:

- signature validity against trusted root keys
- optional expiry
- monotonic anti-rollback state in local SQLite (`remote_trust_state`)

The payload also carries a signed trust node map (`trust.nodes`) for cross-node key identity metadata.

## Config Intent

The object stores global backend capabilities and policy used across tools, including:

- S3 conditional write support flags
- Global object prefixes
- Coordination policy (`coordination.vector_writer_lease.*`) for replicated single-writer services

## Coordination Direction

For replicated single-writer services (for example `forge vector serve -replication`), Forge uses S3-backed writer leases from global config (`coordination.vector_writer_lease`) with capability-driven behavior:

- `hard` mode: CAS/fencing with `If-Match` + `If-None-Match`
- `soft` mode: best-effort advisory lease for weak S3 backends
- `off` mode: no lease

The global remote config is the intended place to carry these coordination defaults so all tools can enforce a consistent policy.
