# Operations

This document covers runtime lifecycle guidance for long-running Forge services and key rotation.

## Daemon Lifecycle

### `forge replicate daemon`

Purpose:

- continuously stream `snapshot.db` (age-encrypted) and `refs.db` (plain) to S3 using Litestream.

Operational baseline:

- run one daemon instance per node.
- ensure `FORGE_S3_*` bootstrap env and remote config are available.
- ensure `FORGE_NODE_NAME` and `FORGE_NODE_SSH_KEY` are configured.
- for encrypted SSH keys, provide `FORGE_NODE_SSH_KEY_PASSPHRASE` or run with interactive TTY.

Startup checks:

- `forge config show -output kv` to verify resolved local paths.
- `forge remote config show -output kv` to verify signed remote config and capabilities.
- `forge replicate daemon -snapshot-db ... -refs-db ...` for explicit path overrides where needed.

Restart behavior:

- service is designed to be restarted by a supervisor (systemd/runit/etc.).
- replication resumes from Litestream state stored in replica location.

### `forge vector serve`

Purpose:

- run embedding API + queue workers with default replication of both:
  - `vector/embeddings.db`
  - `vector/queue.db`

Lease/fencing:

- acquires writer lease before write-serving.
- exits write-serving path on lease loss.
- supervisor should restart after lease-related exits.

Recommended runtime pattern:

- run under a process supervisor with `Restart=always`.
- monitor logs for:
  - `lease lost`
  - `litestream restore`
  - queue recovery/reset messages.

## Key Rotation and Rekeying

## Trust Root Rotation

Current trust model:

- root trust public key is compiled into binaries (`forge.pub` at build time).

Rotation steps:

1. Generate new root signing key pair.
2. Update compiled trust root in source (`forge.pub`) and rebuild binaries.
3. Roll out binaries to all nodes before switching active signer.
4. Publish signed remote config updates with new signer.

Notes:

- trust root is non-overridable at runtime by design.
- old binaries will reject config signed only by unknown new roots.

## Node Key Rotation

Node key roles:

- node SSH key acts as recipient for encrypted replicated data (for example snapshot DB stream).

Rotation steps per node:

1. Generate new node SSH key pair.
2. Update trust node mapping in remote config (`forge remote config node update`).
3. Update node runtime env (`FORGE_NODE_SSH_KEY`) to new private key.
4. Restart node daemons/services.

## Snapshot Recipient Rekeying

Snapshot replication recipients include:

- node SSH public key
- trusted root key(s)

Practical rekey flow:

1. rotate trust/node keys as above.
2. restart `forge replicate daemon` so new recipients are applied for future LTX files.
3. keep old private keys available during transition for historical replica reads if required.

## Signed Remote Config Key Rotation

For config signing key updates:

1. keep trust root compatibility in place.
2. use `forge remote config init` / `forge remote config set` with new `-signing-key`.
3. verify `document_version` monotonicity and signature metadata via `forge remote config show`.

## Incident Response Notes

- If lease anomalies are observed:
  - check remote lease object state with `forge vector lease-status`.
  - verify capability flags in remote config (`conditional_if_none_match`, `conditional_if_match`).
- If remote inventory cache appears stale:
  - run `forge blob inventory publish` from GC worker path after cleanup cycle.
  - verify `gc_info` generation changed and clients rehydrated.
