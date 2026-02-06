# Forge

`forge` is a multi-tool CLI workspace for filesystem workflows.

Current tools:
- `forge hash`: concurrent file hashing with xattr caching (`user.checksum.*`).
- `forge snapshot`: metadata-only filesystem snapshots with history and diff.

## Install

```bash
go install github.com/tionis/forge@latest
```

## CLI Overview

```bash
forge <command> [options]
```

Top-level commands:
- `forge hash`
- `forge snapshot`
- `forge completion`

Compatibility mode:
- `forge [hash options] [path]` is shorthand for `forge hash [hash options] [path]`.

## Hash Tool

```bash
forge hash [flags] [path]
```

Flags:
- `-w`: number of workers (default `NumCPU`)
- `-v`: verbose output
- `-algos`: comma-separated algorithms (default `blake3`)
- `-clean`: force cache invalidation and re-hash
- `-remove`: remove all `user.checksum.*` xattrs

Examples:

```bash
forge hash .
forge hash -algos blake3,sha256 /data
forge hash -remove /data
```

## Snapshot Tool

Create snapshot:

```bash
forge snapshot [flags] [path]
# or
forge snapshot create [flags] [path]
```

History:

```bash
forge snapshot history [flags] [path]
```

Diff:

```bash
forge snapshot diff [flags] [path]
```

Snapshot flags:
- `-db`: snapshot DB path (default from `${FORGE_SNAPSHOT_DB}` or `${XDG_DATA_HOME}/forge/snapshot.db`, fallback `~/.local/share/forge/snapshot.db`)
- `-v`: verbose output (create)
- `-limit`: max rows (history)
- `-from`: older snapshot time in unix ns (diff)
- `-to`: newer snapshot time in unix ns (diff)

Migration compatibility:
- legacy `${HASHTAG_SNAPSHOT_DB}` is still honored.

Diff behavior:
- Without `-from/-to`: compares the two newest snapshots for the path.
- With `-from` and `-to`: compares those specific snapshots.

Diff codes:
- `A`: added path
- `D`: removed path
- `M`: modified path (hash and/or metadata)
- `T`: type changed (`file`/`tree`/`symlink`)

## Documentation

- Docs index: [`docs/README.md`](docs/README.md)
- Tool rules: [`docs/tool_rules.md`](docs/tool_rules.md)
- Adding tools: [`docs/adding_tools.md`](docs/adding_tools.md)
- Hash metadata spec: [`docs/file_hashing_via_xattrs.md`](docs/file_hashing_via_xattrs.md)

## License

MIT (`LICENSE`).
