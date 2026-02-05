Here is the revised `README.md`. I have adjusted the tone to be strictly technical and professional, removing the "hype" language. I also updated the Go module path and added the reference to your specification document.

---

# HashTag

**HashTag** is a concurrent CLI tool for efficiently managing file hash caching on Linux systems. It recursively scans directories, computes file hashes (e.g., SHA-256, BLAKE3), and persists the results using filesystem Extended Attributes (`xattrs`).

This tool is intended for workflows requiring repeated access to file integrity data without incurring the I/O cost of re-reading file contents on every execution. It is compatible with Git LFS object IDs (SHA-256).

## Features

* **Concurrency:** Utilizes a worker pool to parallelize file operations, maximizing throughput on modern storage media.
* **Multi-Algorithm:** Supports SHA-256, SHA-1, SHA-224, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3 (224, 256, 384, 512), BLAKE2b (256, 384, 512), BLAKE2s, BLAKE3, MD5, CRC32, CRC64, Adler32, RIPEMD-160, and xxHash.
* **Memory Efficiency:** Implements buffer pooling to minimize memory allocations and garbage collection overhead during high-throughput I/O.
* **Atomic Caching:** Validates file modification times (`mtime`) before and after reading to ensure consistency between the file content and the cached hash.
* **Smart Invalidation:** Intelligent cache management that reuses existing hashes where possible and performs atomic invalidation upon file modification.
* **Cleanup Utility:** Includes a built-in mechanism to remove all checksum metadata from files.
* **Zero-Read Access:** checks existing metadata against the current file state. If the cache is valid, the hash is retrieved without reading the file from disk.

## Prerequisites

* **OS:** Linux (Requires kernel support for `syscall.Getxattr`/`Setxattr`).
* **Filesystem:** Must support Extended Attributes (e.g., ext4, xfs, btrfs, zfs).
* **Go:** Go 1.20+ (for building).

## Installation

You can install the tool directly using the Go toolchain:

```bash
go install github.com/tionis/hashtag@latest

```

Alternatively, you can build from source:

```bash
git clone https://github.com/tionis/hashtag
cd hashtag
go build -o hashtag main.go

```

## Usage

```bash
hashtag [flags] [path]

```

### Flags

| Flag | Type | Description | Default |
| --- | --- | --- | --- |
| `-w` | `int` | Number of parallel workers. | `NumCPU` |
| `-v` | `bool` | Enable verbose logging. | `false` |
| `-algos` | `string` | Comma-separated list of hash algorithms. | `sha256` |
| `-clean` | `bool` | Force invalidation of existing caches (re-hash everything). | `false` |
| `-remove` | `bool` | Remove all checksum attributes from files. | `false` |

### Examples

**Standard execution:**

```bash
# Process the current directory using default SHA-256
hashtag .

```

**Multi-hash execution:**

```bash
# Compute both SHA-256 and BLAKE3
hashtag -algos sha256,blake3 /mnt/data

```

**Clearing metadata:**

```bash
# Remove all user.checksum.* attributes recursively
hashtag -remove /mnt/data

```

**High concurrency:**

```bash
# Process a specific directory with 32 workers
hashtag -w 32 /mnt/data/images

```

## Technical Specification

This tool implements the specification defined in [`docs/file_hashing_via_xattrs.md`](docs/file_hashing_via_xattrs.md).

### Metadata Schema

The tool utilizes the `user.checksum` namespace.

| Attribute Key | Value Format | Description |
| --- | --- | --- |
| `user.checksum.<algo>` | Hex String | The digest of the file content (e.g., `user.checksum.sha256`, `user.checksum.blake3`). |
| `user.checksum.mtime` | Unix Timestamp | The `mtime` (seconds) of the file when the hash was computed. |

### Verification

You can verify the attributes using the `getfattr` utility:

```bash
$ getfattr -d large_file.iso

# file: large_file.iso
user.checksum.mtime="1717654321"
user.checksum.sha256="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
user.checksum.blake3="..."

```

## Logic Flow

1. **Scan:** Recursively identifies regular files (excluding `.git` directories).
2. **Stat:** Retrieves the current `mtime`.
3. **Cache Lookup:**
* Reads `user.checksum.mtime`.
* **Hit:** If the cached `mtime` matches the filesystem `mtime`, the existing hash is skipped.
* **Miss:** If the `mtime` differs or attributes are missing, the file is queued for hashing.


4. **Compute:**
* Reads the file stream and calculates the SHA-256 hash.


5. **Validation:** Performs a second `stat` after reading. If the `mtime` changed during the read operation, the cache update is aborted to prevent race conditions.
6. **Persist:** Writes the new hash and `mtime` to the extended attributes.

## License

MIT License. See `LICENSE` for details.
