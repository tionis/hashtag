# Forge Dupes Skill

Use this skill to detect duplicate files by content hash.

## Primary Commands

- Scan directory: `forge dupes [path] -output json`
- Size threshold: `forge dupes [path] -min-size 1048576 -output json`
- Paths-only output: `forge dupes [path] -output paths`

## Key Flags

- `-min-size`: minimum file size to include.
- `-cache`: use checksum xattr cache.
- `-update-cache`: write missing cache entries.
- `-output`: `auto|pretty|table|json|paths|paths0`.
