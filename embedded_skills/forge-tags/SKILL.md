# Forge Tags Skill

Use this skill to manage `user.xdg.tags` metadata on paths.

## Primary Commands

- Read tags: `forge tags get [path] -output json`
- Replace tags: `forge tags set [path] -tags a,b -output json`
- Add tags: `forge tags add [path] -tags a,b -output json`
- Remove tags: `forge tags remove [path] -tags a,b -output json`
- Clear tags: `forge tags clear [path] -output json`

## Key Flags

- `-tags`: comma/semicolon separated tag list.
- `-output`: `auto|pretty|kv|json`.
