# Forge Blob Skill

Use this skill for convergent blob storage workflows.

## Primary Commands

- Put blob: `forge blob put <path> -output json`
- Put and upload: `forge blob put <path> -remote -output json`
- Get blob: `forge blob get -cid <hash> -out <path> -output json`
- List local mappings: `forge blob ls -limit 20 -output json`
- Remove blob data: `forge blob rm -cid <hash> -local=true -remote=false -output json`
- Local GC: `forge blob gc -apply -output json`
- Publish remote inventory: `forge blob inventory publish -generation <id> -output json`

## Key Flags

- `-db`: local blob metadata DB.
- `-cache`: local plaintext blob cache directory.
- `-refs-db`: local reference roots database.
- `-remote`: include remote S3 operations.
