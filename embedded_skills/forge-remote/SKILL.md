# Forge Remote Skill

Use this skill to initialize and maintain signed global S3 config.

## Primary Commands

- Initialize config: `forge remote config init -signing-key <key> -output json`
- Show config: `forge remote config show -output json`
- Update values: `forge remote config set ... -signing-key <key> -output json`
- List trust nodes: `forge remote config node list -output json`
- Add node: `forge remote config node add -name ... -public-key ... -roles ... -signing-key <key> -output json`
- Update node: `forge remote config node update ... -signing-key <key> -output json`
- Remove node: `forge remote config node remove -name ... -signing-key <key> -output json`

## Notes

- Config signatures are verified against compiled trust roots.
- Use passphrase flags or interactive passphrase prompt for encrypted signing keys.
