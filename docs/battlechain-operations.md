# BattleChain Operations

BattleChain commands are adapter-layer checks around a compiled SafeHarbor manifest.

They do not send transactions in v0.1.

## Config

```toml
[battlechain]
network = "battlechain-testnet"
chain_id = 627
rpc_url = "https://rpc.example"
agreement_address = "0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8"
explorer_base_url = "https://explorer.example"
recovery_address = "0x91f0c3a7d4b8e2c6a1f5d9b3e7c0a4d8f2b6c1e5"
bounty_pct = 10
commitment_window_days = 30
lifecycle_state = "AGREEMENT_CREATED"
```

If the compiled manifest already contains `adapters.battlechain`, that manifest adapter metadata wins. Conflicting CLI or config overrides are rejected.

## Prepare

```sh
shcli battlechain prepare --config safeharbor.toml
```

Writes:

- `.safeharbor/battlechain/prepare.json`

Checks:

- compiled manifest presence
- reviewed input presence
- draft metadata input presence
- summary presence
- BattleChain network and chain ID
- manifest deployment compatibility
- agreement adapter metadata

## Status

```sh
shcli status --config safeharbor.toml
```

Prints a compact view of:

- manifest path
- agreement address
- lifecycle state
- network
- remote chain status when RPC is configured

## Doctor

```sh
shcli doctor --config safeharbor.toml
```

Prints grouped checks:

- `local_artifacts`
- `network_config`
- `agreement_metadata`
- `remote`

The command exits non-zero when any check fails.

## Registry Publish Prepare / Verify

Registry publishing is separate from BattleChain readiness:

```toml
[registry]
address = "0x1111111111111111111111111111111111111111"
```

```sh
shcli registry publish --config safeharbor.toml --manifest-uri ipfs://...
```

Writes:

- `.safeharbor/registry/publish.json`

If `[battlechain].rpc_url` is configured, the command reads current registry state and records readback status. If no RPC URL is configured, it still writes the prepared payload and prints the calldata.
