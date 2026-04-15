# BattleChain Adapter Requirements

The BattleChain binding in v0.1 is explicit, deployment-aware, and post-compile.

BattleChain metadata lives under `adapters.battlechain`, not as a required top-level manifest block. A compiled manifest can be valid without BattleChain adapter metadata.

## Manifest Inputs

`deployment` must identify:

- `chainId`
- `network`
- deployed contract `name`
- deployed contract `address`
- `abiRef`
- `bytecodeDigestAlgo`
- `bytecodeHash`

When a manifest is BattleChain-linked, `adapters.battlechain` may identify:

- `agreementAddress`
- `lifecycleState`
- `bountyPct`
- `recoveryAddress`
- `commitmentWindowDays`

These fields bind reviewed manifest content to BattleChain agreement metadata without making BattleChain the core manifest standard.

## Implemented Adapter Commands

`shcli battlechain prepare`

- Consumes the compiled manifest.
- Resolves BattleChain network/config values.
- Writes `.safeharbor/battlechain/prepare.json`.
- Emits readiness checks and next steps.
- Does not submit transactions.

`shcli status`

- Shows local agreement linkage and lifecycle state.
- Uses RPC reads only when `[battlechain].rpc_url` or `--rpc-url` is present.
- Falls back to local adapter metadata when remote state is unavailable.

`shcli doctor`

- Checks local artifacts, network config, adapter metadata, and optional remote connectivity.
- Prints path-bearing failures and fix hints.
- Exits non-zero when failing checks are present.

## Registry Boundary

`shcli registry publish` is separate from BattleChain lifecycle checks.

- Registry config lives under `[registry]`.
- Registry publish output lives at `.safeharbor/registry/publish.json`.
- Registry publish prepares calldata and optional readback verification only.
- Signers, owner authorization, and transaction submission are outside v0.1 scope.

## Attack Flow Scope

Attack execution constraints live under `scope.attackFlow.allowedModes`.

Allowed values are:

- `single_tx`
- `multi_tx`
- `multi_block`

A report that depends on a mode outside the manifest's allowed modes is outside the accepted attack-flow scope for that manifest revision.
