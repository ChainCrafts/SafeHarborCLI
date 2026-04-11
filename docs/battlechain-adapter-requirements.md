# BattleChain Adapter Requirements

The BattleChain binding in V1 is explicit, deployment-aware, and post-compile.

BattleChain metadata lives under `adapters.battlechain`, not as a core-defining top-level block.

`shcli compile` can emit a valid manifest with no `adapters` block at all.

`shcli battlechain prepare`, `shcli battlechain create-agreement`, and `shcli battlechain request-attack` are the lifecycle steps that validate or attach BattleChain-specific linkage after review and compile.

`deployment` must identify:

- target `chainId`
- human-readable `network`
- one or more deployed contracts with `name`, `address`, `abiRef`, `bytecodeDigestAlgo`, and `bytecodeHash`

V1 freezes deployment bytecode binding to:

- `bytecodeDigestAlgo = keccak256`
- `bytecodeHash` as a 32-byte hex digest

When a manifest is BattleChain-linked, `adapters.battlechain` must identify:

- `agreementAddress`
- `lifecycleState`
- `bountyPct`
- `recoveryAddress`
- `commitmentWindowDays`

This lets a manifest bind reviewed source analysis to a specific deployment surface and the agreement metadata that governs the BattleChain bounty lifecycle without making BattleChain core-defining schema baggage.

Attack execution constraints live under `scope.attackFlow`:

- `allowedModes`: a non-empty set of `single_tx`, `multi_tx`, and `multi_block`

This replaces the old contradictory `mode + multiTxAllowed + multiBlockAllowed` shape.

`allowedModes` means the exploit-execution modes that are in scope for accepted evidence against the manifest revision. A report that depends on a mode outside this set is outside the accepted attack-flow scope for that manifest.

Operationally:

- `battlechain prepare` should fail fast on deployment or network mismatches
- `battlechain create-agreement` should only run once compile output and deployment prerequisites are ready
- `battlechain request-attack` should require both a compiled manifest and `adapters.battlechain` linkage

The exact `lifecycleState` vocabulary remains BattleChain adapter data rather than a SafeHarbor core-standard concern in V1.
