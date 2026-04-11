# SimpleVault Phase 0 Golden Manifest

This file pair is the handwritten Phase 0 freeze target for the SafeHarbor compiled manifest V1. It is not a generated sample and it is not a loose demo artifact.

## Why This Fixture

SimpleVault is intentionally small, but it still forces the manifest to express the hard parts of the standard:

- deployment-bound identity
- permissionless and privileged executable surfaces
- an explicit out-of-scope selector with a review reason
- a non-selector executable surface via `receive()`
- all three invariant truth layers
- evidence expectations and attack-flow limits
- BattleChain linkage as adapter metadata rather than a core-defining manifest block

## Protocol Shape Captured

- one deployed `SimpleVault` contract on `battlechain-testnet`
- stable contract identity via `scope.contracts[].id = vault_core`, which is what invariants reference
- permissionless user entry and exit via `deposit(uint256)`, `withdraw(uint256)`, and `receive()`
- privileged control via `pause()`, `setFeeBps(uint16)`, and `withdrawFees(uint256)`
- explicit exclusion of `rescueToken(address,uint256)` as an emergency recovery path outside the depositor-loss scope

No synthetic `USER` role appears in the manifest, and no `unknown` access state is used here because the Phase 0 fixture does not require unresolved access classification to stay honest.

The `roles[].holders` value is a deployment-bound snapshot for this manifest revision, not an eternal claim about future ownership.

## Three Truth Layers

### Structural Truth

`INV-001` records an analyzer-derived access-control claim: `pause()` and `withdrawFees(uint256)` must stay owner-gated.

### Semantic Template Truth

`INV-002` records a template-derived pause expectation anchored to the recognized `openzeppelin-pausable:user-entrypoint-guard` template and the OpenZeppelin `Pausable` reference.

### Human-Authored Intent

`INV-003` records protocol-specific fee-boundary intent: fee withdrawal may draw only accrued protocol fees and must not touch depositor principal.

## Evidence And Attack Flow

- the top-level `evidence` block defines the accepted evidence vocabulary for the manifest
- each invariant narrows its own evidence expectations through `evidenceTypes`
- `scope.attackFlow.allowedModes` defines the exploit-execution modes that are in scope for accepted evidence against this manifest revision
- `scope.attackFlow.allowedModes` is intentionally frozen to `single_tx` for this fixture

## BattleChain Binding

BattleChain metadata stays under `adapters.battlechain` and only carries agreement, bounty, recovery, and lifecycle linkage for this reviewed deployment. The manifest remains understandable as a SafeHarbor artifact without treating BattleChain as the center of the standard.

## Phase 0 Use

Use this manifest and its summary as the Phase 0 reference when judging schema changes, review semantics, and future `shcli compile` output. If a schema proposal cannot express this artifact cleanly, the proposal is pushing against the target rather than clarifying it.
