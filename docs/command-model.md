# Manifest Command Model

V1 freezes SafeHarbor CLI as a workflow, not a loose bag of commands.

The happy path is:

`init -> scan -> review -> compile -> battlechain prepare -> battlechain create-agreement -> battlechain request-attack`

This is the default operator path the rest of the docs should assume.

## Stable V1 Commands

`shcli init`

- creates `safeharbor.toml`
- creates a draft workspace
- creates empty review state
- does not emit a compiled manifest

`shcli scan`

- runs structural analysis
- writes normalized analysis output
- writes selector surfaces and special entrypoint surfaces
- writes payable boundary metadata
- writes role and access candidates
- writes standards and template recognitions
- does not finalize semantic claims

`shcli review`

- is the mandatory human approval and edit boundary
- must allow include and exclude surface decisions
- must allow access classification edits as `permissionless`, `role_gated`, or `unknown`
- must allow role ID curation
- must allow approving, rejecting, or rewriting invariant candidates in workspace state
- must allow severity assignment
- must allow evidence requirement selection
- must allow attack-flow marking

`shcli compile`

- validates reviewed workspace state
- emits `safeharbor.manifest.json`
- emits `safeharbor.summary.md`
- emits only finalized scope, roles, invariants, evidence, and adapter linkage
- is the first step in the happy path that emits the canonical manifest artifact
- the Phase 0 handwritten target artifact is `safeharbor-cli/examples/simple-vault/expected.safeharbor.manifest.json` with companion summary `safeharbor-cli/examples/simple-vault/expected.summary.md`

`shcli battlechain prepare`

- creates BattleChain-ready adapter metadata
- checks BattleChain prerequisites

`shcli battlechain create-agreement`

- builds or assists agreement payload creation

`shcli battlechain request-attack`

- checks manifest and agreement readiness
- prepares the request flow

`shcli status`

- shows manifest revision
- shows agreement linkage
- shows lifecycle state
- shows scope digest

`shcli doctor`

- checks missing config
- checks stale artifact refs
- checks bytecode mismatch
- checks chain and network mismatch
- checks missing completed review

`shcli export`

- exports agent-facing bundles
- exports human summaries
- exports artifacts intended for later IPFS packaging

## State Boundaries

`init`, `scan`, and `review` operate on workspace state.

That workspace is allowed to contain:

- unresolved access classifications
- rejected invariant candidates
- edited-but-not-finalized review objects
- raw recognitions and analyzer output

The compiled manifest schema does not represent that workspace state.

`compile` is the transition from workspace review data to the canonical manifest artifact. The compiled manifest is agent-facing output and should contain accepted information only.

That means:

- rejected candidates do not ship
- unresolved review garbage does not ship
- role assumptions that matter to security must have been turned into accepted invariants before compile

The BattleChain subcommands are post-compile lifecycle steps. They consume compiled scope and review output rather than replacing the review boundary.

## Compiled Manifest Semantics

The compiled manifest is a versioned contract.

V1 top-level fields are:

- `schemaVersion`
- `manifestRevision`
- `manifestStatus`
- `protocol`
- `source`
- `deployment`
- `adapters`
- `scope`
- `roles`
- `invariants`
- `evidence`
- `review`
- `provenance`

The important V1 decisions are:

- `schemaVersion` is the schema contract version
- `manifestRevision` is the monotonic revision number for repeated updates to the same logical manifest
- `manifestStatus` is frozen to `final` for compiled output
- `roles` is always present, even when empty
- `invariants` carries accepted invariants only and no candidate-level status field
- `review` records completed human approval metadata only

Workspace drafts, imports, and partial review exports may exist, but they are not the canonical compiled manifest shape and should not reuse the final-manifest semantics carelessly.
