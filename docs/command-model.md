# Manifest Command Model

SafeHarbor CLI v0.1 is a workflow around the manifest, not a broad lifecycle shell.

The implemented operator path is:

```sh
shcli scan --config safeharbor.toml
shcli review --config safeharbor.toml --approve-defaults
shcli compile --config safeharbor.toml
shcli battlechain prepare --config safeharbor.toml
shcli status --config safeharbor.toml
shcli doctor --config safeharbor.toml
shcli registry publish --config safeharbor.toml --manifest-uri ipfs://...
```

Agent consumers read the compiled manifest through `crates/agent-sdk`.

## Implemented Commands

`shcli scan`

- Requires a Foundry repo.
- Runs `forge build` and Aderyn.
- Writes advisory scan-family artifacts under `.safeharbor/analysis/`.
- Does not finalize scope, roles, or invariants.

`shcli review`

- Reads scan-family artifacts plus the draft metadata input.
- Writes review state and reviewed input under `.safeharbor/review/`.
- `--approve-defaults` is the non-interactive path used by the sample workflow.

`shcli compile`

- Reads the draft metadata input and reviewed input.
- Writes the canonical final manifest JSON and summary markdown.
- Validates the manifest against `schemas/safeharbor.manifest.schema.json`.

`shcli battlechain prepare`

- Reads compiled manifest output and local config.
- Writes `.safeharbor/battlechain/prepare.json`.
- Checks local artifact readiness and BattleChain adapter metadata.
- Does not send transactions.

`shcli status`

- Reads local manifest/config and optional RPC state.
- Prints a compact BattleChain lifecycle view.

`shcli doctor`

- Reads local manifest/config and optional RPC state.
- Prints grouped readiness checks and fails when checks have failures.

`shcli registry publish`

- Reads the compiled manifest and registry config.
- Writes `.safeharbor/registry/publish.json`.
- Prints calldata and optional readback status when an RPC URL is configured.
- Does not sign or submit transactions.

`shcli validate`

- Validates a manifest JSON file against the configured or explicit schema.

## State Boundaries

Workspace state can contain rejected candidates, unresolved review state, and raw analyzer output.

The compiled manifest is the canonical boundary:

- rejected candidates do not ship
- raw recognitions do not ship as accepted facts
- reviewed scope, roles, invariants, evidence, review, provenance, and adapter linkage do ship

BattleChain and registry artifacts are post-compile operational artifacts. They consume the manifest; they do not replace review or compile.
