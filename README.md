# SafeHarborCLI

![Rust](https://img.shields.io/badge/built%20with-Rust-dea584)
![Foundry](https://img.shields.io/badge/Foundry-supported-222222)
![Version](https://img.shields.io/badge/version-v0.1.0-blue)
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)

Protocol-aware Safe Harbor spec compiler for BattleChain.

SafeHarborCLI converts reviewed protocol structure, scope, roles, invariants, evidence expectations, and BattleChain metadata into a machine-readable Safe Harbor manifest. The CLI is the operator front end; the core product is the compiler boundary that turns scan output and explicit human review into a canonical JSON artifact for downstream tools.

> **v0.1.0 scope:** Foundry-only, review-gated manifest compilation with local BattleChain and registry prepare/verify workflows. No signer or transaction submission flows.

| Area | Current support |
| --- | --- |
| Project type | Foundry |
| Primary artifact | Compiled Safe Harbor manifest JSON |
| Review model | Mandatory human review before compile |
| BattleChain support | Local readiness, status, and doctor checks |
| Registry support | Publish payload preparation and optional readback verification |
| SDK | Rust read-only manifest consumer |
| License | MIT OR Apache-2.0 |

---

## Why SafeHarborCLI Exists

Safe Harbor specs need to be precise enough for tools and explicit enough for human reviewers. Protocol scope, privileged roles, critical invariants, evidence requirements, and BattleChain adapter metadata cannot be safely inferred from static analysis alone.

SafeHarborCLI provides a compile workflow for that boundary. It uses static analysis and standards recognition to propose structure, requires review to accept or edit those claims, then emits a deterministic manifest that downstream systems can consume without depending on raw scan output or informal project notes.

---

## What It Ships Today

- `shcli scan` for Foundry projects, backed by `forge` build output and Aderyn scan data.
- `shcli review` for accepting, rejecting, or editing machine-suggested scope, role, selector, and invariant material.
- `shcli compile` for emitting the canonical manifest JSON and operator summary Markdown.
- `shcli battlechain prepare` for producing local BattleChain readiness metadata from a compiled manifest.
- `shcli status` and `shcli doctor` for local and optional RPC-backed BattleChain readiness checks.
- `shcli registry publish` for preparing registry calldata and optional readback verification.
- `crates/agent-sdk`, a read-only Rust SDK for loading and querying compiled manifests.
- A checked-in sample workflow that runs without live BattleChain access, signer keys, or network access.

---

## Quickstart

Prerequisites:

- Rust toolchain
- Foundry (`forge`, and `anvil` for tests that need it)
- Aderyn for live scans

Build the CLI:

```sh
cd safeharbor-cli
cargo build -p shcli
```

Run the checked-in sample workflow:

```sh
cd ..
bash safeharbor-cli/scripts/verify-sample-workflow.sh
```

Run the workflow manually against the included sample config:

```sh
cd safeharbor-cli

target/debug/shcli scan --config safeharbor.toml
target/debug/shcli review --config safeharbor.toml --approve-defaults
target/debug/shcli compile --config safeharbor.toml
target/debug/shcli battlechain prepare --config safeharbor.toml
target/debug/shcli status --config safeharbor.toml
target/debug/shcli doctor --config safeharbor.toml
target/debug/shcli registry publish --config safeharbor.toml --manifest-uri ipfs://bafy-safeharbor-sample
```

Consume the compiled manifest from Rust:

```sh
cargo run -p agent-sdk --example simple_consumer -- examples/simple-vault/out/safeharbor.manifest.json
```

---

## Command Workflow

| Step | Command | Output |
| --- | --- | --- |
| 1 | `shcli scan --config safeharbor.toml` | Advisory analysis artifacts in `.safeharbor/analysis/` |
| 2 | `shcli review --config safeharbor.toml` | Review state and reviewed input in `.safeharbor/review/` |
| 3 | `shcli compile --config safeharbor.toml` | Canonical manifest JSON and summary Markdown |
| 4 | `shcli battlechain prepare --config safeharbor.toml` | BattleChain readiness artifact |
| 5 | `shcli status --config safeharbor.toml` | Compact local and optional remote lifecycle view |
| 6 | `shcli doctor --config safeharbor.toml` | Grouped readiness checks |
| 7 | `shcli registry publish --config safeharbor.toml --manifest-uri ipfs://...` | Registry publish payload and optional readback status |

The compiled manifest is the release boundary. Raw analyzer output, rejected review candidates, and local workflow state are not treated as accepted manifest facts.

---

## Known Limitations

- Foundry is the only supported project type in `v0.1.0`.
- Review is mandatory; scan output is advisory and does not finalize scope, roles, invariants, or evidence policy.
- Registry publishing is prepare/verify only.
- No signer or wallet flows are implemented.
- No BattleChain write flows are implemented.
- The Agent SDK is Rust-only.
- Some integration tests require local Foundry tooling and permission to bind local listener ports.

---

## License

SafeHarborCLI is licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

---

## Documentation

| Document | Purpose |
| --- | --- |
| [Quickstart](docs/quickstart.md) | End-to-end local workflow from a Foundry repo to a reviewed manifest |
| [Command Model](docs/command-model.md) | Implemented commands and state boundaries |
| [Artifact Map](docs/artifact-map.md) | Canonical outputs, advisory analysis artifacts, and local operational artifacts |
| [Review Workflow](docs/review-workflow.md) | Review inputs, interactive review, non-interactive review, and determinism notes |
| [BattleChain Operations](docs/battlechain-operations.md) | `prepare`, `status`, `doctor`, and registry publish prepare/verify behavior |
| [Agent SDK](docs/agent-sdk.md) | Rust manifest loading, validation, selector lookup, invariant filters, and evidence queries |
| [Invariant Taxonomy](docs/invariant-taxonomy.md) | Invariant classes, origin rules, role boundaries, and evidence vocabulary |
| [Fresh User Verification](docs/fresh-user-verification.md) | Clean-room verification path |
| [Release Checklist](docs/release-checklist.md) | Release validation checklist |
| [Release Cut](docs/release-cut.md) | Release cut procedure |

---

## Repository Layout

```text
.
|-- README.md
|-- docs/
|   |-- quickstart.md
|   |-- command-model.md
|   |-- artifact-map.md
|   |-- review-workflow.md
|   |-- battlechain-operations.md
|   `-- agent-sdk.md
|-- safeharbor-cli/
|   |-- apps/cli/                 # shcli command-line front end
|   |-- crates/
|   |   |-- analyzer/             # Foundry and Aderyn scan integration
|   |   |-- compiler/             # reviewed input to manifest compiler
|   |   |-- manifest/             # schema validation support
|   |   |-- review-engine/        # review session and projection logic
|   |   |-- standards-recognizer/ # standards and template recognition
|   |   |-- structural-extractor/ # structural candidate extraction
|   |   |-- battlechain-adapter/  # prepare, status, and doctor checks
|   |   |-- registry/             # registry publish payload preparation
|   |   `-- agent-sdk/            # read-only Rust manifest SDK
|   |-- examples/                 # sample inputs, outputs, and Foundry fixture
|   |-- schemas/                  # Safe Harbor manifest JSON schema
|   `-- scripts/                  # release and workflow verification scripts
`-- contracts/                    # Foundry registry fixture and tests
```

---

## Architecture Summary

SafeHarborCLI uses a three-layer truth model:

| Layer | Source | Role |
| --- | --- | --- |
| Structural truth | Static analysis and deployment-facing code structure | Produces concrete scope, selector, role, and code-structure candidates |
| Semantic templates | Standards and protocol pattern recognition | Suggests template-backed expectations without treating them as final facts |
| Human-authored intent | Explicit review | Accepts, edits, rejects, and adds the claims that compile into the manifest |

The compiler only emits reviewed material into the final manifest. BattleChain operations, registry publishing, and the Agent SDK consume the compiled manifest; they do not replace review or compilation as the source of truth.

---

## Development And Verification

Run Rust formatting and tests:

```sh
cd safeharbor-cli
cargo fmt --check
cargo test --workspace
```

Run registry contract tests:

```sh
cd ../contracts
forge test
```

Run the deterministic sample workflow:

```sh
cd ..
bash safeharbor-cli/scripts/verify-sample-workflow.sh
```

Run the Agent SDK example test directly:

```sh
cd safeharbor-cli
cargo test -p agent-sdk --test simple_consumer
```

Some smoke and integration coverage uses local RPC or fake listener ports. Run those checks in an environment where local tooling and listener permissions are available.
