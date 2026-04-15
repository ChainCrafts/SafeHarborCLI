# Agent SDK

`crates/agent-sdk` is a read-only Rust consumer for compiled SafeHarbor manifests.

It does not scan repos, run review, compile manifests, submit BattleChain transactions, or publish registry entries.

## Example

Run against the checked-in sample manifest:

```sh
cd safeharbor-cli
cargo run -p agent-sdk --example simple_consumer -- examples/simple-vault/expected.safeharbor.manifest.json
```

Expected output includes:

- protocol name
- critical invariants
- selector scope lookup for `0x8456cb59`
- evidence types for `INV-001`

## Basic Use

```rust
use agent_sdk::AgentManifest;

let agent = AgentManifest::from_path("out/safeharbor.manifest.json")?;
let manifest = agent.manifest();
let critical = agent.critical_invariants();
let pause_in_scope = agent.is_selector_in_scope("0x8456cb59")?;
```

## Supported Reads

The SDK supports:

- manifest loading and schema validation
- selector lookup by hex selector or signature
- role-gated selector queries
- invariant filtering by severity, contract, selector, and evidence type
- evidence type lookup for an invariant

## Release Check

The SDK example is covered by:

```sh
cd safeharbor-cli
cargo test -p agent-sdk --test simple_consumer
```
