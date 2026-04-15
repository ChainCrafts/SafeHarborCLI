# Quickstart

This path starts from a Foundry repo and produces a reviewed SafeHarbor manifest.

## 1. Build the CLI

```sh
cd safeharbor-cli
cargo build -p shcli
```

Use `target/debug/shcli` directly or put it on your `PATH`.

## 2. Add `safeharbor.toml`

Create a config at the Foundry repo root:

```toml
[input]
file = "safeharbor.input.json"

[output]
manifest = "out/safeharbor.manifest.json"
summary = "out/safeharbor.summary.md"

[schema]
file = "schemas/safeharbor.manifest.schema.json"

[review]
analysis_dir = ".safeharbor/analysis"
state_file = ".safeharbor/review/review-state.json"
reviewed_input = ".safeharbor/review/reviewed-input.json"
low_confidence_threshold = 75

[scan]
repo_root = "."
output_dir = ".safeharbor/analysis"
forge_bin = "forge"
aderyn_bin = "aderyn"
cache = true

[battlechain]
network = "battlechain-testnet"
chain_id = 627

[registry]
address = "0x1111111111111111111111111111111111111111"
```

`[input].file` is the draft metadata input. It carries protocol/deployment metadata and any human-authored manifest material that scan cannot infer.

## 3. Scan

```sh
shcli scan --config safeharbor.toml
```

Expected outputs:

- `.safeharbor/analysis/analysis.graph.json`
- `.safeharbor/analysis/structural-candidates.json`
- `.safeharbor/analysis/standards-recognition.json`

## 4. Review

For the non-interactive default path:

```sh
shcli review --config safeharbor.toml --approve-defaults
```

Expected outputs:

- `.safeharbor/review/review-state.json`
- `.safeharbor/review/reviewed-input.json`

Use interactive review by omitting `--approve-defaults`.

## 5. Compile

```sh
shcli compile --config safeharbor.toml
```

Expected outputs:

- `out/safeharbor.manifest.json`
- `out/safeharbor.summary.md`

Validate explicitly when needed:

```sh
shcli validate --manifest out/safeharbor.manifest.json
```

## 6. Prepare BattleChain Metadata

```sh
shcli battlechain prepare --config safeharbor.toml
shcli status --config safeharbor.toml
shcli doctor --config safeharbor.toml
```

Expected output:

- `.safeharbor/battlechain/prepare.json`

## 7. Prepare Registry Publish Payload

```sh
shcli registry publish --config safeharbor.toml --manifest-uri ipfs://...
```

Expected output:

- `.safeharbor/registry/publish.json`

The command prints calldata and optionally verifies readback if `[battlechain].rpc_url` is configured.

## 8. Run the Checked-in Sample

```sh
bash safeharbor-cli/scripts/verify-sample-workflow.sh
```

This script uses only local checked-in fixtures and does not require Anvil, live RPC, signer keys, or network access.
