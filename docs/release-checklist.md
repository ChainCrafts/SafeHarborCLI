# v0.1.0 Release Checklist

Use this checklist for the `0.1.0` release.

## Local Verification

```sh
cd safeharbor-cli
cargo fmt --check
cargo test --workspace
cd ../contracts
forge test
cd ..
bash safeharbor-cli/scripts/verify-sample-workflow.sh
cd safeharbor-cli
cargo build --release -p shcli
```

## Artifact Checks

- Sample workflow writes `.safeharbor/analysis/analysis.graph.json`.
- Sample workflow writes `.safeharbor/analysis/structural-candidates.json`.
- Sample workflow writes `.safeharbor/analysis/standards-recognition.json`.
- Sample workflow writes `.safeharbor/review/review-state.json`.
- Sample workflow writes `.safeharbor/review/reviewed-input.json`.
- Sample workflow writes the configured final manifest JSON.
- Sample workflow writes the configured summary markdown.
- Sample workflow writes `.safeharbor/battlechain/prepare.json`.
- Sample workflow writes `.safeharbor/registry/publish.json`.

## Determinism Checks

- Final manifest JSON compares byte-for-byte when inputs are unchanged.
- Summary markdown compares byte-for-byte when inputs are unchanged.
- Reviewed input compares byte-for-byte when inputs are unchanged.
- BattleChain prepare artifact compares byte-for-byte when inputs are unchanged.
- Registry publish artifact compares byte-for-byte when inputs are unchanged.
- Scan-family artifacts compare as normalized JSON with only `metadata.generated_at` stripped.

## Docs Checks

- README documents the real v0.1.0 workflow.
- `docs/artifact-map.md` separates canonical, advisory, and local operational artifacts.
- Quickstart uses real commands and paths.
- BattleChain docs state that v0.1.0 does not send transactions.
- Registry docs state that publish prepares calldata and optional readback only.
- Agent SDK docs describe read-only manifest consumption.
- Dogfood template and SimpleVault fixture report are checked in.

## Scope Checks

- No signer or wallet plumbing.
- No BattleChain transaction-sending flow.
- No TypeScript or Python SDK.
- No full-screen TUI.
- No non-Foundry analyzer.
- No semantic inference beyond the current recognizers.
