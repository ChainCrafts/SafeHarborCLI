# Changelog

## 0.1.0

SafeHarborCLI `v0.1.0` is the first stable release of the protocol-aware Safe Harbor spec compiler for BattleChain. It transforms a Foundry project and human-reviewed protocol metadata into a deterministic, standards-aligned SafeHarbor manifest.

Supported Architecture & Workflow:
- Foundry-based structural code analysis.
- Standards recognition combining static analysis with expected templates.
- Explicit human review boundary for intent capture.
- Deterministic manifest and summary compilation.
- Registry publish payload generation and readback verification.
- Rust Agent SDK for downstream manifest consumption.

Notable Architecture Boundaries:
- The compiled manifest JSON and summary markdown are the final canonical outputs.
- All analysis artifacts (graphs, candidates, recognition) are advisory and intermediate.
- Time metadata (`metadata.generated_at`) is advisory and excluded from canonical artifact stability checks.

V1 Constraints & Limitations:
- **Foundry-only**: Hardcoded dependency on Foundry project structures.
- **Review is Mandatory**: Automated analysis cannot infer all human intent.
- **Prepare/Verify Only**: Registry publish operations only prepare calldata and verify readback, but do not broadcast.
- **No Signer Flows**: SafeHarborCLI provides zero signer or wallet plumbing.
- **No BattleChain Write Flows**: Operations do not send transactions to BattleChain.
- **Rust-only SDK**: Only a Rust Agent SDK is provided.
- **Execution Requirements**: Some integration smoke tests bind local TCP ports and require local listener permissions.
