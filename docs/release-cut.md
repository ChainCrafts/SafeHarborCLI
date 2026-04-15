# v0.1.0 Release Cut Status

This document tracks the readiness for the `v0.1.0` release.

## Blockers

- [x] Documentation accuracy (remove RC wording, expand limitations)
- [x] Version alignment across crates and workspace
- [x] Fresh UI verification path validated
- [x] Test suite and verifications green
- [x] Changelog finalized for v0.1.0

## Release Readiness Checks

✅ **Pass:** Local workflow completes successfully with expected artifacts.
✅ **Pass:** Manifest JSON compiles deterministically.
✅ **Pass:** Rust standard formatting and cargo checks pass.
✅ **Pass:** `cargo build --release -p shcli` works without error.
✅ **Pass:** Known limitations explicitly stated in documentation.

## Intentionally Deferred to Post-0.1.0

The following features and integrations are explicitly omitted from the v0.1.0 boundary:
- Signer and wallet plumbing
- BattleChain transaction-sending (write) flows
- Real registry publish mechanisms beyond prepare/verify
- Non-Rust SDKs (TypeScript, Python)
- Comprehensive UI/TUI
- Additional static analyzers beyond Foundry (e.g. Slither)
- Advanced semantic inference beyond current recognizers
