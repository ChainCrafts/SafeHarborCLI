# Fresh User Verification

This guide outlines the exact, zero-tribal-knowledge path for a fresh user to clone the repository and verify the core v0.1.0 workflow.

## 1. Clone the Repository

```sh
git clone https://github.com/battlechain/SafeHarborCLI.git
cd SafeHarborCLI
```

## 2. Build the CLI

Ensure you have a recent Rust toolchain installed.

```sh
cd safeharbor-cli
cargo build --release -p shcli
```

## 3. Verify the Sample Workflow

The repository includes a verification script that tests the full `shcli` pipeline (scan, review, compile, prepare, status, doctor, publish) on a dummy contract. 
You will also need Foundry (`forge`) installed to successfully complete this step.

```sh
# Ensure you are at the repository root
bash safeharbor-cli/scripts/verify-sample-workflow.sh
```

Upon success, the script will explicitly exit without error, indicating that the artifacts have been deterministically generated under `.safeharbor/`.

## 4. Verify the Agent SDK Example

To ensure the compiled manifest can be correctly consumed by down-stream clients, run the provided simple consumer example:

```sh
cd safeharbor-cli
cargo run -p agent-sdk --example simple_consumer -- examples/simple-vault/expected.safeharbor.manifest.json
```

If successful, the consumer will parse the manifest without any panics or assertion failures.

## Expected Behavior
By completing these steps verbatim, you have proven that:
- Source build/install path is correct.
- Documented commands are valid.
- The default pipeline executes flawlessly using the prepared `safeharbor.toml`.
- Downstream Rust SDK integrations can natively load the finalized `SafeHarbor` manifest.
