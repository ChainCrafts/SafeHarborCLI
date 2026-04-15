#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
workspace_root="$repo_root/safeharbor-cli"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

work_dir="$tmp_dir/foundry-simple-vault"
mkdir -p "$work_dir"
cp -R "$workspace_root/examples/foundry-simple-vault/." "$work_dir/"
chmod +x "$work_dir/bin/mock-aderyn"

mkdir -p "$work_dir/examples/simple-vault" "$work_dir/schemas"
cp "$workspace_root/examples/simple-vault/safeharbor.input.json" \
  "$work_dir/examples/simple-vault/safeharbor.input.json"
cp "$workspace_root/schemas/safeharbor.manifest.schema.json" \
  "$work_dir/schemas/safeharbor.manifest.schema.json"

cat > "$work_dir/safeharbor.toml" <<'EOF'
[input]
file = "examples/simple-vault/safeharbor.input.json"

[output]
manifest = "examples/simple-vault/out/safeharbor.manifest.json"
summary = "examples/simple-vault/out/safeharbor.summary.md"

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
aderyn_bin = "bin/mock-aderyn"
cache = true

[battlechain]
network = "battlechain-testnet"
chain_id = 627

[registry]
address = "0x1111111111111111111111111111111111111111"
EOF

assert_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing expected file: $1" >&2
    exit 1
  fi
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "expected output to contain: $needle" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

assert_file_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$file"; then
    echo "expected $file to contain: $needle" >&2
    exit 1
  fi
}

cargo build --quiet --manifest-path "$workspace_root/Cargo.toml" -p shcli
shcli="$workspace_root/target/debug/shcli"
config="$work_dir/safeharbor.toml"
manifest="$work_dir/examples/simple-vault/out/safeharbor.manifest.json"
summary="$work_dir/examples/simple-vault/out/safeharbor.summary.md"

scan_output="$(cd "$work_dir" && "$shcli" scan --config "$config")"
assert_contains "$scan_output" "Structural scan completed"
assert_contains "$scan_output" "Found 1 contracts"
assert_file "$work_dir/.safeharbor/analysis/analysis.graph.json"
assert_file "$work_dir/.safeharbor/analysis/structural-candidates.json"
assert_file "$work_dir/.safeharbor/analysis/standards-recognition.json"

review_output="$(cd "$work_dir" && "$shcli" review --config "$config" --approve-defaults)"
assert_contains "$review_output" "Review completed"
assert_contains "$review_output" "reviewed input:"
assert_file "$work_dir/.safeharbor/review/review-state.json"
assert_file "$work_dir/.safeharbor/review/reviewed-input.json"

compile_output="$(cd "$work_dir" && "$shcli" compile --config "$config")"
assert_contains "$compile_output" "Emitted manifest successfully"
assert_contains "$compile_output" "draft metadata input"
assert_file "$manifest"
assert_file "$summary"
assert_file_contains "$manifest" '"schemaVersion": "1.0.0"'

prepare_output="$(cd "$work_dir" && "$shcli" battlechain prepare --config "$config")"
assert_contains "$prepare_output" "BattleChain prepare completed"
assert_file "$work_dir/.safeharbor/battlechain/prepare.json"
assert_file_contains "$work_dir/.safeharbor/battlechain/prepare.json" '"schemaVersion": "battlechain_prepare/v1"'

status_output="$(cd "$work_dir" && "$shcli" status --config "$config")"
assert_contains "$status_output" "BattleChain status"
assert_contains "$status_output" "lifecycle: AGREEMENT_CREATED"

doctor_output="$(cd "$work_dir" && "$shcli" doctor --config "$config")"
assert_contains "$doctor_output" "BattleChain doctor"
assert_contains "$doctor_output" "summary:"

publish_output="$(cd "$work_dir" && "$shcli" registry publish --config "$config" --manifest-uri ipfs://bafy-safeharbor-sample)"
assert_contains "$publish_output" "Registry publish prepared"
assert_contains "$publish_output" "readback     : unavailable"
assert_file "$work_dir/.safeharbor/registry/publish.json"
assert_file_contains "$work_dir/.safeharbor/registry/publish.json" '"schemaVersion": "registry_publish/v1"'
assert_file_contains "$work_dir/.safeharbor/registry/publish.json" '"manifestUri": "ipfs://bafy-safeharbor-sample"'

agent_output="$(cargo run --quiet --manifest-path "$workspace_root/Cargo.toml" -p agent-sdk --example simple_consumer -- "$manifest")"
assert_contains "$agent_output" "Protocol: SimpleVault"
assert_contains "$agent_output" "selector 0x8456cb59 in scope: true"

echo "sample workflow verification passed"
