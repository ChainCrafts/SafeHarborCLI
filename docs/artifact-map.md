# Artifact Map

SafeHarborCLI writes artifacts in three categories: canonical outputs, advisory/generated analysis outputs, and local operational artifacts.

## Canonical Outputs

These are the artifacts downstream consumers should treat as release artifacts for a reviewed manifest revision.

| Artifact | Writer | Inputs | Notes |
| --- | --- | --- | --- |
| `[output].manifest` | `shcli compile` | draft metadata input, reviewed input, schema | Canonical final manifest JSON. Validated against `schemas/safeharbor.manifest.schema.json`. |
| `[output].summary` | `shcli compile` | final manifest JSON | Canonical markdown summary for operators and reviewers. |
| `.safeharbor/review/reviewed-input.json` | `shcli review` | scan-family artifacts, draft metadata input, review decisions | Canonical compile input for reviewed scope, roles, and invariants. |

The reviewed input stores source digests. Scan-family digests are computed from canonicalized scan JSON with only `metadata.generated_at` removed. The draft metadata input digest is byte-for-byte.

## Advisory / Generated Analysis Outputs

These artifacts explain what static analysis and recognizers found. They are inputs to review, not final manifest claims.

| Artifact | Writer | Inputs | Notes |
| --- | --- | --- | --- |
| `.safeharbor/analysis/analysis.graph.json` | `shcli scan` | Foundry artifacts, Aderyn report | Normalized structural facts and detector findings. |
| `.safeharbor/analysis/structural-candidates.json` | `shcli scan` | analysis graph | Candidate scope, role, selector, and invariant material. |
| `.safeharbor/analysis/standards-recognition.json` | `shcli scan` | analysis graph | Recognized standards/patterns and semantic template suggestions. |

Scan-family artifacts include `metadata.generated_at` for operator traceability. That field is advisory and non-canonical. Determinism checks strip only that field before comparing scan-family artifacts.

## Local Operational Artifacts

These artifacts help operators prepare or inspect post-compile workflows. They are reproducible local state, not manifest schema fields.

| Artifact | Writer | Inputs | Notes |
| --- | --- | --- | --- |
| `.safeharbor/review/review-state.json` | `shcli review` | scan-family artifacts, draft metadata input | Local review progress and rejected candidate reasons. |
| `.safeharbor/battlechain/prepare.json` | `shcli battlechain prepare` | final manifest, config | BattleChain readiness checks and adapter binding. No transaction sending. |
| `.safeharbor/registry/publish.json` | `shcli registry publish` | final manifest, config, manifest URI, optional RPC readback | Prepared registry calldata and optional readback result. No signing. |

## Interactive vs Non-interactive Commands

Non-interactive:

- `shcli scan`
- `shcli review --approve-defaults`
- `shcli compile`
- `shcli battlechain prepare`
- `shcli status`
- `shcli doctor`
- `shcli registry publish`
- `shcli validate`

Interactive:

- `shcli review` without `--approve-defaults`

## Default Paths

When configured as the sample workflow expects:

- analysis directory: `.safeharbor/analysis`
- review state: `.safeharbor/review/review-state.json`
- reviewed input: `.safeharbor/review/reviewed-input.json`
- BattleChain prepare artifact: `.safeharbor/battlechain/prepare.json`
- registry publish artifact: `.safeharbor/registry/publish.json`

Manifest and summary paths are configured through `[output].manifest` and `[output].summary`.
