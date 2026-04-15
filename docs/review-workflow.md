# Review Workflow

Review is the boundary between machine-suggested material and accepted manifest input.

## Inputs

`shcli review` reads:

- `.safeharbor/analysis/analysis.graph.json`
- `.safeharbor/analysis/structural-candidates.json`
- `.safeharbor/analysis/standards-recognition.json`
- the draft metadata input from `[input].file`

The draft metadata input remains authoritative for protocol identity, deployment identity, adapter metadata, evidence policy, provenance, and human-authored manifest intent.

## Non-interactive Review

```sh
shcli review --config safeharbor.toml --approve-defaults
```

This approves default decisions and writes:

- `.safeharbor/review/review-state.json`
- `.safeharbor/review/reviewed-input.json`

Use this for deterministic sample and release verification.

## Interactive Review

```sh
shcli review --config safeharbor.toml
```

Interactive review can approve, reject, or edit candidate decisions before compile.

Review state keeps local workflow data such as rejected candidate reasons. Reviewed input keeps only material needed by compile.

## Low-confidence Semantic Templates

To reject semantic template suggestions below the configured threshold during non-interactive review:

```sh
shcli review \
  --config safeharbor.toml \
  --approve-defaults \
  --reject-low-confidence-semantic-templates
```

The default threshold is `75`, or `[review].low_confidence_threshold` if configured.

## Determinism Notes

Reviewed input is expected to be byte-for-byte stable when inputs are unchanged.

Scan-family source digests in reviewed input ignore only `metadata.generated_at`, because that timestamp is advisory scan metadata. Draft metadata input digests remain byte-for-byte.

## Compile Boundary

Compile consumes reviewed input:

```sh
shcli compile --config safeharbor.toml
```

Rejected candidates and local review progress do not appear in the final manifest.
