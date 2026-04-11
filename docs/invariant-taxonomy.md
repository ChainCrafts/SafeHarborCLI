# Invariant Taxonomy

The compiled SafeHarbor manifest only ships accepted invariants.

Rejected, proposed, and partially edited candidates belong to review workspace state, not to the canonical compiled manifest JSON.

The Phase 0 reference artifact that exercises all three invariant classes lives at `examples/golden/simple-vault.safeharbor.manifest.json`, with the companion explanation in `examples/golden/simple-vault.summary.md`.

Each compiled invariant in V1 has this shape:

- `id`
- `class`
- `kind`
- `severity`
- `description`
- `contracts`
- `selectors`
- `specialEntrypoints`
- `evidenceTypes`
- `rationale`
- `origin`
- `derivationConfidence` for machine-suggested invariants only

`contracts` references are stable IDs from `scope.contracts[].id`, not human display names.

V1 freezes `class` to:

- `structural`
- `semantic_template`
- `human_authored`

This is the product honesty boundary:

- `structural` means the claim is grounded in structural truth extracted from code or deployment-facing analysis
- `semantic_template` means the claim was suggested from a recognized template or standard, not inferred from arbitrary economics
- `human_authored` means the claim was written directly during review and carries human intent rather than machine derivation

V1 freezes `kind` to:

- `access_control`
- `selector_scope`
- `pause_control`
- `upgrade_control`
- `fee_boundary`
- `asset_accounting`
- `solvency`
- `mint_burn_integrity`
- `role_assumption`
- `external_dependency`
- `settlement_flow`
- `time_window`

Other schema constraints:

- `id` uses `INV-###...`
- `severity` is one of `low`, `medium`, `high`, `critical`
- at least one of `contracts`, `selectors`, or `specialEntrypoints` must be present
- `specialEntrypoints` is limited to `receive` and `fallback` in V1

## Origin Rules

The old loose `source` string is replaced by a structured `origin` object.

`origin.type` must match `class`, and each class has different required fields:

The duplication is intentional: `class` is the invariant's top-level truth category, while `origin.type` makes the provenance object self-describing when read in isolation. The schema requires exact equality between the two.

### Structural

- `origin.type = structural`
- `origin.engine` is required
- `origin.detectorId` is optional
- `derivationConfidence` is required
- `origin.templateId`, `origin.standardReference`, and `origin.author` are not allowed

This is for high-confidence structural truth such as selector exposure, role gating, pause control, and upgrade surfaces.

### Semantic Template

- `origin.type = semantic_template`
- `origin.engine` is required
- `origin.templateId` is required
- `origin.standardReference` is optional
- `derivationConfidence` is required
- `origin.author` is not allowed

This is for template-guided suggestions such as ERC20, ERC4626, or vault-style expectations.

The required `templateId` is the V1 identity anchor that prevents `semantic_template` from becoming a bare label.

### Human Authored

- `origin.type = human_authored`
- `origin.author` is required
- `origin.reviewer` is optional
- `derivationConfidence` is forbidden
- `origin.engine`, `origin.detectorId`, `origin.templateId`, and `origin.standardReference` are not allowed

This is for protocol-specific business logic or economic intent that the compiler cannot honestly infer.

## Role and Assumption Boundary

Role records are canonical references, not a shortcut for invariant authoring.

- roles define stable `id` values and optional deployment holder sets
- `holders` is a manifest-revision snapshot of known deployment holders, not a claim that the set is timeless
- role assumptions that matter to security belong in `invariants`
- human-authored protocol assumptions must not hide inside role metadata

## Evidence Vocabulary

Evidence vocabulary in V1 remains:

- `trace`
- `state-diff`
- `balance-delta`
- `selector-access-breach`
- `multi-tx-sequence`
- `reproduction-script`

The invariant record stays compact, while the top-level `evidence` block defines the accepted and minimum required proof types for the compiled manifest.
