use crate::types::{
    DraftCompileInput, REVIEW_STATE_SCHEMA_VERSION, REVIEWED_INPUT_SCHEMA_VERSION, ReviewState,
    ReviewedInput,
};
use analyzer::AnalysisGraph;
use anyhow::{Result, bail};
use manifest::AccessKind;
use std::collections::{BTreeMap, BTreeSet};

pub fn validate_draft_mappings(
    draft: &DraftCompileInput,
    graph: &AnalysisGraph,
) -> Result<BTreeMap<String, String>> {
    if draft.analysis_contract_mappings.is_empty() {
        bail!("reviewed compile requires analysis_contract_mappings in the draft metadata input");
    }

    let source_contract_ids = graph
        .contracts
        .iter()
        .map(|contract| contract.id.as_str())
        .collect::<BTreeSet<_>>();
    let draft_scope_ids = draft
        .manifest
        .scope
        .contracts
        .iter()
        .map(|contract| contract.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut manifest_to_source = BTreeMap::new();

    for mapping in &draft.analysis_contract_mappings {
        if !draft_scope_ids.contains(mapping.manifest_contract_id.as_str()) {
            bail!(
                "analysis_contract_mappings references unknown manifest contract id: {}",
                mapping.manifest_contract_id
            );
        }
        if !source_contract_ids.contains(mapping.source_analysis_contract_id.as_str()) {
            bail!(
                "analysis_contract_mappings references unknown source analysis contract id: {}",
                mapping.source_analysis_contract_id
            );
        }
        if manifest_to_source
            .insert(
                mapping.manifest_contract_id.clone(),
                mapping.source_analysis_contract_id.clone(),
            )
            .is_some()
        {
            bail!(
                "analysis_contract_mappings contains duplicate manifest contract id: {}",
                mapping.manifest_contract_id
            );
        }
    }

    for scope_id in draft_scope_ids {
        if !manifest_to_source.contains_key(scope_id) {
            bail!("missing analysis_contract_mappings entry for scope contract id: {scope_id}");
        }
    }

    Ok(manifest_to_source)
}

pub fn validate_review_state(state: &ReviewState) -> Result<()> {
    if state.schema_version != REVIEW_STATE_SCHEMA_VERSION {
        bail!(
            "unsupported review state schema version: {}",
            state.schema_version
        );
    }
    validate_digest("analysis_graph", &state.source_digests.analysis_graph)?;
    validate_digest(
        "structural_candidates",
        &state.source_digests.structural_candidates,
    )?;
    validate_digest(
        "standards_recognition",
        &state.source_digests.standards_recognition,
    )?;
    validate_digest("draft_metadata", &state.source_digests.draft_metadata)?;
    Ok(())
}

pub fn validate_reviewed_input_for_compile(
    reviewed: &ReviewedInput,
    draft: &DraftCompileInput,
    actual_draft_digest: &str,
) -> Result<()> {
    if reviewed.schema_version != REVIEWED_INPUT_SCHEMA_VERSION {
        bail!(
            "unsupported reviewed input schema version: {}",
            reviewed.schema_version
        );
    }
    validate_digest("analysis_graph", &reviewed.source_digests.analysis_graph)?;
    validate_digest(
        "structural_candidates",
        &reviewed.source_digests.structural_candidates,
    )?;
    validate_digest(
        "standards_recognition",
        &reviewed.source_digests.standards_recognition,
    )?;
    validate_digest("draft_metadata", &reviewed.source_digests.draft_metadata)?;
    if reviewed.source_digests.draft_metadata != actual_draft_digest {
        bail!(
            "reviewed input was produced from a different draft metadata digest: reviewed={}, current={actual_draft_digest}",
            reviewed.source_digests.draft_metadata
        );
    }

    let draft_scope_ids = draft
        .manifest
        .scope
        .contracts
        .iter()
        .map(|contract| contract.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut mapping_ids = BTreeSet::new();
    for mapping in &draft.analysis_contract_mappings {
        if !draft_scope_ids.contains(mapping.manifest_contract_id.as_str()) {
            bail!(
                "analysis_contract_mappings references unknown draft scope contract id: {}",
                mapping.manifest_contract_id
            );
        }
        if !mapping_ids.insert(mapping.manifest_contract_id.as_str()) {
            bail!(
                "analysis_contract_mappings contains duplicate manifest contract id: {}",
                mapping.manifest_contract_id
            );
        }
    }

    let mut reviewed_scope_ids = BTreeSet::new();
    for contract in &reviewed.reviewed_scope.contracts {
        if !draft_scope_ids.contains(contract.manifest_contract_id.as_str()) {
            bail!(
                "reviewed scope references contract missing from draft metadata: {}",
                contract.manifest_contract_id
            );
        }
        if !reviewed_scope_ids.insert(contract.manifest_contract_id.as_str()) {
            bail!(
                "reviewed scope contains duplicate contract id: {}",
                contract.manifest_contract_id
            );
        }
    }

    for contract_id in &reviewed_scope_ids {
        if !mapping_ids.contains(contract_id) {
            bail!(
                "reviewed contract id has no draft analysis_contract_mappings entry: {contract_id}"
            );
        }
    }

    let role_ids = reviewed
        .reviewed_roles
        .iter()
        .map(|role| role.reviewed_role.id.as_str())
        .collect::<BTreeSet<_>>();
    if role_ids.len() != reviewed.reviewed_roles.len() {
        bail!("reviewed roles contain duplicate role ids");
    }

    let mut selectors = BTreeSet::new();
    for contract in &reviewed.reviewed_scope.contracts {
        validate_access_roles(&contract.manifest_contract_id, &role_ids, None)?;
        for selector in &contract.selectors {
            selectors.insert(selector.selector.as_str());
            validate_access_roles(
                &contract.manifest_contract_id,
                &role_ids,
                Some(&selector.reviewed_access_classification),
            )?;
        }
        for entrypoint in &contract.special_entrypoints {
            validate_access_roles(
                &contract.manifest_contract_id,
                &role_ids,
                Some(&entrypoint.reviewed_access_classification),
            )?;
        }
    }

    for invariant in reviewed.all_invariants() {
        if invariant.reviewed_evidence_types.is_empty() {
            bail!("reviewed invariant {} has no evidence types", invariant.id);
        }
        for evidence in &invariant.reviewed_evidence_types {
            if !draft.manifest.evidence.accepted_types.contains(evidence) {
                bail!(
                    "reviewed invariant {} uses evidence type not accepted by draft policy: {:?}",
                    invariant.id,
                    evidence
                );
            }
        }
        for contract_id in &invariant.manifest_contract_ids {
            if !reviewed_scope_ids.contains(contract_id.as_str()) {
                bail!(
                    "reviewed invariant {} references missing contract id: {}",
                    invariant.id,
                    contract_id
                );
            }
        }
        for selector in &invariant.selectors {
            if !selectors.contains(selector.as_str()) {
                bail!(
                    "reviewed invariant {} references missing selector: {}",
                    invariant.id,
                    selector
                );
            }
        }
        if invariant.manifest_contract_ids.is_empty()
            && invariant.selectors.is_empty()
            && invariant.special_entrypoints.is_empty()
        {
            bail!(
                "reviewed invariant {} must reference a contract, selector, or special entrypoint",
                invariant.id
            );
        }
    }

    Ok(())
}

fn validate_digest(name: &str, digest: &str) -> Result<()> {
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("{name} digest must be a 64-character hex sha256 digest");
    }
    Ok(())
}

fn validate_access_roles(
    context: &str,
    role_ids: &BTreeSet<&str>,
    access: Option<&manifest::Access>,
) -> Result<()> {
    let Some(access) = access else {
        return Ok(());
    };
    if access.kind == AccessKind::RoleGated {
        let Some(required) = &access.required_role_ids else {
            bail!("role-gated access in {context} must include required role ids");
        };
        for role_id in required {
            if !role_ids.contains(role_id.as_str()) {
                bail!("role-gated access in {context} references unknown role id: {role_id}");
            }
        }
    }
    Ok(())
}
