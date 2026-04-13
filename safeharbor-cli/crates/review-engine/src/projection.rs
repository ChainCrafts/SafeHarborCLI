use crate::{
    loader::ReviewContext,
    taxonomy::{semantic_evidence, semantic_kind, semantic_severity, structural_default},
    types::{
        REVIEWED_INPUT_SCHEMA_VERSION, ReviewAction, ReviewDecision, ReviewSessionStatus,
        ReviewState, ReviewedAccessClassification, ReviewedInput, ReviewedInvariant, ReviewedRole,
        ReviewedScope, ReviewedScopeContract, ReviewedScopeSelector, ReviewedSpecialEntrypoint,
    },
    view::{
        human_item_id, role_item_id, scope_item_id, selector_item_id, semantic_item_id,
        structural_item_id,
    },
};
use analyzer::types::{EntrypointKind, StateMutability};
use anyhow::{Result, bail};
use manifest::{
    Access, AccessKind, InvariantClass, InvariantOrigin, Role, Scope, Severity,
    SpecialEntrypointKind,
};
use std::collections::{BTreeMap, BTreeSet};
use structural_extractor::{
    RoleCandidate, ScopeCandidate, SelectorCandidate, StructuralInvariantCandidate,
};

pub fn project_reviewed_input(
    context: &ReviewContext,
    state: &ReviewState,
) -> Result<ReviewedInput> {
    if state.session_status != ReviewSessionStatus::Complete || state.unresolved_count != 0 {
        bail!(
            "reviewed input cannot be projected while review is incomplete: status={:?}, unresolved={}",
            state.session_status,
            state.unresolved_count
        );
    }

    let decisions = decisions_by_id(&state.decisions)?;
    let source_to_manifest = source_to_manifest_ids(context);
    let draft_contracts = draft_contracts(context);
    let scope_candidates = scope_candidates(context);
    let selector_candidates = selector_candidates(context);

    let reviewed_roles = project_roles(context, &decisions)?;
    let mut role_id_by_source = BTreeMap::new();
    for role in &reviewed_roles {
        role_id_by_source.insert(role.source_role.clone(), role.reviewed_role.id.clone());
        role_id_by_source.insert(
            normalize_role_id(&role.source_role),
            role.reviewed_role.id.clone(),
        );
    }

    let reviewed_scope = project_scope(
        context,
        &decisions,
        &draft_contracts,
        &scope_candidates,
        &selector_candidates,
        &role_id_by_source,
    )?;
    let in_scope_contract_ids = reviewed_scope
        .contracts
        .iter()
        .filter(|contract| contract.reviewed_in_scope)
        .map(|contract| contract.manifest_contract_id.as_str())
        .collect::<BTreeSet<_>>();
    let in_scope_selectors = reviewed_scope
        .contracts
        .iter()
        .flat_map(|contract| contract.selectors.iter())
        .filter(|selector| selector.reviewed_in_scope)
        .map(|selector| selector.selector.as_str())
        .collect::<BTreeSet<_>>();

    let mut next_id = 1usize;
    let reviewed_structural_invariants = project_structural_invariants(
        context,
        &decisions,
        &source_to_manifest,
        &in_scope_contract_ids,
        &in_scope_selectors,
        &mut next_id,
    );
    let reviewed_semantic_templates = project_semantic_templates(
        context,
        &decisions,
        &source_to_manifest,
        &in_scope_contract_ids,
        &in_scope_selectors,
        &mut next_id,
    );
    let reviewed_human_authored_invariants =
        project_human_invariants(context, &decisions, &in_scope_contract_ids, &mut next_id);

    Ok(ReviewedInput {
        schema_version: REVIEWED_INPUT_SCHEMA_VERSION.to_string(),
        source_digests: state.source_digests.clone(),
        reviewed_scope,
        reviewed_roles,
        reviewed_structural_invariants,
        reviewed_semantic_templates,
        reviewed_human_authored_invariants,
        review: context.draft_input.manifest.review.clone(),
    })
}

pub fn reviewed_input_to_manifest_scope(reviewed: &ReviewedInput) -> Scope {
    reviewed.reviewed_scope.to_manifest_scope()
}

fn project_scope(
    context: &ReviewContext,
    decisions: &BTreeMap<String, &ReviewDecision>,
    draft_contracts: &BTreeMap<String, manifest::ScopeContract>,
    scope_candidates: &BTreeMap<String, ScopeCandidate>,
    selector_candidates: &[SelectorCandidate],
    role_id_by_source: &BTreeMap<String, String>,
) -> Result<ReviewedScope> {
    let mut contracts = Vec::new();
    for mapping in &context.draft_input.analysis_contract_mappings {
        let Some(draft_contract) = draft_contracts.get(&mapping.manifest_contract_id) else {
            bail!(
                "draft mapping references missing manifest contract id: {}",
                mapping.manifest_contract_id
            );
        };
        let scope_candidate = scope_candidates.get(&mapping.source_analysis_contract_id);
        let item_id = scope_item_id(&mapping.manifest_contract_id);
        let decision = decisions.get(&item_id).copied();
        let default_in_scope = scope_candidate
            .map(|candidate| candidate.candidate_in_scope)
            .unwrap_or(true);
        let reviewed_in_scope = reviewed_in_scope_from_decision(decision, default_in_scope);
        let out_of_scope_reason = out_of_scope_reason_from_decision(decision).or_else(|| {
            if reviewed_in_scope {
                None
            } else {
                draft_contract.out_of_scope_reason.clone().or_else(|| {
                    Some(
                        scope_candidate
                            .map(|candidate| candidate.reason.clone())
                            .unwrap_or_else(|| "rejected during review".to_string()),
                    )
                })
            }
        });

        let mut selectors = Vec::new();
        let mut special_entrypoints = Vec::new();
        if reviewed_in_scope {
            for selector in selector_candidates
                .iter()
                .filter(|candidate| candidate.contract_id == mapping.source_analysis_contract_id)
            {
                if selector.selector.is_some() {
                    selectors.push(project_selector(
                        &mapping.manifest_contract_id,
                        selector,
                        decisions,
                        role_id_by_source,
                    ));
                } else if let Some(entrypoint) = special_entrypoint_kind(&selector.entrypoint_kind)
                {
                    special_entrypoints.push(project_special_entrypoint(
                        &mapping.manifest_contract_id,
                        selector,
                        entrypoint,
                        decisions,
                        role_id_by_source,
                    ));
                }
            }
        }

        selectors.sort_by(|left, right| left.selector.cmp(&right.selector));
        special_entrypoints
            .sort_by(|left, right| left.entrypoint_string().cmp(&right.entrypoint_string()));

        contracts.push(ReviewedScopeContract {
            manifest_contract_id: mapping.manifest_contract_id.clone(),
            source_analysis_contract_id: mapping.source_analysis_contract_id.clone(),
            name: draft_contract.name.clone(),
            address: draft_contract.address.clone(),
            source_candidate_in_scope: default_in_scope,
            reviewed_in_scope,
            out_of_scope_reason,
            source_confidence: scope_candidate.map(|candidate| candidate.confidence),
            source_rationale: scope_candidate.map(|candidate| candidate.reason.clone()),
            selectors,
            special_entrypoints,
        });
    }

    contracts.sort_by(|left, right| left.manifest_contract_id.cmp(&right.manifest_contract_id));
    Ok(ReviewedScope {
        contracts,
        attack_flow: context.draft_input.manifest.scope.attack_flow.clone(),
    })
}

fn project_selector(
    manifest_contract_id: &str,
    selector: &SelectorCandidate,
    decisions: &BTreeMap<String, &ReviewDecision>,
    role_id_by_source: &BTreeMap<String, String>,
) -> ReviewedScopeSelector {
    let item_id = selector_item_id(manifest_contract_id, &selector.function_id);
    let decision = decisions.get(&item_id).copied();
    let default_in_scope = true;
    let reviewed_in_scope = reviewed_in_scope_from_decision(decision, default_in_scope);
    let source_access = source_access_from_selector(selector);
    let reviewed_access = reviewed_access_from_decision(decision)
        .map(|access| access.to_access())
        .unwrap_or_else(|| normalize_access_roles(&source_access, role_id_by_source));

    ReviewedScopeSelector {
        function_id: selector.function_id.clone(),
        selector: selector.selector.clone().unwrap_or_default(),
        signature: selector
            .signature
            .clone()
            .unwrap_or_else(|| selector.function_id.clone()),
        payable: selector.payable,
        source_in_scope: default_in_scope,
        reviewed_in_scope,
        out_of_scope_reason: out_of_scope_reason_from_decision(decision),
        source_access_classification: source_access,
        reviewed_access_classification: reviewed_access,
        source_confidence: Some(selector.confidence),
        source_provenance: selector.provenance.clone(),
    }
}

fn project_special_entrypoint(
    manifest_contract_id: &str,
    selector: &SelectorCandidate,
    entrypoint: SpecialEntrypointKind,
    decisions: &BTreeMap<String, &ReviewDecision>,
    role_id_by_source: &BTreeMap<String, String>,
) -> ReviewedSpecialEntrypoint {
    let item_id = selector_item_id(manifest_contract_id, &selector.function_id);
    let decision = decisions.get(&item_id).copied();
    let default_in_scope = true;
    let reviewed_in_scope = reviewed_in_scope_from_decision(decision, default_in_scope);
    let source_access = source_access_from_selector(selector);
    let reviewed_access = reviewed_access_from_decision(decision)
        .map(|access| access.to_access())
        .unwrap_or_else(|| normalize_access_roles(&source_access, role_id_by_source));

    ReviewedSpecialEntrypoint {
        function_id: selector.function_id.clone(),
        entrypoint,
        payable: selector.payable || selector.state_mutability == StateMutability::Payable,
        source_in_scope: default_in_scope,
        reviewed_in_scope,
        out_of_scope_reason: out_of_scope_reason_from_decision(decision),
        source_access_classification: source_access,
        reviewed_access_classification: reviewed_access,
        source_confidence: Some(selector.confidence),
        source_provenance: selector.provenance.clone(),
    }
}

fn project_roles(
    context: &ReviewContext,
    decisions: &BTreeMap<String, &ReviewDecision>,
) -> Result<Vec<ReviewedRole>> {
    let draft_roles = context
        .draft_input
        .manifest
        .roles
        .iter()
        .map(|role| (role.id.as_str(), role))
        .collect::<BTreeMap<_, _>>();
    let mut roles = Vec::new();

    for candidate in &context
        .structural_candidates
        .extracted_candidates
        .role_candidates
    {
        let item_id = role_item_id(&candidate.role);
        let Some(decision) = decisions.get(&item_id).copied() else {
            continue;
        };
        if decision.action == ReviewAction::Rejected {
            continue;
        }
        let reviewed_id = decision
            .edits
            .as_ref()
            .and_then(|edits| edits.reviewed_role_id.clone())
            .unwrap_or_else(|| normalize_role_id(&candidate.role));
        let draft_role = draft_roles.get(reviewed_id.as_str());
        roles.push(ReviewedRole {
            source_role: candidate.role.clone(),
            reviewed_role: Role {
                id: reviewed_id.clone(),
                label: draft_role
                    .and_then(|role| role.label.clone())
                    .or_else(|| Some(candidate.role.to_ascii_uppercase())),
                holders: draft_role
                    .map(|role| role.holders.clone())
                    .unwrap_or_default(),
                description: draft_role
                    .and_then(|role| role.description.clone())
                    .or_else(|| Some(role_description(candidate))),
            },
            source_confidence: Some(candidate.confidence),
            source_provenance: candidate.provenance.clone(),
            reviewer_note: decision.reviewer_note.clone(),
        });
    }

    roles.sort_by(|left, right| left.reviewed_role.id.cmp(&right.reviewed_role.id));
    Ok(roles)
}

fn project_structural_invariants(
    context: &ReviewContext,
    decisions: &BTreeMap<String, &ReviewDecision>,
    source_to_manifest: &BTreeMap<String, Vec<String>>,
    in_scope_contract_ids: &BTreeSet<&str>,
    in_scope_selectors: &BTreeSet<&str>,
    next_id: &mut usize,
) -> Vec<ReviewedInvariant> {
    let mut invariants = Vec::new();
    for candidate in &context
        .structural_candidates
        .extracted_candidates
        .structural_invariant_candidates
    {
        let item_id = structural_item_id(&candidate.id);
        let Some(decision) = decisions.get(&item_id).copied() else {
            continue;
        };
        if decision.action == ReviewAction::Rejected {
            continue;
        }

        let default = structural_default(&candidate.kind);
        let manifest_contract_ids = manifest_ids_for_sources(
            &candidate.contract_ids,
            source_to_manifest,
            in_scope_contract_ids,
        );
        let selectors = in_scope_only(&candidate.selectors, in_scope_selectors);
        let special_entrypoints = candidate
            .entrypoints
            .iter()
            .filter_map(special_entrypoint_kind)
            .collect::<Vec<_>>();
        if manifest_contract_ids.is_empty()
            && selectors.is_empty()
            && special_entrypoints.is_empty()
        {
            continue;
        }

        invariants.push(ReviewedInvariant {
            id: next_invariant_id(next_id),
            source_item_id: candidate.id.clone(),
            class: InvariantClass::Structural,
            kind: default.kind,
            description: reviewed_description(
                decision,
                &format!(
                    "{} should remain within the reviewed boundary.",
                    candidate.title
                ),
            ),
            manifest_contract_ids,
            selectors,
            special_entrypoints,
            source_confidence: Some(candidate.confidence),
            source_rationale: source_rationale(candidate),
            source_provenance: candidate.provenance.clone(),
            reviewed_severity: edited_severity(decision, default.severity),
            reviewed_evidence_types: edited_evidence(decision, default.evidence_types),
            reviewer_note: decision.reviewer_note.clone(),
            origin: InvariantOrigin {
                origin_type: InvariantClass::Structural,
                engine: Some("safeharbor-structural-extractor".to_string()),
                detector_id: Some(candidate.id.clone()),
                template_id: None,
                standard_reference: None,
                author: None,
                reviewer: None,
            },
        });
    }
    invariants
}

fn project_semantic_templates(
    context: &ReviewContext,
    decisions: &BTreeMap<String, &ReviewDecision>,
    source_to_manifest: &BTreeMap<String, Vec<String>>,
    in_scope_contract_ids: &BTreeSet<&str>,
    in_scope_selectors: &BTreeSet<&str>,
    next_id: &mut usize,
) -> Vec<ReviewedInvariant> {
    let mut invariants = Vec::new();
    for suggestion in &context.standards_recognition.semantic_template_suggestions {
        let item_id = semantic_item_id(&suggestion.id);
        let Some(decision) = decisions.get(&item_id).copied() else {
            continue;
        };
        if decision.action == ReviewAction::Rejected {
            continue;
        }

        let manifest_contract_ids = manifest_ids_for_sources(
            &suggestion.contract_ids,
            source_to_manifest,
            in_scope_contract_ids,
        );
        let selectors = in_scope_only(&suggestion.selectors, in_scope_selectors);
        let special_entrypoints = suggestion
            .special_entrypoints
            .iter()
            .filter_map(special_entrypoint_kind)
            .collect::<Vec<_>>();
        if manifest_contract_ids.is_empty()
            && selectors.is_empty()
            && special_entrypoints.is_empty()
        {
            continue;
        }

        let default_evidence = suggestion
            .evidence_types
            .iter()
            .map(semantic_evidence)
            .collect::<Vec<_>>();
        invariants.push(ReviewedInvariant {
            id: next_invariant_id(next_id),
            source_item_id: suggestion.id.clone(),
            class: InvariantClass::SemanticTemplate,
            kind: semantic_kind(&suggestion.kind),
            description: reviewed_description(decision, &suggestion.description),
            manifest_contract_ids,
            selectors,
            special_entrypoints,
            source_confidence: Some(suggestion.confidence),
            source_rationale: suggestion.rationale.clone(),
            source_provenance: suggestion.provenance.clone(),
            reviewed_severity: edited_severity(decision, semantic_severity(&suggestion.severity)),
            reviewed_evidence_types: edited_evidence(decision, default_evidence),
            reviewer_note: decision.reviewer_note.clone(),
            origin: InvariantOrigin {
                origin_type: InvariantClass::SemanticTemplate,
                engine: Some("safeharbor-template-recognizer".to_string()),
                detector_id: None,
                template_id: Some(suggestion.template_id.clone()),
                standard_reference: suggestion.standard_reference.clone(),
                author: None,
                reviewer: None,
            },
        });
    }
    invariants
}

fn project_human_invariants(
    context: &ReviewContext,
    decisions: &BTreeMap<String, &ReviewDecision>,
    in_scope_contract_ids: &BTreeSet<&str>,
    next_id: &mut usize,
) -> Vec<ReviewedInvariant> {
    let mut invariants = Vec::new();
    for invariant in context
        .draft_input
        .manifest
        .invariants
        .iter()
        .filter(|invariant| invariant.class == InvariantClass::HumanAuthored)
    {
        let item_id = human_item_id(&invariant.id);
        let Some(decision) = decisions.get(&item_id).copied() else {
            continue;
        };
        if decision.action == ReviewAction::Rejected {
            continue;
        }

        let manifest_contract_ids = invariant
            .contracts
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|contract_id| in_scope_contract_ids.contains(contract_id.as_str()))
            .collect::<Vec<_>>();
        let selectors = invariant.selectors.clone().unwrap_or_default();
        let special_entrypoints = invariant.special_entrypoints.clone().unwrap_or_default();
        if manifest_contract_ids.is_empty()
            && selectors.is_empty()
            && special_entrypoints.is_empty()
        {
            continue;
        }

        invariants.push(ReviewedInvariant {
            id: next_invariant_id(next_id),
            source_item_id: invariant.id.clone(),
            class: InvariantClass::HumanAuthored,
            kind: invariant.kind.clone(),
            description: reviewed_description(decision, &invariant.description),
            manifest_contract_ids,
            selectors,
            special_entrypoints,
            source_confidence: None,
            source_rationale: invariant.rationale.clone(),
            source_provenance: vec!["draft_manifest.invariants".to_string()],
            reviewed_severity: edited_severity(decision, invariant.severity.clone()),
            reviewed_evidence_types: edited_evidence(decision, invariant.evidence_types.clone()),
            reviewer_note: decision.reviewer_note.clone(),
            origin: invariant.origin.clone(),
        });
    }
    invariants
}

fn decisions_by_id(decisions: &[ReviewDecision]) -> Result<BTreeMap<String, &ReviewDecision>> {
    let mut by_id = BTreeMap::new();
    for decision in decisions {
        if by_id.insert(decision.item_id.clone(), decision).is_some() {
            bail!(
                "duplicate review decision for item id: {}",
                decision.item_id
            );
        }
    }
    Ok(by_id)
}

fn draft_contracts(context: &ReviewContext) -> BTreeMap<String, manifest::ScopeContract> {
    context
        .draft_input
        .manifest
        .scope
        .contracts
        .iter()
        .map(|contract| (contract.id.clone(), contract.clone()))
        .collect()
}

fn scope_candidates(context: &ReviewContext) -> BTreeMap<String, ScopeCandidate> {
    context
        .structural_candidates
        .extracted_candidates
        .scope_candidates
        .iter()
        .map(|candidate| (candidate.contract_id.clone(), candidate.clone()))
        .collect()
}

fn selector_candidates(context: &ReviewContext) -> Vec<SelectorCandidate> {
    context
        .structural_candidates
        .extracted_candidates
        .selector_candidates
        .clone()
}

fn source_to_manifest_ids(context: &ReviewContext) -> BTreeMap<String, Vec<String>> {
    let mut by_source = BTreeMap::<String, Vec<String>>::new();
    for mapping in &context.draft_input.analysis_contract_mappings {
        by_source
            .entry(mapping.source_analysis_contract_id.clone())
            .or_default()
            .push(mapping.manifest_contract_id.clone());
    }
    for ids in by_source.values_mut() {
        ids.sort();
    }
    by_source
}

fn reviewed_in_scope_from_decision(
    decision: Option<&ReviewDecision>,
    default_in_scope: bool,
) -> bool {
    match decision {
        Some(decision) if decision.action == ReviewAction::Rejected => false,
        Some(decision) => decision
            .edits
            .as_ref()
            .and_then(|edits| edits.in_scope)
            .unwrap_or(default_in_scope),
        None => default_in_scope,
    }
}

fn out_of_scope_reason_from_decision(decision: Option<&ReviewDecision>) -> Option<String> {
    let decision = decision?;
    if decision.action == ReviewAction::Rejected {
        return decision
            .rejection_reason
            .clone()
            .or_else(|| Some("rejected during review".to_string()));
    }
    decision
        .edits
        .as_ref()
        .and_then(|edits| edits.out_of_scope_reason.clone())
}

fn reviewed_access_from_decision(
    decision: Option<&ReviewDecision>,
) -> Option<ReviewedAccessClassification> {
    decision
        .and_then(|decision| decision.edits.as_ref())
        .and_then(|edits| edits.reviewed_access_classification.clone())
}

fn source_access_from_selector(selector: &SelectorCandidate) -> Access {
    if selector.role_hints.is_empty() {
        return Access {
            kind: AccessKind::Permissionless,
            required_role_ids: None,
        };
    }
    Access {
        kind: AccessKind::RoleGated,
        required_role_ids: Some(
            selector
                .role_hints
                .iter()
                .map(|role| normalize_role_id(role))
                .collect(),
        ),
    }
}

fn normalize_access_roles(access: &Access, role_id_by_source: &BTreeMap<String, String>) -> Access {
    if access.kind != AccessKind::RoleGated {
        return access.clone();
    }
    let Some(required) = &access.required_role_ids else {
        return Access {
            kind: AccessKind::Unknown,
            required_role_ids: None,
        };
    };
    let reviewed_roles = required
        .iter()
        .filter_map(|role| role_id_by_source.get(role).cloned())
        .collect::<Vec<_>>();
    if reviewed_roles.is_empty() {
        Access {
            kind: AccessKind::Unknown,
            required_role_ids: None,
        }
    } else {
        Access {
            kind: AccessKind::RoleGated,
            required_role_ids: Some(reviewed_roles),
        }
    }
}

fn normalize_role_id(role: &str) -> String {
    role.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn role_description(candidate: &RoleCandidate) -> String {
    format!(
        "Reviewed role candidate derived from {} selectors.",
        candidate.selectors.len()
    )
}

fn edited_severity(decision: &ReviewDecision, default: Severity) -> Severity {
    decision
        .edits
        .as_ref()
        .and_then(|edits| edits.severity.clone())
        .unwrap_or(default)
}

fn edited_evidence(
    decision: &ReviewDecision,
    default: Vec<manifest::EvidenceType>,
) -> Vec<manifest::EvidenceType> {
    decision
        .edits
        .as_ref()
        .filter(|edits| !edits.evidence_types.is_empty())
        .map(|edits| edits.evidence_types.clone())
        .unwrap_or(default)
}

fn reviewed_description(decision: &ReviewDecision, default: &str) -> String {
    decision
        .edits
        .as_ref()
        .and_then(|edits| edits.reviewed_summary.clone())
        .filter(|summary| !summary.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn source_rationale(candidate: &StructuralInvariantCandidate) -> String {
    let evidence = if candidate.evidence.is_empty() {
        "no structured evidence detail".to_string()
    } else {
        candidate.evidence.join("; ")
    };
    format!(
        "Suggested from structural candidate '{}'. Evidence: {evidence}.",
        candidate.title
    )
}

fn manifest_ids_for_sources(
    source_contract_ids: &[String],
    source_to_manifest: &BTreeMap<String, Vec<String>>,
    in_scope_contract_ids: &BTreeSet<&str>,
) -> Vec<String> {
    let mut manifest_ids = source_contract_ids
        .iter()
        .flat_map(|source_id| {
            source_to_manifest
                .get(source_id)
                .cloned()
                .unwrap_or_default()
        })
        .filter(|manifest_id| in_scope_contract_ids.contains(manifest_id.as_str()))
        .collect::<Vec<_>>();
    dedup_sort(&mut manifest_ids);
    manifest_ids
}

fn in_scope_only(values: &[String], in_scope_values: &BTreeSet<&str>) -> Vec<String> {
    let mut kept = values
        .iter()
        .filter(|value| in_scope_values.contains(value.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    dedup_sort(&mut kept);
    kept
}

fn special_entrypoint_kind(kind: &EntrypointKind) -> Option<SpecialEntrypointKind> {
    match kind {
        EntrypointKind::Receive => Some(SpecialEntrypointKind::Receive),
        EntrypointKind::Fallback => Some(SpecialEntrypointKind::Fallback),
        _ => None,
    }
}

fn next_invariant_id(next_id: &mut usize) -> String {
    let id = format!("INV-{next_id:03}");
    *next_id += 1;
    id
}

fn dedup_sort(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

trait EntrypointSort {
    fn entrypoint_string(&self) -> String;
}

impl EntrypointSort for ReviewedSpecialEntrypoint {
    fn entrypoint_string(&self) -> String {
        match self.entrypoint {
            SpecialEntrypointKind::Receive => "receive".to_string(),
            SpecialEntrypointKind::Fallback => "fallback".to_string(),
        }
    }
}
