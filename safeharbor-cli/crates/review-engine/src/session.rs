use crate::{
    loader::{ReviewContext, load_review_context},
    persistence::{load_review_state, save_review_state, save_reviewed_input},
    projection::project_reviewed_input,
    prompts::{ReviewPrompter, ReviewSummary},
    taxonomy::{semantic_evidence, semantic_severity, structural_default},
    types::{
        ReviewAction, ReviewDecision, ReviewItemKind, ReviewRequest, ReviewSessionStatus,
        ReviewState, ReviewedAccessClassification,
    },
    view::{
        EditableFieldSet, ReviewItemView, human_item_id, role_item_id, scope_item_id,
        selector_item_id, semantic_item_id, structural_item_id,
    },
};
use analyzer::types::EntrypointKind;
use anyhow::{Result, bail};
use manifest::{AccessKind, InvariantClass};
use std::collections::{BTreeMap, BTreeSet};
use structural_extractor::{PrivilegeClass, SelectorCandidate};

pub fn run_review<P: ReviewPrompter>(
    request: ReviewRequest,
    prompter: &mut P,
) -> Result<crate::types::ReviewedInput> {
    let context = load_review_context(request)?;
    let items = build_review_items(&context);
    let mut state = match load_review_state(&context.request.state_path)? {
        Some(existing) if existing.source_digests == context.source_digests => existing,
        Some(_) => {
            if !prompter.should_discard_stale_state()? {
                bail!("review state is stale; rerun scan or discard the stale review state");
            }
            ReviewState::new(context.source_digests.clone())
        }
        None => ReviewState::new(context.source_digests.clone()),
    };

    let mut decided = state
        .decisions
        .iter()
        .map(|decision| decision.item_id.clone())
        .collect::<BTreeSet<_>>();
    state.unresolved_count = items
        .iter()
        .filter(|item| !decided.contains(&item.item_id))
        .count();
    save_review_state(&context.request.state_path, &state)?;

    for item in &items {
        if decided.contains(&item.item_id) {
            continue;
        }
        let decision = prompter.review_item(item)?;
        validate_decision_matches_item(item, &decision)?;
        decided.insert(item.item_id.clone());
        state.decisions.push(decision);
        state.unresolved_count = items
            .iter()
            .filter(|item| !decided.contains(&item.item_id))
            .count();
        save_review_state(&context.request.state_path, &state)?;
    }

    let summary = summarize(&state.decisions, items.len(), state.unresolved_count);
    if !prompter.confirm_final(&summary)? {
        bail!("review was not finalized");
    }

    state.session_status = ReviewSessionStatus::Complete;
    state.unresolved_count = 0;
    save_review_state(&context.request.state_path, &state)?;
    let reviewed = project_reviewed_input(&context, &state)?;
    save_reviewed_input(&context.request.reviewed_input_path, &reviewed)?;
    Ok(reviewed)
}

fn validate_decision_matches_item(item: &ReviewItemView, decision: &ReviewDecision) -> Result<()> {
    if decision.item_id != item.item_id || decision.item_kind != item.item_kind {
        bail!(
            "prompter returned decision for wrong item: expected {}, got {}",
            item.item_id,
            decision.item_id
        );
    }
    Ok(())
}

fn summarize(
    decisions: &[ReviewDecision],
    total_items: usize,
    unresolved_count: usize,
) -> ReviewSummary {
    ReviewSummary {
        total_items,
        approved_count: decisions
            .iter()
            .filter(|decision| decision.action == ReviewAction::Approved)
            .count(),
        rejected_count: decisions
            .iter()
            .filter(|decision| decision.action == ReviewAction::Rejected)
            .count(),
        edited_count: decisions
            .iter()
            .filter(|decision| decision.action == ReviewAction::Edited)
            .count(),
        unresolved_count,
    }
}

fn build_review_items(context: &ReviewContext) -> Vec<ReviewItemView> {
    let mut items = Vec::new();
    let scope_candidates = context
        .structural_candidates
        .extracted_candidates
        .scope_candidates
        .iter()
        .map(|candidate| (candidate.contract_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let selector_candidates = context
        .structural_candidates
        .extracted_candidates
        .selector_candidates
        .iter()
        .collect::<Vec<_>>();
    let draft_contracts = context
        .draft_input
        .manifest
        .scope
        .contracts
        .iter()
        .map(|contract| (contract.id.as_str(), contract))
        .collect::<BTreeMap<_, _>>();

    for mapping in &context.draft_input.analysis_contract_mappings {
        let Some(draft_contract) = draft_contracts.get(mapping.manifest_contract_id.as_str())
        else {
            continue;
        };
        let candidate = scope_candidates.get(mapping.source_analysis_contract_id.as_str());
        items.push(ReviewItemView {
            item_id: scope_item_id(&mapping.manifest_contract_id),
            item_kind: ReviewItemKind::ScopeContract,
            source_contract_id: Some(mapping.source_analysis_contract_id.clone()),
            manifest_contract_id: Some(mapping.manifest_contract_id.clone()),
            title: format!("Scope contract {}", draft_contract.name),
            description: candidate
                .map(|candidate| candidate.reason.clone())
                .unwrap_or_else(|| "Review mapped contract scope.".to_string()),
            source_confidence: candidate.map(|candidate| candidate.confidence),
            source_rationale: candidate.map(|candidate| candidate.reason.clone()),
            source_provenance: vec!["structural_candidates.scope_candidates".to_string()],
            default_in_scope: Some(
                candidate
                    .map(|candidate| candidate.candidate_in_scope)
                    .unwrap_or(draft_contract.in_scope),
            ),
            default_access: None,
            default_role_id: None,
            default_severity: None,
            default_evidence: Vec::new(),
            editable_fields: EditableFieldSet {
                scope: true,
                note: true,
                ..EditableFieldSet::default()
            },
        });
    }

    for mapping in &context.draft_input.analysis_contract_mappings {
        for selector in selector_candidates
            .iter()
            .filter(|candidate| candidate.contract_id == mapping.source_analysis_contract_id)
        {
            items.push(selector_view(&mapping.manifest_contract_id, selector));
        }
    }

    for role in &context
        .structural_candidates
        .extracted_candidates
        .role_candidates
    {
        items.push(ReviewItemView {
            item_id: role_item_id(&role.role),
            item_kind: ReviewItemKind::Role,
            source_contract_id: None,
            manifest_contract_id: None,
            title: format!("Role {}", role.role),
            description: format!("Role candidate gates {} selectors.", role.selectors.len()),
            source_confidence: Some(role.confidence),
            source_rationale: Some(role.evidence.join("; ")),
            source_provenance: role.provenance.clone(),
            default_in_scope: None,
            default_access: None,
            default_role_id: Some(normalize_role_id(&role.role)),
            default_severity: None,
            default_evidence: Vec::new(),
            editable_fields: EditableFieldSet {
                role_id: true,
                note: true,
                ..EditableFieldSet::default()
            },
        });
    }

    for candidate in &context
        .structural_candidates
        .extracted_candidates
        .structural_invariant_candidates
    {
        let default = structural_default(&candidate.kind);
        items.push(ReviewItemView {
            item_id: structural_item_id(&candidate.id),
            item_kind: ReviewItemKind::StructuralInvariant,
            source_contract_id: None,
            manifest_contract_id: None,
            title: candidate.title.clone(),
            description: format!(
                "Structural invariant candidate with {} selectors.",
                candidate.selectors.len()
            ),
            source_confidence: Some(candidate.confidence),
            source_rationale: Some(candidate.evidence.join("; ")),
            source_provenance: candidate.provenance.clone(),
            default_in_scope: None,
            default_access: None,
            default_role_id: None,
            default_severity: Some(default.severity),
            default_evidence: default.evidence_types,
            editable_fields: EditableFieldSet {
                severity: true,
                evidence: true,
                note: true,
                ..EditableFieldSet::default()
            },
        });
    }

    for suggestion in &context.standards_recognition.semantic_template_suggestions {
        items.push(ReviewItemView {
            item_id: semantic_item_id(&suggestion.id),
            item_kind: ReviewItemKind::SemanticTemplate,
            source_contract_id: suggestion.contract_ids.first().cloned(),
            manifest_contract_id: None,
            title: suggestion.title.clone(),
            description: suggestion.description.clone(),
            source_confidence: Some(suggestion.confidence),
            source_rationale: Some(suggestion.rationale.clone()),
            source_provenance: suggestion.provenance.clone(),
            default_in_scope: None,
            default_access: None,
            default_role_id: None,
            default_severity: Some(semantic_severity(&suggestion.severity)),
            default_evidence: suggestion
                .evidence_types
                .iter()
                .map(semantic_evidence)
                .collect(),
            editable_fields: EditableFieldSet {
                severity: true,
                evidence: true,
                label: true,
                summary: true,
                note: true,
                ..EditableFieldSet::default()
            },
        });
    }

    for invariant in context
        .draft_input
        .manifest
        .invariants
        .iter()
        .filter(|invariant| invariant.class == InvariantClass::HumanAuthored)
    {
        items.push(ReviewItemView {
            item_id: human_item_id(&invariant.id),
            item_kind: ReviewItemKind::HumanAuthoredInvariant,
            source_contract_id: None,
            manifest_contract_id: invariant
                .contracts
                .as_ref()
                .and_then(|contracts| contracts.first().cloned()),
            title: invariant.id.clone(),
            description: invariant.description.clone(),
            source_confidence: None,
            source_rationale: Some(invariant.rationale.clone()),
            source_provenance: vec!["draft_manifest.invariants".to_string()],
            default_in_scope: None,
            default_access: None,
            default_role_id: None,
            default_severity: Some(invariant.severity.clone()),
            default_evidence: invariant.evidence_types.clone(),
            editable_fields: EditableFieldSet {
                severity: true,
                evidence: true,
                summary: true,
                note: true,
                ..EditableFieldSet::default()
            },
        });
    }

    items.push(ReviewItemView {
        item_id: "metadata:manifest-preview".to_string(),
        item_kind: ReviewItemKind::MetadataPreview,
        source_contract_id: None,
        manifest_contract_id: None,
        title: "Manifest metadata preview".to_string(),
        description: format!(
            "{} on {} with {} deployment contracts.",
            context.draft_input.manifest.protocol.name,
            context.draft_input.manifest.deployment.network,
            context.draft_input.manifest.deployment.contracts.len()
        ),
        source_confidence: None,
        source_rationale: Some(
            "Draft metadata remains authoritative for protocol, deployment, adapters, evidence policy, and provenance."
                .to_string(),
        ),
        source_provenance: vec!["draft_manifest".to_string()],
        default_in_scope: None,
        default_access: None,
        default_role_id: None,
        default_severity: None,
        default_evidence: Vec::new(),
        editable_fields: EditableFieldSet {
            note: true,
            ..EditableFieldSet::default()
        },
    });

    items
}

fn selector_view(manifest_contract_id: &str, selector: &SelectorCandidate) -> ReviewItemView {
    let source_access = source_access_from_selector(selector);
    let title = match &selector.signature {
        Some(signature) => format!("Selector {signature}"),
        None => match selector.entrypoint_kind {
            EntrypointKind::Receive => "Special entrypoint receive".to_string(),
            EntrypointKind::Fallback => "Special entrypoint fallback".to_string(),
            _ => selector.function_id.clone(),
        },
    };
    ReviewItemView {
        item_id: selector_item_id(manifest_contract_id, &selector.function_id),
        item_kind: ReviewItemKind::Selector,
        source_contract_id: Some(selector.contract_id.clone()),
        manifest_contract_id: Some(manifest_contract_id.to_string()),
        title,
        description: format!(
            "{:?} {:?}, payable={}",
            selector.visibility, selector.entrypoint_kind, selector.payable
        ),
        source_confidence: Some(selector.confidence),
        source_rationale: Some(selector.provenance.join("; ")),
        source_provenance: selector.provenance.clone(),
        default_in_scope: Some(true),
        default_access: Some(source_access),
        default_role_id: None,
        default_severity: None,
        default_evidence: Vec::new(),
        editable_fields: EditableFieldSet {
            scope: true,
            access: true,
            note: true,
            ..EditableFieldSet::default()
        },
    }
}

fn source_access_from_selector(selector: &SelectorCandidate) -> ReviewedAccessClassification {
    if selector.privilege_class == PrivilegeClass::Privileged && !selector.role_hints.is_empty() {
        return ReviewedAccessClassification {
            kind: AccessKind::RoleGated,
            required_role_ids: selector
                .role_hints
                .iter()
                .map(|role| normalize_role_id(role))
                .collect(),
        };
    }
    ReviewedAccessClassification {
        kind: AccessKind::Permissionless,
        required_role_ids: Vec::new(),
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
