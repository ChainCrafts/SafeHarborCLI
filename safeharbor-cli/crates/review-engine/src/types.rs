use manifest::{
    Access, AttackFlow, EvidenceType, InvariantClass, InvariantKind, InvariantOrigin, Review, Role,
    SafeHarborManifest, Scope, Severity, SpecialEntrypointKind,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const REVIEW_STATE_SCHEMA_VERSION: &str = "review_state/v1";
pub const REVIEWED_INPUT_SCHEMA_VERSION: &str = "reviewed_input/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRequest {
    pub analysis_graph_path: PathBuf,
    pub structural_candidates_path: PathBuf,
    pub standards_recognition_path: PathBuf,
    pub draft_input_path: PathBuf,
    pub state_path: PathBuf,
    pub reviewed_input_path: PathBuf,
    pub low_confidence_threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftCompileInput {
    pub manifest: SafeHarborManifest,
    #[serde(default)]
    pub analysis_contract_mappings: Vec<AnalysisContractMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisContractMapping {
    pub manifest_contract_id: String,
    pub source_analysis_contract_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDigests {
    pub analysis_graph: String,
    pub structural_candidates: String,
    pub standards_recognition: String,
    pub draft_metadata: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewState {
    pub schema_version: String,
    pub source_digests: SourceDigests,
    pub decisions: Vec<ReviewDecision>,
    pub session_status: ReviewSessionStatus,
    pub unresolved_count: usize,
}

impl ReviewState {
    pub fn new(source_digests: SourceDigests) -> Self {
        Self {
            schema_version: REVIEW_STATE_SCHEMA_VERSION.to_string(),
            source_digests,
            decisions: Vec::new(),
            session_status: ReviewSessionStatus::InProgress,
            unresolved_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSessionStatus {
    InProgress,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDecision {
    pub item_id: String,
    pub item_kind: ReviewItemKind,
    pub action: ReviewAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edits: Option<ReviewEdits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewItemKind {
    ScopeContract,
    Selector,
    Role,
    StructuralInvariant,
    SemanticTemplate,
    HumanAuthoredInvariant,
    MetadataPreview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    Approved,
    Rejected,
    Edited,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReviewEdits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_scope: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_access_classification: Option<ReviewedAccessClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_role_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_types: Vec<EvidenceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedAccessClassification {
    pub kind: manifest::AccessKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_role_ids: Vec<String>,
}

impl ReviewedAccessClassification {
    pub fn to_access(&self) -> Access {
        Access {
            kind: self.kind.clone(),
            required_role_ids: if self.required_role_ids.is_empty() {
                None
            } else {
                Some(self.required_role_ids.clone())
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedInput {
    pub schema_version: String,
    pub source_digests: SourceDigests,
    pub reviewed_scope: ReviewedScope,
    pub reviewed_roles: Vec<ReviewedRole>,
    pub reviewed_structural_invariants: Vec<ReviewedInvariant>,
    pub reviewed_semantic_templates: Vec<ReviewedInvariant>,
    pub reviewed_human_authored_invariants: Vec<ReviewedInvariant>,
    pub review: Review,
}

impl ReviewedInput {
    pub fn all_invariants(&self) -> impl Iterator<Item = &ReviewedInvariant> {
        self.reviewed_structural_invariants
            .iter()
            .chain(self.reviewed_semantic_templates.iter())
            .chain(self.reviewed_human_authored_invariants.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedScope {
    pub contracts: Vec<ReviewedScopeContract>,
    pub attack_flow: AttackFlow,
}

impl ReviewedScope {
    pub fn to_manifest_scope(&self) -> Scope {
        Scope {
            contracts: self
                .contracts
                .iter()
                .map(ReviewedScopeContract::to_manifest_contract)
                .collect(),
            attack_flow: self.attack_flow.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedScopeContract {
    pub manifest_contract_id: String,
    pub source_analysis_contract_id: String,
    pub name: String,
    pub address: String,
    pub source_candidate_in_scope: bool,
    pub reviewed_in_scope: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_rationale: Option<String>,
    pub selectors: Vec<ReviewedScopeSelector>,
    pub special_entrypoints: Vec<ReviewedSpecialEntrypoint>,
}

impl ReviewedScopeContract {
    pub fn to_manifest_contract(&self) -> manifest::ScopeContract {
        manifest::ScopeContract {
            id: self.manifest_contract_id.clone(),
            name: self.name.clone(),
            address: self.address.clone(),
            in_scope: self.reviewed_in_scope,
            out_of_scope_reason: self.out_of_scope_reason.clone(),
            selectors: if self.selectors.is_empty() {
                None
            } else {
                Some(
                    self.selectors
                        .iter()
                        .map(ReviewedScopeSelector::to_manifest_selector)
                        .collect(),
                )
            },
            special_entrypoints: if self.special_entrypoints.is_empty() {
                None
            } else {
                Some(
                    self.special_entrypoints
                        .iter()
                        .map(ReviewedSpecialEntrypoint::to_manifest_entrypoint)
                        .collect(),
                )
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedScopeSelector {
    pub function_id: String,
    pub selector: String,
    pub signature: String,
    pub payable: bool,
    pub source_in_scope: bool,
    pub reviewed_in_scope: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
    pub source_access_classification: Access,
    pub reviewed_access_classification: Access,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confidence: Option<f64>,
    pub source_provenance: Vec<String>,
}

impl ReviewedScopeSelector {
    pub fn to_manifest_selector(&self) -> manifest::ScopeSelector {
        manifest::ScopeSelector {
            selector: self.selector.clone(),
            signature: self.signature.clone(),
            payable: self.payable,
            in_scope: self.reviewed_in_scope,
            access: self.reviewed_access_classification.clone(),
            out_of_scope_reason: self.out_of_scope_reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedSpecialEntrypoint {
    pub function_id: String,
    pub entrypoint: SpecialEntrypointKind,
    pub payable: bool,
    pub source_in_scope: bool,
    pub reviewed_in_scope: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
    pub source_access_classification: Access,
    pub reviewed_access_classification: Access,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confidence: Option<f64>,
    pub source_provenance: Vec<String>,
}

impl ReviewedSpecialEntrypoint {
    pub fn to_manifest_entrypoint(&self) -> manifest::SpecialEntrypoint {
        manifest::SpecialEntrypoint {
            entrypoint: self.entrypoint.clone(),
            payable: self.payable,
            in_scope: self.reviewed_in_scope,
            access: self.reviewed_access_classification.clone(),
            out_of_scope_reason: self.out_of_scope_reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedRole {
    pub source_role: String,
    pub reviewed_role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confidence: Option<f64>,
    pub source_provenance: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedInvariant {
    pub id: String,
    pub source_item_id: String,
    pub class: InvariantClass,
    pub kind: InvariantKind,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifest_contract_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub special_entrypoints: Vec<SpecialEntrypointKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confidence: Option<f64>,
    pub source_rationale: String,
    pub source_provenance: Vec<String>,
    pub reviewed_severity: Severity,
    pub reviewed_evidence_types: Vec<EvidenceType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_note: Option<String>,
    pub origin: InvariantOrigin,
}

impl ReviewedInvariant {
    pub fn to_manifest_invariant(&self) -> manifest::Invariant {
        manifest::Invariant {
            id: self.id.clone(),
            class: self.class.clone(),
            kind: self.kind.clone(),
            severity: self.reviewed_severity.clone(),
            description: self.description.clone(),
            contracts: if self.manifest_contract_ids.is_empty() {
                None
            } else {
                Some(self.manifest_contract_ids.clone())
            },
            selectors: if self.selectors.is_empty() {
                None
            } else {
                Some(self.selectors.clone())
            },
            special_entrypoints: if self.special_entrypoints.is_empty() {
                None
            } else {
                Some(self.special_entrypoints.clone())
            },
            evidence_types: self.reviewed_evidence_types.clone(),
            rationale: append_reviewer_note(&self.source_rationale, self.reviewer_note.as_deref()),
            origin: self.origin.clone(),
            derivation_confidence: self.source_confidence,
        }
    }
}

fn append_reviewer_note(rationale: &str, note: Option<&str>) -> String {
    match note.filter(|value| !value.trim().is_empty()) {
        Some(note) => format!("{rationale}\nReviewer note: {}", note.trim()),
        None => rationale.to_string(),
    }
}
