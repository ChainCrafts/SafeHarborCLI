use crate::types::{ReviewItemKind, ReviewedAccessClassification};
use manifest::{EvidenceType, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewItemView {
    pub item_id: String,
    pub item_kind: ReviewItemKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_contract_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_contract_id: Option<String>,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_rationale: Option<String>,
    pub source_provenance: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_in_scope: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_access: Option<ReviewedAccessClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_role_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_severity: Option<Severity>,
    pub default_evidence: Vec<EvidenceType>,
    pub editable_fields: EditableFieldSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EditableFieldSet {
    pub scope: bool,
    pub access: bool,
    pub role_id: bool,
    pub severity: bool,
    pub evidence: bool,
    pub label: bool,
    pub summary: bool,
    pub note: bool,
}

pub fn scope_item_id(manifest_contract_id: &str) -> String {
    format!("scope:{manifest_contract_id}")
}

pub fn selector_item_id(manifest_contract_id: &str, function_id: &str) -> String {
    format!("selector:{manifest_contract_id}:{function_id}")
}

pub fn role_item_id(source_role: &str) -> String {
    format!("role:{source_role}")
}

pub fn structural_item_id(candidate_id: &str) -> String {
    format!("structural:{candidate_id}")
}

pub fn semantic_item_id(suggestion_id: &str) -> String {
    format!("semantic:{suggestion_id}")
}

pub fn human_item_id(invariant_id: &str) -> String {
    format!("human:{invariant_id}")
}
