use analyzer::types::{EntrypointKind, ScanMetadata};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedStandardsRecognition {
    pub metadata: ScanMetadata,
    pub recognized_standards: Vec<RecognizedStandard>,
    pub semantic_template_suggestions: Vec<SemanticTemplateSuggestion>,
    pub recognition_summary: RecognitionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecognitionOutput {
    pub recognized_standards: Vec<RecognizedStandard>,
    pub semantic_template_suggestions: Vec<SemanticTemplateSuggestion>,
    pub recognition_summary: RecognitionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecognitionSummary {
    pub contract_count: usize,
    pub recognized_standard_count: usize,
    pub semantic_template_suggestion_count: usize,
    pub high_confidence_recognition_count: usize,
    pub recognized_by_kind: BTreeMap<RecognitionKind, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionKind {
    Erc20,
    Erc4626,
    Ownable,
    AccessControl,
    Pausable,
    Upgradeable,
}

impl RecognitionKind {
    pub fn id_part(&self) -> &'static str {
        match self {
            RecognitionKind::Erc20 => "erc20",
            RecognitionKind::Erc4626 => "erc4626",
            RecognitionKind::Ownable => "ownable",
            RecognitionKind::AccessControl => "access-control",
            RecognitionKind::Pausable => "pausable",
            RecognitionKind::Upgradeable => "upgradeable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionType {
    Standard,
    Pattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionCategory {
    TokenStandard,
    VaultStandard,
    AccessPattern,
    OperationalPattern,
    UpgradePattern,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecognizedStandard {
    pub id: String,
    pub contract_id: String,
    pub contract_name: String,
    pub kind: RecognitionKind,
    pub recognition_type: RecognitionType,
    pub category: RecognitionCategory,
    pub standard_reference: Option<String>,
    pub confidence: f64,
    pub evidence: Vec<RecognitionEvidence>,
    pub affected_function_ids: Vec<String>,
    pub affected_selectors: Vec<String>,
    pub provenance: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecognitionEvidence {
    pub source: RecognitionEvidenceSource,
    pub detail: String,
    pub function_ids: Vec<String>,
    pub selectors: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RecognitionEvidenceSource {
    FunctionSignature,
    Inheritance,
    Modifier,
    AuthSignal,
    DetectorFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionClass {
    SemanticTemplate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTemplateKind {
    AccessControl,
    PauseControl,
    UpgradeControl,
    AssetAccounting,
    Solvency,
    MintBurnIntegrity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SuggestionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateEvidenceType {
    Trace,
    StateDiff,
    BalanceDelta,
    SelectorAccessBreach,
    MultiTxSequence,
    ReproductionScript,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TemplateReviewStatus {
    RequiresHumanReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticTemplateSuggestion {
    pub id: String,
    pub class: SuggestionClass,
    pub template_id: String,
    pub source_kind: RecognitionKind,
    pub standard_reference: Option<String>,
    pub kind: SemanticTemplateKind,
    pub severity: SuggestionSeverity,
    pub review_status: TemplateReviewStatus,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub contract_ids: Vec<String>,
    pub function_ids: Vec<String>,
    pub selectors: Vec<String>,
    pub special_entrypoints: Vec<EntrypointKind>,
    pub evidence_types: Vec<TemplateEvidenceType>,
    pub provenance: Vec<String>,
    pub confidence: f64,
}
