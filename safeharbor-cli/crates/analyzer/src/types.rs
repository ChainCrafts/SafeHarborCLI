use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub repo_root: PathBuf,
    pub output_dir: PathBuf,
    pub forge_bin: PathBuf,
    pub aderyn_bin: PathBuf,
    pub cache: bool,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanMetadata {
    pub schema_version: String,
    pub generated_at: String,
    pub tool_version: String,
    pub repo_root: String,
    pub input_digest: String,
    pub aderyn_version: String,
    pub forge_version: String,
}

#[derive(Debug, Clone)]
pub struct ScanMetadataBase {
    pub generated_at: String,
    pub tool_version: String,
    pub repo_root: String,
    pub input_digest: String,
    pub aderyn_version: String,
    pub forge_version: String,
}

impl ScanMetadataBase {
    pub fn with_schema_version(&self, schema_version: &str) -> ScanMetadata {
        ScanMetadata {
            schema_version: schema_version.to_string(),
            generated_at: self.generated_at.clone(),
            tool_version: self.tool_version.clone(),
            repo_root: self.repo_root.clone(),
            input_digest: self.input_digest.clone(),
            aderyn_version: self.aderyn_version.clone(),
            forge_version: self.forge_version.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisGraph {
    pub project: ProjectFacts,
    pub contracts: Vec<ContractFacts>,
    pub functions: Vec<FunctionFacts>,
    pub modifiers: Vec<ModifierFacts>,
    pub inheritance: Vec<InheritanceEdge>,
    pub detector_findings: Vec<DetectorFinding>,
}

impl AnalysisGraph {
    pub fn normalized_facts(&self) -> NormalizedFacts {
        NormalizedFacts {
            project: self.project.clone(),
            contracts: self.contracts.clone(),
            functions: self.functions.clone(),
            modifiers: self.modifiers.clone(),
            inheritance: self.inheritance.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedAnalysisGraph {
    pub metadata: ScanMetadata,
    pub normalized_facts: NormalizedFacts,
    pub detector_findings: Vec<DetectorFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedFacts {
    pub project: ProjectFacts,
    pub contracts: Vec<ContractFacts>,
    pub functions: Vec<FunctionFacts>,
    pub modifiers: Vec<ModifierFacts>,
    pub inheritance: Vec<InheritanceEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectFacts {
    pub build_system: String,
    pub foundry_config_path: String,
    pub src_dir: String,
    pub test_dir: String,
    pub script_dir: String,
    pub libs: Vec<String>,
    pub artifact_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    Contract,
    AbstractContract,
    Interface,
    Library,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractFacts {
    pub id: String,
    pub name: String,
    pub source_path: String,
    pub kind: ContractKind,
    pub bases: Vec<String>,
    pub artifact_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EntrypointKind {
    Normal,
    Constructor,
    Receive,
    Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    External,
    Public,
    Internal,
    Private,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StateMutability {
    Pure,
    View,
    Payable,
    Nonpayable,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionFacts {
    pub id: String,
    pub contract_id: String,
    pub name: String,
    pub signature: Option<String>,
    pub selector: Option<String>,
    pub entrypoint_kind: EntrypointKind,
    pub visibility: Visibility,
    pub state_mutability: StateMutability,
    pub modifiers: Vec<String>,
    pub auth_signals: Vec<AuthSignal>,
    pub calls: Vec<CallTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModifierFacts {
    pub id: String,
    pub contract_id: String,
    pub name: String,
    pub source_path: String,
    pub auth_signals: Vec<AuthSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InheritanceEdge {
    pub contract_id: String,
    pub base_contract_id: Option<String>,
    pub base_contract_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuthSignalKind {
    OnlyOwnerModifier,
    OnlyRoleModifier,
    NamedModifier,
    RoleCheck,
    OwnerCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuthSignalSource {
    ModifierInvocation,
    ModifierDefinition,
    FunctionBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthSignal {
    pub kind: AuthSignalKind,
    pub source: AuthSignalSource,
    pub role: Option<String>,
    pub evidence: String,
    pub confidence: f64,
}

impl Eq for AuthSignal {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Call,
    DelegateCall,
    StaticCall,
    Transfer,
    Send,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallTarget {
    pub kind: CallKind,
    pub target: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DetectorSeverity {
    High,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectorLocation {
    pub contract_path: String,
    pub line_no: usize,
    pub src: String,
    pub src_char: String,
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectorFinding {
    pub detector_id: String,
    pub severity: DetectorSeverity,
    pub title: String,
    pub description: String,
    pub locations: Vec<DetectorLocation>,
}

#[derive(Debug, Clone)]
pub struct AnalysisRun {
    pub graph: AnalysisGraph,
    pub metadata_base: ScanMetadataBase,
    pub paths: ScanPaths,
}

#[derive(Debug, Clone)]
pub struct ScanPaths {
    pub output_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub analysis_graph_path: PathBuf,
    pub structural_candidates_path: PathBuf,
    pub standards_recognition_path: PathBuf,
    pub aderyn_report_path: PathBuf,
}
