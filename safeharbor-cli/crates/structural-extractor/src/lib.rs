use analyzer::types::{
    AnalysisGraph, AuthSignal, ContractFacts, ContractKind, EntrypointKind, FunctionFacts,
    ScanMetadata, StateMutability, Visibility,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedStructuralCandidates {
    pub metadata: ScanMetadata,
    pub extracted_candidates: ExtractedCandidates,
    pub summary: StructuralSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtractedCandidates {
    pub scope_candidates: Vec<ScopeCandidate>,
    pub selector_candidates: Vec<SelectorCandidate>,
    pub role_candidates: Vec<RoleCandidate>,
    pub structural_invariant_candidates: Vec<StructuralInvariantCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuralSummary {
    pub contract_count: usize,
    pub external_public_selector_count: usize,
    pub privileged_selector_count: usize,
    pub payable_entrypoint_count: usize,
    pub role_candidate_count: usize,
    pub upgrade_surface_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ScopeTag {
    AdminControl,
    ProxyLike,
    ImplementationLike,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeCandidate {
    pub contract_id: String,
    pub contract_name: String,
    pub source_path: String,
    pub candidate_in_scope: bool,
    pub reason: String,
    pub confidence: f64,
    pub tags: Vec<ScopeTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ExposureClass {
    ExternalFunction,
    PublicFunction,
    Receive,
    Fallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeClass {
    Privileged,
    Unclassified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelectorCandidate {
    pub function_id: String,
    pub contract_id: String,
    pub signature: Option<String>,
    pub selector: Option<String>,
    pub entrypoint_kind: EntrypointKind,
    pub visibility: Visibility,
    pub state_mutability: StateMutability,
    pub payable: bool,
    pub exposure_class: ExposureClass,
    pub privilege_class: PrivilegeClass,
    pub role_hints: Vec<String>,
    pub provenance: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoleCandidate {
    pub role: String,
    pub contract_ids: Vec<String>,
    pub function_ids: Vec<String>,
    pub selectors: Vec<String>,
    pub entrypoints: Vec<EntrypointKind>,
    pub evidence: Vec<String>,
    pub provenance: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StructuralInvariantKind {
    AccessControlSurface,
    PauseControl,
    UpgradeControl,
    FeeWithdrawalSurface,
    PayableEntrypoint,
    EmergencyStopSurface,
    ExternalCallSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructuralInvariantCandidate {
    pub id: String,
    pub kind: StructuralInvariantKind,
    pub title: String,
    pub contract_ids: Vec<String>,
    pub function_ids: Vec<String>,
    pub selectors: Vec<String>,
    pub entrypoints: Vec<EntrypointKind>,
    pub evidence: Vec<String>,
    pub provenance: Vec<String>,
    pub confidence: f64,
}

pub fn extract_candidates(graph: &AnalysisGraph) -> ExtractedCandidates {
    ExtractedCandidates {
        scope_candidates: scope_candidates(graph),
        selector_candidates: selector_candidates(graph),
        role_candidates: role_candidates(graph),
        structural_invariant_candidates: structural_invariant_candidates(graph),
    }
}

pub fn summarize(graph: &AnalysisGraph, extracted: &ExtractedCandidates) -> StructuralSummary {
    StructuralSummary {
        contract_count: graph.contracts.len(),
        external_public_selector_count: extracted
            .selector_candidates
            .iter()
            .filter(|candidate| candidate.selector.is_some())
            .count(),
        privileged_selector_count: extracted
            .selector_candidates
            .iter()
            .filter(|candidate| candidate.privilege_class == PrivilegeClass::Privileged)
            .count(),
        payable_entrypoint_count: extracted
            .selector_candidates
            .iter()
            .filter(|candidate| candidate.payable)
            .count(),
        role_candidate_count: extracted.role_candidates.len(),
        upgrade_surface_count: extracted
            .structural_invariant_candidates
            .iter()
            .filter(|candidate| candidate.kind == StructuralInvariantKind::UpgradeControl)
            .count(),
    }
}

fn scope_candidates(graph: &AnalysisGraph) -> Vec<ScopeCandidate> {
    let callable_by_contract = callable_functions_by_contract(graph);
    let mut candidates = Vec::new();

    for contract in &graph.contracts {
        let mut tags = scope_tags(contract, &callable_by_contract);
        tags.sort();
        tags.dedup();

        let callable = callable_by_contract
            .get(&contract.id)
            .cloned()
            .unwrap_or_default();
        let source_lower = contract.source_path.to_ascii_lowercase();
        let name_lower = contract.name.to_ascii_lowercase();

        let (candidate_in_scope, reason, confidence) = match contract.kind {
            ContractKind::Interface => (
                false,
                "interface contract candidate is out of scope by default".to_string(),
                0.98,
            ),
            ContractKind::Library => (
                false,
                "library contract candidate is out of scope by default".to_string(),
                0.98,
            ),
            ContractKind::AbstractContract => (
                false,
                "abstract base contract candidate is out of scope by default".to_string(),
                0.95,
            ),
            _ if source_lower.starts_with("test/")
                || source_lower.starts_with("script/")
                || source_lower.contains("/mocks/")
                || name_lower.contains("mock") =>
            {
                (
                    false,
                    "test, script, or mock contract candidate is out of scope by default"
                        .to_string(),
                    0.96,
                )
            }
            _ if callable.is_empty() => (
                false,
                "contract has no detected public or external callable surfaces".to_string(),
                0.84,
            ),
            _ => (
                true,
                "concrete contract exposes public or external callable surfaces".to_string(),
                0.87,
            ),
        };

        candidates.push(ScopeCandidate {
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            source_path: contract.source_path.clone(),
            candidate_in_scope,
            reason,
            confidence,
            tags,
        });
    }

    candidates.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    candidates
}

fn selector_candidates(graph: &AnalysisGraph) -> Vec<SelectorCandidate> {
    let mut candidates = Vec::new();

    for function in graph.functions.iter().filter(is_callable_surface) {
        let role_hints = role_hints(&function.auth_signals);
        let privileged = !role_hints.is_empty();

        candidates.push(SelectorCandidate {
            function_id: function.id.clone(),
            contract_id: function.contract_id.clone(),
            signature: function.signature.clone(),
            selector: function.selector.clone(),
            entrypoint_kind: function.entrypoint_kind.clone(),
            visibility: function.visibility.clone(),
            state_mutability: function.state_mutability.clone(),
            payable: function.state_mutability == StateMutability::Payable
                || function.entrypoint_kind == EntrypointKind::Receive,
            exposure_class: exposure_class(function),
            privilege_class: if privileged {
                PrivilegeClass::Privileged
            } else {
                PrivilegeClass::Unclassified
            },
            role_hints: role_hints.clone(),
            provenance: selector_provenance(function),
            confidence: if privileged { 0.97 } else { 0.78 },
        });
    }

    candidates.sort_by(|left, right| left.function_id.cmp(&right.function_id));
    candidates
}

fn role_candidates(graph: &AnalysisGraph) -> Vec<RoleCandidate> {
    let callable = callable_functions_by_contract(graph);
    let mut grouped: BTreeMap<String, RoleCandidate> = BTreeMap::new();

    for function in graph.functions.iter().filter(is_callable_surface) {
        let roles = role_hints(&function.auth_signals);
        if roles.is_empty() {
            continue;
        }

        for role in roles {
            let entry = grouped.entry(role.clone()).or_insert(RoleCandidate {
                role: role.clone(),
                contract_ids: Vec::new(),
                function_ids: Vec::new(),
                selectors: Vec::new(),
                entrypoints: Vec::new(),
                evidence: Vec::new(),
                provenance: vec!["analysis_graph.auth_signals".to_string()],
                confidence: max_auth_confidence(&function.auth_signals),
            });

            entry.contract_ids.push(function.contract_id.clone());
            entry.function_ids.push(function.id.clone());
            if let Some(selector) = &function.selector {
                entry.selectors.push(selector.clone());
            }
            if function.entrypoint_kind != EntrypointKind::Normal {
                entry.entrypoints.push(function.entrypoint_kind.clone());
            }
            entry.evidence.extend(
                function
                    .auth_signals
                    .iter()
                    .filter(|signal| signal.role.as_deref() == Some(role.as_str()))
                    .map(|signal| signal.evidence.clone()),
            );
            entry.confidence = entry
                .confidence
                .max(max_auth_confidence(&function.auth_signals));
        }
    }

    let mut candidates = grouped
        .into_values()
        .map(|mut candidate| {
            dedup_sort(&mut candidate.contract_ids);
            dedup_sort(&mut candidate.function_ids);
            dedup_sort(&mut candidate.selectors);
            candidate.entrypoints.sort();
            candidate.entrypoints.dedup();
            dedup_sort(&mut candidate.evidence);
            dedup_sort(&mut candidate.provenance);
            candidate
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| left.role.cmp(&right.role));

    let _ = callable;
    candidates
}

fn structural_invariant_candidates(graph: &AnalysisGraph) -> Vec<StructuralInvariantCandidate> {
    let mut candidates = Vec::new();
    let selector_candidates = selector_candidates(graph);
    let role_candidates = role_candidates(graph);

    for role in role_candidates {
        candidates.push(StructuralInvariantCandidate {
            id: format!("access-{}", role.role),
            kind: StructuralInvariantKind::AccessControlSurface,
            title: format!("{}-gated callable surfaces", role.role),
            contract_ids: role.contract_ids.clone(),
            function_ids: role.function_ids.clone(),
            selectors: role.selectors.clone(),
            entrypoints: role.entrypoints.clone(),
            evidence: role.evidence.clone(),
            provenance: role.provenance.clone(),
            confidence: role.confidence,
        });
    }

    push_named_surface_candidate(
        &mut candidates,
        graph,
        StructuralInvariantKind::PauseControl,
        "pause-control",
        "pause and unpause controls",
        |function| matches_name(function, &["pause", "unpause"]),
    );
    push_named_surface_candidate(
        &mut candidates,
        graph,
        StructuralInvariantKind::UpgradeControl,
        "upgrade-control",
        "upgrade entrypoints",
        |function| {
            matches_name(
                function,
                &[
                    "upgrade",
                    "upgrade_to",
                    "upgrade_to_and_call",
                    "set_implementation",
                ],
            )
        },
    );
    push_named_surface_candidate(
        &mut candidates,
        graph,
        StructuralInvariantKind::FeeWithdrawalSurface,
        "fee-withdrawal",
        "fee and admin withdrawal surfaces",
        |function| {
            let name = function.name.to_ascii_lowercase();
            (name.contains("withdraw") || name.contains("sweep"))
                && (name.contains("fee") || name.contains("admin") || name.contains("treasury"))
        },
    );
    push_named_surface_candidate(
        &mut candidates,
        graph,
        StructuralInvariantKind::EmergencyStopSurface,
        "emergency-stop",
        "emergency shutdown surfaces",
        |function| {
            matches_name(
                function,
                &["shutdown", "emergency_shutdown", "stop", "kill"],
            )
        },
    );

    let payable_surfaces = selector_candidates
        .iter()
        .filter(|candidate| candidate.payable)
        .collect::<Vec<_>>();
    if !payable_surfaces.is_empty() {
        candidates.push(StructuralInvariantCandidate {
            id: "payable-entrypoints".to_string(),
            kind: StructuralInvariantKind::PayableEntrypoint,
            title: "payable entrypoints".to_string(),
            contract_ids: payable_surfaces
                .iter()
                .map(|candidate| candidate.contract_id.clone())
                .collect(),
            function_ids: payable_surfaces
                .iter()
                .map(|candidate| candidate.function_id.clone())
                .collect(),
            selectors: payable_surfaces
                .iter()
                .filter_map(|candidate| candidate.selector.clone())
                .collect(),
            entrypoints: payable_surfaces
                .iter()
                .filter(|candidate| candidate.entrypoint_kind != EntrypointKind::Normal)
                .map(|candidate| candidate.entrypoint_kind.clone())
                .collect(),
            evidence: payable_surfaces
                .iter()
                .map(|candidate| {
                    candidate
                        .signature
                        .clone()
                        .unwrap_or_else(|| format!("{:?}", candidate.entrypoint_kind))
                })
                .collect(),
            provenance: vec!["analysis_graph.functions".to_string()],
            confidence: 0.99,
        });
    }

    let external_call_functions = graph
        .functions
        .iter()
        .filter(|function| !function.calls.is_empty())
        .collect::<Vec<_>>();
    if !external_call_functions.is_empty() {
        candidates.push(StructuralInvariantCandidate {
            id: "external-call-surfaces".to_string(),
            kind: StructuralInvariantKind::ExternalCallSurface,
            title: "external call surfaces".to_string(),
            contract_ids: external_call_functions
                .iter()
                .map(|function| function.contract_id.clone())
                .collect(),
            function_ids: external_call_functions
                .iter()
                .map(|function| function.id.clone())
                .collect(),
            selectors: external_call_functions
                .iter()
                .filter_map(|function| function.selector.clone())
                .collect(),
            entrypoints: external_call_functions
                .iter()
                .filter(|function| function.entrypoint_kind != EntrypointKind::Normal)
                .map(|function| function.entrypoint_kind.clone())
                .collect(),
            evidence: external_call_functions
                .iter()
                .flat_map(|function| function.calls.iter().map(|call| call.evidence.clone()))
                .collect(),
            provenance: vec!["analysis_graph.calls".to_string()],
            confidence: 0.93,
        });
    }

    for candidate in &mut candidates {
        dedup_sort(&mut candidate.contract_ids);
        dedup_sort(&mut candidate.function_ids);
        dedup_sort(&mut candidate.selectors);
        candidate.entrypoints.sort();
        candidate.entrypoints.dedup();
        dedup_sort(&mut candidate.evidence);
        dedup_sort(&mut candidate.provenance);
    }
    candidates.sort_by(|left, right| left.id.cmp(&right.id));
    candidates
}

fn push_named_surface_candidate<F>(
    candidates: &mut Vec<StructuralInvariantCandidate>,
    graph: &AnalysisGraph,
    kind: StructuralInvariantKind,
    id: &str,
    title: &str,
    matches: F,
) where
    F: Fn(&FunctionFacts) -> bool,
{
    let matched = graph
        .functions
        .iter()
        .filter(is_callable_surface)
        .filter(|function| matches(function))
        .collect::<Vec<_>>();
    if matched.is_empty() {
        return;
    }

    candidates.push(StructuralInvariantCandidate {
        id: id.to_string(),
        kind,
        title: title.to_string(),
        contract_ids: matched
            .iter()
            .map(|function| function.contract_id.clone())
            .collect(),
        function_ids: matched.iter().map(|function| function.id.clone()).collect(),
        selectors: matched
            .iter()
            .filter_map(|function| function.selector.clone())
            .collect(),
        entrypoints: matched
            .iter()
            .filter(|function| function.entrypoint_kind != EntrypointKind::Normal)
            .map(|function| function.entrypoint_kind.clone())
            .collect(),
        evidence: matched
            .iter()
            .map(|function| {
                function
                    .signature
                    .clone()
                    .unwrap_or_else(|| function.name.clone())
            })
            .collect(),
        provenance: vec!["analysis_graph.functions".to_string()],
        confidence: 0.92,
    });
}

fn callable_functions_by_contract(graph: &AnalysisGraph) -> BTreeMap<String, Vec<FunctionFacts>> {
    let mut grouped: BTreeMap<String, Vec<FunctionFacts>> = BTreeMap::new();

    for function in graph.functions.iter().filter(is_callable_surface) {
        grouped
            .entry(function.contract_id.clone())
            .or_default()
            .push(function.clone());
    }

    grouped
}

fn scope_tags(
    contract: &ContractFacts,
    callable_by_contract: &BTreeMap<String, Vec<FunctionFacts>>,
) -> Vec<ScopeTag> {
    let mut tags = Vec::new();
    let callable = callable_by_contract
        .get(&contract.id)
        .cloned()
        .unwrap_or_default();
    let name = contract.name.to_ascii_lowercase();

    if callable
        .iter()
        .any(|function| !function.auth_signals.is_empty())
    {
        tags.push(ScopeTag::AdminControl);
    }
    if name.contains("proxy")
        || callable
            .iter()
            .any(|function| function.name.eq_ignore_ascii_case("implementation"))
    {
        tags.push(ScopeTag::ProxyLike);
    }
    if callable
        .iter()
        .any(|function| matches_name(function, &["upgrade", "upgrade_to", "upgrade_to_and_call"]))
    {
        tags.push(ScopeTag::ImplementationLike);
    }

    tags
}

fn is_callable_surface(function: &&FunctionFacts) -> bool {
    matches!(
        function.entrypoint_kind,
        EntrypointKind::Receive | EntrypointKind::Fallback
    ) || (function.entrypoint_kind == EntrypointKind::Normal
        && matches!(
            function.visibility,
            Visibility::External | Visibility::Public
        ))
}

fn exposure_class(function: &FunctionFacts) -> ExposureClass {
    match function.entrypoint_kind {
        EntrypointKind::Receive => ExposureClass::Receive,
        EntrypointKind::Fallback => ExposureClass::Fallback,
        _ => match function.visibility {
            Visibility::Public => ExposureClass::PublicFunction,
            _ => ExposureClass::ExternalFunction,
        },
    }
}

fn role_hints(auth_signals: &[AuthSignal]) -> Vec<String> {
    let mut roles = auth_signals
        .iter()
        .filter_map(|signal| signal.role.clone())
        .collect::<Vec<_>>();
    dedup_sort(&mut roles);
    roles
}

fn max_auth_confidence(auth_signals: &[AuthSignal]) -> f64 {
    auth_signals
        .iter()
        .map(|signal| signal.confidence)
        .fold(0.0_f64, f64::max)
}

fn selector_provenance(function: &FunctionFacts) -> Vec<String> {
    let mut sources = vec!["analysis_graph.functions".to_string()];
    if !function.auth_signals.is_empty() {
        sources.push("analysis_graph.auth_signals".to_string());
    }
    if !function.calls.is_empty() {
        sources.push("analysis_graph.calls".to_string());
    }
    dedup_sort(&mut sources);
    sources
}

fn matches_name(function: &FunctionFacts, names: &[&str]) -> bool {
    let normalized = normalize_function_name(&function.name);
    names
        .iter()
        .any(|candidate| normalized == normalize_function_name(candidate))
}

fn normalize_function_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn dedup_sort(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
    values.sort();
}

#[cfg(test)]
mod tests {
    use super::*;
    use analyzer::types::{
        AnalysisGraph, AuthSignal, AuthSignalKind, AuthSignalSource, CallTarget, ContractFacts,
        ContractKind, DetectorFinding, ModifierFacts, ProjectFacts, StateMutability, Visibility,
    };

    fn sample_graph() -> AnalysisGraph {
        AnalysisGraph {
            project: ProjectFacts {
                build_system: "foundry".to_string(),
                foundry_config_path: "foundry.toml".to_string(),
                src_dir: "src".to_string(),
                test_dir: "test".to_string(),
                script_dir: "script".to_string(),
                libs: vec!["lib".to_string()],
                artifact_dir: "out".to_string(),
            },
            contracts: vec![ContractFacts {
                id: "src/SimpleVault.sol:SimpleVault".to_string(),
                name: "SimpleVault".to_string(),
                source_path: "src/SimpleVault.sol".to_string(),
                kind: ContractKind::Contract,
                bases: Vec::new(),
                artifact_ref: Some("out/SimpleVault.sol/SimpleVault.json".to_string()),
            }],
            functions: vec![
                FunctionFacts {
                    id: "src/SimpleVault.sol:SimpleVault#deposit()".to_string(),
                    contract_id: "src/SimpleVault.sol:SimpleVault".to_string(),
                    name: "deposit".to_string(),
                    signature: Some("deposit()".to_string()),
                    selector: Some("0xd0e30db0".to_string()),
                    entrypoint_kind: EntrypointKind::Normal,
                    visibility: Visibility::External,
                    state_mutability: StateMutability::Payable,
                    modifiers: vec!["whenNotPaused".to_string()],
                    auth_signals: Vec::new(),
                    calls: Vec::new(),
                },
                FunctionFacts {
                    id: "src/SimpleVault.sol:SimpleVault#pause()".to_string(),
                    contract_id: "src/SimpleVault.sol:SimpleVault".to_string(),
                    name: "pause".to_string(),
                    signature: Some("pause()".to_string()),
                    selector: Some("0x8456cb59".to_string()),
                    entrypoint_kind: EntrypointKind::Normal,
                    visibility: Visibility::External,
                    state_mutability: StateMutability::Nonpayable,
                    modifiers: vec!["onlyOwner".to_string()],
                    auth_signals: vec![AuthSignal {
                        kind: AuthSignalKind::OnlyOwnerModifier,
                        source: AuthSignalSource::ModifierInvocation,
                        role: Some("owner".to_string()),
                        evidence: "modifier onlyOwner".to_string(),
                        confidence: 0.99,
                    }],
                    calls: vec![CallTarget {
                        kind: analyzer::types::CallKind::Call,
                        target: Some("feeRecipient".to_string()),
                        evidence: "feeRecipient.call(data)".to_string(),
                    }],
                },
                FunctionFacts {
                    id: "src/SimpleVault.sol:SimpleVault#fallback".to_string(),
                    contract_id: "src/SimpleVault.sol:SimpleVault".to_string(),
                    name: "fallback".to_string(),
                    signature: None,
                    selector: None,
                    entrypoint_kind: EntrypointKind::Fallback,
                    visibility: Visibility::External,
                    state_mutability: StateMutability::Payable,
                    modifiers: Vec::new(),
                    auth_signals: Vec::new(),
                    calls: Vec::new(),
                },
            ],
            modifiers: vec![ModifierFacts {
                id: "src/SimpleVault.sol:SimpleVault#modifier:onlyOwner".to_string(),
                contract_id: "src/SimpleVault.sol:SimpleVault".to_string(),
                name: "onlyOwner".to_string(),
                source_path: "src/SimpleVault.sol".to_string(),
                auth_signals: Vec::new(),
            }],
            inheritance: Vec::new(),
            detector_findings: Vec::<DetectorFinding>::new(),
        }
    }

    #[test]
    fn extracts_privileged_roles_and_named_surfaces() {
        let graph = sample_graph();
        let extracted = extract_candidates(&graph);
        let summary = summarize(&graph, &extracted);

        assert_eq!(summary.contract_count, 1);
        assert_eq!(summary.privileged_selector_count, 1);
        assert_eq!(summary.payable_entrypoint_count, 2);
        assert!(
            extracted
                .role_candidates
                .iter()
                .any(|candidate| candidate.role == "owner")
        );
        assert!(
            extracted
                .structural_invariant_candidates
                .iter()
                .any(|candidate| candidate.kind == StructuralInvariantKind::PauseControl)
        );
        assert!(
            extracted
                .structural_invariant_candidates
                .iter()
                .any(|candidate| candidate.kind == StructuralInvariantKind::ExternalCallSurface)
        );
    }

    #[test]
    fn extracts_fallback_as_callable_surface_without_selector() {
        let graph = sample_graph();
        let extracted = extract_candidates(&graph);
        let fallback = extracted
            .selector_candidates
            .iter()
            .find(|candidate| candidate.entrypoint_kind == EntrypointKind::Fallback)
            .unwrap();

        assert_eq!(
            fallback.function_id,
            "src/SimpleVault.sol:SimpleVault#fallback"
        );
        assert_eq!(fallback.signature, None);
        assert_eq!(fallback.selector, None);
        assert_eq!(fallback.exposure_class, ExposureClass::Fallback);
        assert!(fallback.payable);
    }
}
