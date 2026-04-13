mod confidence;
mod recognizers;
mod signatures;
mod templates;
pub mod types;

use analyzer::types::{AnalysisGraph, ScanMetadata};
use std::collections::{BTreeMap, BTreeSet};

pub use types::{
    PersistedStandardsRecognition, RecognitionOutput, RecognitionSummary,
    SemanticTemplateSuggestion,
};

use crate::{
    confidence::high_confidence,
    recognizers::{access_control, erc20, erc4626, ownable, patterns},
    templates::suggest_templates,
    types::{RecognitionKind, RecognizedStandard},
};

pub fn recognize_standards(graph: &AnalysisGraph) -> RecognitionOutput {
    let mut recognized_standards = Vec::new();

    let erc20 = erc20::recognize(graph);
    let erc20_contracts = erc20
        .iter()
        .map(|recognition| recognition.contract_id.clone())
        .collect::<BTreeSet<_>>();
    recognized_standards.extend(erc20);
    recognized_standards.extend(erc4626::recognize(graph, &erc20_contracts));
    recognized_standards.extend(ownable::recognize(graph));
    recognized_standards.extend(access_control::recognize(graph));
    recognized_standards.extend(patterns::recognize(graph));

    recognized_standards.sort_by(|left, right| {
        left.contract_id
            .cmp(&right.contract_id)
            .then(left.kind.cmp(&right.kind))
            .then(left.id.cmp(&right.id))
    });

    let semantic_template_suggestions = suggest_templates(graph, &recognized_standards);
    let recognition_summary =
        summarize(graph, &recognized_standards, &semantic_template_suggestions);

    RecognitionOutput {
        recognized_standards,
        semantic_template_suggestions,
        recognition_summary,
    }
}

pub fn persisted_standards_recognition(
    output: RecognitionOutput,
    metadata: ScanMetadata,
) -> PersistedStandardsRecognition {
    PersistedStandardsRecognition {
        metadata,
        recognized_standards: output.recognized_standards,
        semantic_template_suggestions: output.semantic_template_suggestions,
        recognition_summary: output.recognition_summary,
    }
}

fn summarize(
    graph: &AnalysisGraph,
    recognized_standards: &[RecognizedStandard],
    semantic_template_suggestions: &[SemanticTemplateSuggestion],
) -> RecognitionSummary {
    let mut recognized_by_kind = BTreeMap::<RecognitionKind, usize>::new();
    for recognition in recognized_standards {
        *recognized_by_kind
            .entry(recognition.kind.clone())
            .or_insert(0) += 1;
    }

    RecognitionSummary {
        contract_count: graph.contracts.len(),
        recognized_standard_count: recognized_standards.len(),
        semantic_template_suggestion_count: semantic_template_suggestions.len(),
        high_confidence_recognition_count: recognized_standards
            .iter()
            .filter(|recognition| high_confidence(recognition.confidence))
            .count(),
        recognized_by_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use analyzer::types::{
        AnalysisGraph, AuthSignal, AuthSignalKind, AuthSignalSource, ContractFacts, ContractKind,
        DetectorFinding, EntrypointKind, FunctionFacts, ModifierFacts, ProjectFacts,
        StateMutability, Visibility,
    };

    fn base_graph(functions: Vec<FunctionFacts>, bases: Vec<String>) -> AnalysisGraph {
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
                id: "src/Token.sol:Token".to_string(),
                name: "Token".to_string(),
                source_path: "src/Token.sol".to_string(),
                kind: ContractKind::Contract,
                bases,
                artifact_ref: Some("out/Token.sol/Token.json".to_string()),
            }],
            functions,
            modifiers: Vec::<ModifierFacts>::new(),
            inheritance: Vec::new(),
            detector_findings: Vec::<DetectorFinding>::new(),
        }
    }

    fn function(signature: &str) -> FunctionFacts {
        FunctionFacts {
            id: format!("src/Token.sol:Token#{signature}"),
            contract_id: "src/Token.sol:Token".to_string(),
            name: signature.split('(').next().unwrap().to_string(),
            signature: Some(signature.to_string()),
            selector: Some(format!("0x{:08x}", signature.len())),
            entrypoint_kind: EntrypointKind::Normal,
            visibility: Visibility::External,
            state_mutability: StateMutability::Nonpayable,
            modifiers: Vec::new(),
            auth_signals: Vec::new(),
            calls: Vec::new(),
        }
    }

    fn receive_function() -> FunctionFacts {
        FunctionFacts {
            id: "src/Token.sol:Token#receive".to_string(),
            contract_id: "src/Token.sol:Token".to_string(),
            name: "receive".to_string(),
            signature: None,
            selector: None,
            entrypoint_kind: EntrypointKind::Receive,
            visibility: Visibility::External,
            state_mutability: StateMutability::Payable,
            modifiers: Vec::new(),
            auth_signals: Vec::new(),
            calls: Vec::new(),
        }
    }

    #[test]
    fn recognizes_erc20_only_with_full_core_surface() {
        let functions = crate::signatures::ERC20_CORE_SIGNATURES
            .iter()
            .chain(crate::signatures::ERC20_METADATA_SIGNATURES.iter())
            .map(|signature| function(signature))
            .collect::<Vec<_>>();
        let output = recognize_standards(&base_graph(functions, Vec::new()));

        assert!(
            output
                .recognized_standards
                .iter()
                .any(|recognition| recognition.kind == RecognitionKind::Erc20)
        );
        assert!(
            output
                .semantic_template_suggestions
                .iter()
                .any(|suggestion| suggestion.template_id == "erc20:transfer-accounting-review")
        );
    }

    #[test]
    fn does_not_recognize_erc20_from_partial_surface() {
        let functions = vec![
            function("transfer(address,uint256)"),
            function("approve(address,uint256)"),
        ];
        let output = recognize_standards(&base_graph(functions, Vec::new()));

        assert!(
            output
                .recognized_standards
                .iter()
                .all(|recognition| recognition.kind != RecognitionKind::Erc20)
        );
    }

    #[test]
    fn recognizes_ownable_from_owner_auth_signals() {
        let mut pause = function("pause()");
        pause.modifiers = vec!["onlyOwner".to_string()];
        pause.auth_signals = vec![AuthSignal {
            kind: AuthSignalKind::OnlyOwnerModifier,
            source: AuthSignalSource::ModifierInvocation,
            role: Some("owner".to_string()),
            evidence: "modifier onlyOwner".to_string(),
            confidence: 0.99,
        }];
        let output = recognize_standards(&base_graph(vec![pause], Vec::new()));

        assert!(
            output
                .recognized_standards
                .iter()
                .any(|recognition| recognition.kind == RecognitionKind::Ownable)
        );
        assert!(
            output
                .semantic_template_suggestions
                .iter()
                .any(|suggestion| {
                    suggestion.template_id == "ownable:owner-gated-admin-surfaces"
                })
        );
    }

    #[test]
    fn recognizes_access_control_from_role_auth_signals() {
        let mut pause = function("pause()");
        pause.modifiers = vec!["onlyRole".to_string()];
        pause.auth_signals = vec![AuthSignal {
            kind: AuthSignalKind::OnlyRoleModifier,
            source: AuthSignalSource::ModifierInvocation,
            role: Some("pauser".to_string()),
            evidence: "modifier onlyRole(pauser)".to_string(),
            confidence: 0.98,
        }];
        let mut functions = vec![pause];
        functions.extend(
            [
                "hasRole(bytes32,address)",
                "getRoleAdmin(bytes32)",
                "grantRole(bytes32,address)",
            ]
            .iter()
            .map(|signature| function(signature)),
        );
        let output = recognize_standards(&base_graph(functions, Vec::new()));

        assert!(
            output
                .recognized_standards
                .iter()
                .any(
                    |recognition| recognition.kind == RecognitionKind::AccessControl
                        && recognition.confidence == 0.96
                )
        );
        assert!(
            output
                .semantic_template_suggestions
                .iter()
                .any(|suggestion| {
                    suggestion.template_id == "access-control:role-gated-admin-surfaces"
                })
        );
    }

    #[test]
    fn recognizes_pausable_and_upgradeable_patterns() {
        let pause = function("pause()");
        let unpause = function("unpause()");
        let mut deposit = function("deposit()");
        deposit.modifiers = vec!["whenNotPaused".to_string()];
        deposit.state_mutability = StateMutability::Payable;
        let mut upgrade = function("upgradeTo(address)");
        upgrade.auth_signals = vec![AuthSignal {
            kind: AuthSignalKind::OnlyOwnerModifier,
            source: AuthSignalSource::ModifierInvocation,
            role: Some("owner".to_string()),
            evidence: "modifier onlyOwner".to_string(),
            confidence: 0.99,
        }];
        let output = recognize_standards(&base_graph(
            vec![pause, unpause, deposit, receive_function(), upgrade],
            Vec::new(),
        ));

        assert!(
            output
                .recognized_standards
                .iter()
                .any(|recognition| recognition.kind == RecognitionKind::Pausable)
        );
        assert!(
            output
                .recognized_standards
                .iter()
                .any(|recognition| recognition.kind == RecognitionKind::Upgradeable)
        );
        assert!(
            output
                .semantic_template_suggestions
                .iter()
                .any(|suggestion| {
                    suggestion.template_id == "openzeppelin-pausable:user-entrypoint-guard"
                        && !suggestion.special_entrypoints.is_empty()
                })
        );
    }
}
