use crate::{
    recognizers::{access_control::role_gated_functions, ownable::owner_gated_functions},
    signatures::{
        UPGRADE_SIGNATURES, callable_functions_for_contract, dedup_sort, function_ids,
        functions_matching_signatures, has_named_base, recognition_id, selectors,
    },
    types::{
        RecognitionCategory, RecognitionEvidence, RecognitionEvidenceSource, RecognitionKind,
        RecognizedStandard,
    },
};
use analyzer::types::{AnalysisGraph, EntrypointKind, FunctionFacts, StateMutability};

pub fn recognize(graph: &AnalysisGraph) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();
    standards.extend(recognize_pausable(graph));
    standards.extend(recognize_upgradeable(graph));
    standards.sort_by(|left, right| left.id.cmp(&right.id));
    standards
}

fn recognize_pausable(graph: &AnalysisGraph) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();

    for contract in &graph.contracts {
        let pause_functions =
            functions_matching_signatures(graph, &contract.id, &["pause()", "unpause()"]);
        let guarded_functions = pausable_guarded_functions(graph, &contract.id);
        let pause_modifiers = graph
            .modifiers
            .iter()
            .filter(|modifier| {
                modifier.contract_id == contract.id
                    && matches!(
                        normalize_modifier_name(&modifier.name).as_str(),
                        "whennotpaused" | "whenpaused"
                    )
            })
            .collect::<Vec<_>>();
        let exact_base = has_named_base(contract, &["Pausable"]);
        if pause_functions.is_empty()
            && guarded_functions.is_empty()
            && pause_modifiers.is_empty()
            && !exact_base
        {
            continue;
        }

        let confidence = if !pause_functions.is_empty() && !guarded_functions.is_empty() {
            0.95
        } else if !guarded_functions.is_empty() || exact_base {
            0.92
        } else {
            0.90
        };

        let mut affected_functions = pause_functions.clone();
        affected_functions.extend(guarded_functions.clone());
        affected_functions.extend(payable_special_entrypoints(graph, &contract.id));
        let mut evidence = Vec::new();
        if !pause_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: "contract exposes pause or unpause control signatures".to_string(),
                function_ids: function_ids(&pause_functions),
                selectors: selectors(&pause_functions),
                confidence: 0.90,
            });
        }
        if !guarded_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::Modifier,
                detail: "callable functions use whenPaused or whenNotPaused modifiers".to_string(),
                function_ids: function_ids(&guarded_functions),
                selectors: selectors(&guarded_functions),
                confidence: 0.95,
            });
        }
        if exact_base {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::Inheritance,
                detail: format!("contract inherits one of {:?}", contract.bases),
                function_ids: Vec::new(),
                selectors: Vec::new(),
                confidence: 0.92,
            });
        }

        let mut provenance = vec!["analysis_graph.functions".to_string()];
        if !guarded_functions.is_empty() || !pause_modifiers.is_empty() {
            provenance.push("analysis_graph.modifiers".to_string());
        }
        if exact_base {
            provenance.push("analysis_graph.inheritance".to_string());
        }
        dedup_sort(&mut provenance);

        standards.push(RecognizedStandard {
            id: recognition_id(&contract.id, RecognitionKind::Pausable.id_part()),
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            kind: RecognitionKind::Pausable,
            category: RecognitionCategory::OperationalPattern,
            standard_reference: Some("OpenZeppelin Contracts Pausable".to_string()),
            confidence,
            evidence,
            affected_function_ids: function_ids(&affected_functions),
            affected_selectors: selectors(&affected_functions),
            provenance,
        });
    }

    standards
}

fn recognize_upgradeable(graph: &AnalysisGraph) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();

    for contract in &graph.contracts {
        let upgrade_functions =
            functions_matching_signatures(graph, &contract.id, UPGRADE_SIGNATURES);
        let exact_base = has_named_base(contract, &["UUPSUpgradeable"]);
        if upgrade_functions.is_empty() && !exact_base {
            continue;
        }

        let owner_gated = owner_gated_functions(graph, &contract.id);
        let role_gated = role_gated_functions(graph, &contract.id);
        let gated_upgrade = upgrade_functions.iter().any(|upgrade| {
            owner_gated.iter().any(|function| function.id == upgrade.id)
                || role_gated.iter().any(|function| function.id == upgrade.id)
        });
        let confidence = if exact_base && gated_upgrade {
            0.95
        } else if gated_upgrade {
            0.95
        } else if exact_base {
            0.92
        } else {
            0.88
        };

        let mut evidence = Vec::new();
        if !upgrade_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: "contract exposes upgrade or UUPS compatibility signatures".to_string(),
                function_ids: function_ids(&upgrade_functions),
                selectors: selectors(&upgrade_functions),
                confidence: 0.88,
            });
        }
        if gated_upgrade {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::AuthSignal,
                detail: "upgrade entrypoints carry owner or role auth signals".to_string(),
                function_ids: function_ids(&upgrade_functions),
                selectors: selectors(&upgrade_functions),
                confidence: 0.95,
            });
        }
        if exact_base {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::Inheritance,
                detail: format!("contract inherits one of {:?}", contract.bases),
                function_ids: Vec::new(),
                selectors: Vec::new(),
                confidence: 0.92,
            });
        }

        let mut provenance = vec!["analysis_graph.functions".to_string()];
        if gated_upgrade {
            provenance.push("analysis_graph.auth_signals".to_string());
        }
        if exact_base {
            provenance.push("analysis_graph.inheritance".to_string());
        }
        dedup_sort(&mut provenance);

        standards.push(RecognizedStandard {
            id: recognition_id(&contract.id, RecognitionKind::Upgradeable.id_part()),
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            kind: RecognitionKind::Upgradeable,
            category: RecognitionCategory::UpgradePattern,
            standard_reference: Some("UUPS or upgradeable implementation pattern".to_string()),
            confidence,
            evidence,
            affected_function_ids: function_ids(&upgrade_functions),
            affected_selectors: selectors(&upgrade_functions),
            provenance,
        });
    }

    standards
}

pub fn pausable_user_entrypoints<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    let mut functions = pausable_guarded_functions(graph, contract_id)
        .into_iter()
        .filter(|function| {
            !matches!(
                function.signature.as_deref(),
                Some("pause()") | Some("unpause()")
            )
        })
        .collect::<Vec<_>>();
    functions.extend(payable_special_entrypoints(graph, contract_id));
    functions.sort_by(|left, right| left.id.cmp(&right.id));
    functions.dedup_by(|left, right| left.id == right.id);
    functions
}

fn pausable_guarded_functions<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    callable_functions_for_contract(graph, contract_id)
        .into_iter()
        .filter(|function| {
            function.modifiers.iter().any(|modifier| {
                matches!(
                    normalize_modifier_name(modifier).as_str(),
                    "whennotpaused" | "whenpaused"
                )
            })
        })
        .collect()
}

fn payable_special_entrypoints<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    callable_functions_for_contract(graph, contract_id)
        .into_iter()
        .filter(|function| {
            matches!(
                function.entrypoint_kind,
                EntrypointKind::Receive | EntrypointKind::Fallback
            ) && function.state_mutability == StateMutability::Payable
        })
        .collect()
}

fn normalize_modifier_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}
