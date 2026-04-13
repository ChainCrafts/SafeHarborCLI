use crate::{
    signatures::{
        ACCESS_CONTROL_MANAGEMENT_SIGNATURES, callable_functions_for_contract,
        count_present_signatures, dedup_sort, function_ids, functions_matching_signatures,
        has_named_base, recognition_id, selectors,
    },
    types::{
        RecognitionCategory, RecognitionEvidence, RecognitionEvidenceSource, RecognitionKind,
        RecognitionType, RecognizedStandard,
    },
};
use analyzer::types::{AnalysisGraph, AuthSignalKind, FunctionFacts};

pub fn recognize(graph: &AnalysisGraph) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();

    for contract in &graph.contracts {
        let role_functions = role_gated_functions(graph, &contract.id);
        let management_functions = functions_matching_signatures(
            graph,
            &contract.id,
            ACCESS_CONTROL_MANAGEMENT_SIGNATURES,
        );
        let exact_base = has_named_base(contract, &["AccessControl", "IAccessControl"]);
        if role_functions.is_empty() && management_functions.is_empty() && !exact_base {
            continue;
        }

        let management_count =
            count_present_signatures(graph, &contract.id, ACCESS_CONTROL_MANAGEMENT_SIGNATURES);
        let confidence = if !role_functions.is_empty() && management_count >= 3 {
            0.96
        } else if !role_functions.is_empty() {
            0.90
        } else if exact_base {
            0.84
        } else {
            continue;
        };

        let mut affected_functions = role_functions.clone();
        affected_functions.extend(management_functions.clone());
        let mut evidence = Vec::new();
        if !role_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::AuthSignal,
                detail: "callable functions carry role-based auth signals".to_string(),
                function_ids: function_ids(&role_functions),
                selectors: selectors(&role_functions),
                confidence: if management_count >= 3 { 0.96 } else { 0.90 },
            });
        }
        if !management_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: "contract exposes AccessControl role management signatures".to_string(),
                function_ids: function_ids(&management_functions),
                selectors: selectors(&management_functions),
                confidence: 0.96,
            });
        }
        if exact_base {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::Inheritance,
                detail: format!("contract inherits one of {:?}", contract.bases),
                function_ids: Vec::new(),
                selectors: Vec::new(),
                confidence: 0.84,
            });
        }

        let mut provenance = vec!["analysis_graph.functions".to_string()];
        if !role_functions.is_empty() {
            provenance.push("analysis_graph.auth_signals".to_string());
        }
        if exact_base {
            provenance.push("analysis_graph.inheritance".to_string());
        }
        dedup_sort(&mut provenance);

        standards.push(RecognizedStandard {
            id: recognition_id(&contract.id, RecognitionKind::AccessControl.id_part()),
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            kind: RecognitionKind::AccessControl,
            recognition_type: RecognitionType::Pattern,
            category: RecognitionCategory::AccessPattern,
            standard_reference: Some("OpenZeppelin Contracts AccessControl".to_string()),
            confidence,
            evidence,
            affected_function_ids: function_ids(&affected_functions),
            affected_selectors: selectors(&affected_functions),
            provenance,
        });
    }

    standards.sort_by(|left, right| left.id.cmp(&right.id));
    standards
}

pub fn role_gated_functions<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    callable_functions_for_contract(graph, contract_id)
        .into_iter()
        .filter(|function| {
            function.auth_signals.iter().any(|signal| {
                matches!(
                    signal.kind,
                    AuthSignalKind::OnlyRoleModifier | AuthSignalKind::RoleCheck
                )
            })
        })
        .collect()
}
