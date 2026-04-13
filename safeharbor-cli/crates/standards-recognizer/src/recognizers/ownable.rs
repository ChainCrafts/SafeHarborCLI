use crate::{
    confidence::max_confidence,
    signatures::{
        OWNABLE_MANAGEMENT_SIGNATURES, callable_functions_for_contract, count_present_signatures,
        dedup_sort, function_ids, functions_matching_signatures, has_named_base, recognition_id,
        selectors,
    },
    types::{
        RecognitionCategory, RecognitionEvidence, RecognitionEvidenceSource, RecognitionKind,
        RecognizedStandard,
    },
};
use analyzer::types::{AnalysisGraph, AuthSignalKind, FunctionFacts};

pub fn recognize(graph: &AnalysisGraph) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();

    for contract in &graph.contracts {
        let owner_functions = owner_gated_functions(graph, &contract.id);
        let management_functions =
            functions_matching_signatures(graph, &contract.id, OWNABLE_MANAGEMENT_SIGNATURES);
        let exact_base = has_named_base(contract, &["Ownable", "Ownable2Step"]);
        if owner_functions.is_empty() && management_functions.is_empty() && !exact_base {
            continue;
        }

        let management_count =
            count_present_signatures(graph, &contract.id, OWNABLE_MANAGEMENT_SIGNATURES);
        let confidence = if !owner_functions.is_empty() {
            max_confidence(owner_functions.iter().flat_map(|function| {
                function
                    .auth_signals
                    .iter()
                    .filter(|signal| signal.role.as_deref() == Some("owner"))
                    .map(|signal| signal.confidence)
            }))
            .max(0.99)
        } else if exact_base {
            0.88
        } else if management_count >= 2 {
            0.88
        } else {
            continue;
        };

        let mut affected_functions = owner_functions.clone();
        affected_functions.extend(management_functions.clone());
        let mut evidence = Vec::new();
        if !owner_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::AuthSignal,
                detail: "callable functions carry owner auth signals".to_string(),
                function_ids: function_ids(&owner_functions),
                selectors: selectors(&owner_functions),
                confidence: 0.99,
            });
        }
        if !management_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: "contract exposes Ownable ownership management signatures".to_string(),
                function_ids: function_ids(&management_functions),
                selectors: selectors(&management_functions),
                confidence: 0.88,
            });
        }
        if exact_base {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::Inheritance,
                detail: format!("contract inherits one of {:?}", contract.bases),
                function_ids: Vec::new(),
                selectors: Vec::new(),
                confidence: 0.94,
            });
        }

        let mut provenance = vec!["analysis_graph.functions".to_string()];
        if !owner_functions.is_empty() {
            provenance.push("analysis_graph.auth_signals".to_string());
        }
        if exact_base {
            provenance.push("analysis_graph.inheritance".to_string());
        }
        dedup_sort(&mut provenance);

        standards.push(RecognizedStandard {
            id: recognition_id(&contract.id, RecognitionKind::Ownable.id_part()),
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            kind: RecognitionKind::Ownable,
            category: RecognitionCategory::AccessPattern,
            standard_reference: Some("OpenZeppelin Contracts Ownable".to_string()),
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

pub fn owner_gated_functions<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    callable_functions_for_contract(graph, contract_id)
        .into_iter()
        .filter(|function| {
            function.auth_signals.iter().any(|signal| {
                signal.role.as_deref() == Some("owner")
                    || matches!(
                        signal.kind,
                        AuthSignalKind::OnlyOwnerModifier | AuthSignalKind::OwnerCheck
                    )
            })
        })
        .collect()
}
