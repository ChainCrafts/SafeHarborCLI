use crate::{
    signatures::{
        ERC20_CORE_SIGNATURES, ERC20_METADATA_SIGNATURES, dedup_sort, function_ids,
        functions_matching_signatures, has_all_signatures, has_named_base, recognition_id,
        selectors,
    },
    types::{
        RecognitionCategory, RecognitionEvidence, RecognitionEvidenceSource, RecognitionKind,
        RecognizedStandard,
    },
};
use analyzer::types::{AnalysisGraph, ContractFacts, FunctionFacts};

pub fn recognize(graph: &AnalysisGraph) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();

    for contract in &graph.contracts {
        if !has_all_signatures(graph, &contract.id, ERC20_CORE_SIGNATURES) {
            continue;
        }

        let core_functions =
            functions_matching_signatures(graph, &contract.id, ERC20_CORE_SIGNATURES);
        let metadata_functions =
            functions_matching_signatures(graph, &contract.id, ERC20_METADATA_SIGNATURES);
        let exact_base = has_named_base(contract, &["ERC20", "IERC20"]);
        let metadata_complete = metadata_functions.len() == ERC20_METADATA_SIGNATURES.len();
        let confidence = if exact_base {
            0.99
        } else if metadata_complete {
            0.97
        } else {
            0.92
        };

        let mut affected_functions = core_functions.clone();
        affected_functions.extend(metadata_functions.clone());
        let evidence = erc20_evidence(contract, &core_functions, &metadata_functions, exact_base);
        let provenance = provenance(exact_base);

        standards.push(RecognizedStandard {
            id: recognition_id(&contract.id, RecognitionKind::Erc20.id_part()),
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            kind: RecognitionKind::Erc20,
            category: RecognitionCategory::TokenStandard,
            standard_reference: Some("ERC-20".to_string()),
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

fn erc20_evidence(
    contract: &ContractFacts,
    core_functions: &[&FunctionFacts],
    metadata_functions: &[&FunctionFacts],
    exact_base: bool,
) -> Vec<RecognitionEvidence> {
    let mut evidence = vec![RecognitionEvidence {
        source: RecognitionEvidenceSource::FunctionSignature,
        detail: "contract exposes all six ERC20 core function signatures".to_string(),
        function_ids: function_ids(core_functions),
        selectors: selectors(core_functions),
        confidence: 0.92,
    }];

    if metadata_functions.len() == ERC20_METADATA_SIGNATURES.len() {
        evidence.push(RecognitionEvidence {
            source: RecognitionEvidenceSource::FunctionSignature,
            detail: "contract exposes ERC20 metadata function signatures".to_string(),
            function_ids: function_ids(metadata_functions),
            selectors: selectors(metadata_functions),
            confidence: 0.97,
        });
    }

    if exact_base {
        evidence.push(RecognitionEvidence {
            source: RecognitionEvidenceSource::Inheritance,
            detail: format!("contract inherits one of {:?}", contract.bases),
            function_ids: Vec::new(),
            selectors: Vec::new(),
            confidence: 0.99,
        });
    }

    evidence
}

fn provenance(exact_base: bool) -> Vec<String> {
    let mut provenance = vec!["analysis_graph.functions".to_string()];
    if exact_base {
        provenance.push("analysis_graph.inheritance".to_string());
    }
    dedup_sort(&mut provenance);
    provenance
}
