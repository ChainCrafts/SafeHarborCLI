use crate::{
    signatures::{
        ERC4626_MUTATION_SIGNATURES, ERC4626_PREVIEW_MAX_SIGNATURES, ERC4626_VIEW_SIGNATURES,
        count_present_signatures, dedup_sort, function_ids, functions_matching_signatures,
        has_all_signatures, has_named_base, recognition_id, selectors,
    },
    types::{
        RecognitionCategory, RecognitionEvidence, RecognitionEvidenceSource, RecognitionKind,
        RecognizedStandard,
    },
};
use analyzer::types::AnalysisGraph;
use std::collections::BTreeSet;

pub fn recognize(
    graph: &AnalysisGraph,
    erc20_contracts: &BTreeSet<String>,
) -> Vec<RecognizedStandard> {
    let mut standards = Vec::new();

    for contract in &graph.contracts {
        let exact_base = has_named_base(contract, &["ERC4626", "IERC4626"]);
        let erc20_supported = erc20_contracts.contains(&contract.id);
        if !exact_base && !erc20_supported {
            continue;
        }

        if !has_all_signatures(graph, &contract.id, ERC4626_VIEW_SIGNATURES) {
            continue;
        }

        let mutation_count =
            count_present_signatures(graph, &contract.id, ERC4626_MUTATION_SIGNATURES);
        let full_mutation_surface = mutation_count == ERC4626_MUTATION_SIGNATURES.len();
        if !full_mutation_surface && !(exact_base && mutation_count >= 2) {
            continue;
        }

        let view_functions =
            functions_matching_signatures(graph, &contract.id, ERC4626_VIEW_SIGNATURES);
        let mutation_functions =
            functions_matching_signatures(graph, &contract.id, ERC4626_MUTATION_SIGNATURES);
        let preview_functions =
            functions_matching_signatures(graph, &contract.id, ERC4626_PREVIEW_MAX_SIGNATURES);
        let confidence = if full_mutation_surface && exact_base {
            0.99
        } else if full_mutation_surface {
            0.96
        } else {
            0.90
        };

        let mut affected_functions = view_functions.clone();
        affected_functions.extend(mutation_functions.clone());
        affected_functions.extend(preview_functions.clone());

        let mut evidence = vec![
            RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: "contract exposes ERC4626 asset/share accounting view signatures"
                    .to_string(),
                function_ids: function_ids(&view_functions),
                selectors: selectors(&view_functions),
                confidence: 0.90,
            },
            RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: if full_mutation_surface {
                    "contract exposes all ERC4626 deposit, mint, withdraw, and redeem signatures"
                        .to_string()
                } else {
                    "contract inherits ERC4626 and exposes a partial vault mutation surface"
                        .to_string()
                },
                function_ids: function_ids(&mutation_functions),
                selectors: selectors(&mutation_functions),
                confidence: if full_mutation_surface { 0.96 } else { 0.90 },
            },
        ];

        if !preview_functions.is_empty() {
            evidence.push(RecognitionEvidence {
                source: RecognitionEvidenceSource::FunctionSignature,
                detail: "contract exposes ERC4626 preview or max limit signatures".to_string(),
                function_ids: function_ids(&preview_functions),
                selectors: selectors(&preview_functions),
                confidence: 0.96,
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

        let mut provenance = vec!["analysis_graph.functions".to_string()];
        if exact_base {
            provenance.push("analysis_graph.inheritance".to_string());
        }
        dedup_sort(&mut provenance);

        standards.push(RecognizedStandard {
            id: recognition_id(&contract.id, RecognitionKind::Erc4626.id_part()),
            contract_id: contract.id.clone(),
            contract_name: contract.name.clone(),
            kind: RecognitionKind::Erc4626,
            category: RecognitionCategory::VaultStandard,
            standard_reference: Some("ERC-4626".to_string()),
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
