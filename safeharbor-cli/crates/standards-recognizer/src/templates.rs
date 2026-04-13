use crate::{
    recognizers::{
        access_control::role_gated_functions, ownable::owner_gated_functions,
        patterns::pausable_user_entrypoints,
    },
    signatures::{
        ERC20_CORE_SIGNATURES, ERC4626_MUTATION_SIGNATURES, ERC4626_PREVIEW_MAX_SIGNATURES,
        ERC4626_VIEW_SIGNATURES, UPGRADE_SIGNATURES, dedup_sort, function_ids,
        functions_matching_signatures, is_state_changing, selectors, special_entrypoints,
        suggestion_id,
    },
    types::{
        RecognitionKind, RecognizedStandard, SemanticTemplateKind, SemanticTemplateSuggestion,
        SuggestionClass, SuggestionSeverity, TemplateEvidenceType, TemplateReviewStatus,
    },
};
use analyzer::types::{AnalysisGraph, AuthSignalKind, FunctionFacts};
use std::collections::BTreeMap;

pub fn suggest_templates(
    graph: &AnalysisGraph,
    recognitions: &[RecognizedStandard],
) -> Vec<SemanticTemplateSuggestion> {
    let mut suggestions = Vec::new();

    for recognition in recognitions {
        match recognition.kind {
            RecognitionKind::Ownable => suggestions.extend(ownable_suggestions(graph, recognition)),
            RecognitionKind::AccessControl => {
                suggestions.extend(access_control_suggestions(graph, recognition))
            }
            RecognitionKind::Erc20 => suggestions.extend(erc20_suggestions(graph, recognition)),
            RecognitionKind::Erc4626 => suggestions.extend(erc4626_suggestions(graph, recognition)),
            RecognitionKind::Pausable => {
                suggestions.extend(pausable_suggestions(graph, recognition))
            }
            RecognitionKind::Upgradeable => {
                suggestions.extend(upgradeable_suggestions(graph, recognition))
            }
        }
    }

    suggestions.sort_by(|left, right| left.id.cmp(&right.id));
    suggestions
}

fn ownable_suggestions(
    graph: &AnalysisGraph,
    recognition: &RecognizedStandard,
) -> Vec<SemanticTemplateSuggestion> {
    let functions = owner_gated_functions(graph, &recognition.contract_id)
        .into_iter()
        .filter(|function| is_state_changing(function))
        .collect::<Vec<_>>();
    if functions.is_empty() {
        return Vec::new();
    }

    vec![base_suggestion(
        recognition,
        "ownable:owner-gated-admin-surfaces",
        SemanticTemplateKind::AccessControl,
        SuggestionSeverity::Critical,
        "Owner-gated admin surfaces",
        "Suggested review target: owner-gated administrative entrypoints should remain restricted to the reviewed owner authority.",
        "This suggestion is derived from explicit owner auth signals. It does not decide whether the owner role holder set is acceptable; human review must confirm that intent.",
        &functions,
        Vec::new(),
        vec![
            TemplateEvidenceType::SelectorAccessBreach,
            TemplateEvidenceType::Trace,
            TemplateEvidenceType::StateDiff,
        ],
    )]
}

fn access_control_suggestions(
    graph: &AnalysisGraph,
    recognition: &RecognizedStandard,
) -> Vec<SemanticTemplateSuggestion> {
    let mut by_role: BTreeMap<String, Vec<&FunctionFacts>> = BTreeMap::new();
    for function in role_gated_functions(graph, &recognition.contract_id) {
        for signal in &function.auth_signals {
            if !matches!(
                signal.kind,
                AuthSignalKind::OnlyRoleModifier | AuthSignalKind::RoleCheck
            ) {
                continue;
            }
            if let Some(role) = &signal.role {
                by_role.entry(role.clone()).or_default().push(function);
            }
        }
    }

    if by_role.is_empty() {
        let functions = role_gated_functions(graph, &recognition.contract_id);
        if functions.is_empty() {
            return Vec::new();
        }
        return vec![access_control_suggestion(
            recognition,
            "unknown-role",
            &functions,
        )];
    }

    by_role
        .into_iter()
        .map(|(role, mut functions)| {
            functions.sort_by(|left, right| left.id.cmp(&right.id));
            functions.dedup_by(|left, right| left.id == right.id);
            access_control_suggestion(recognition, &role, &functions)
        })
        .collect()
}

fn access_control_suggestion(
    recognition: &RecognizedStandard,
    role: &str,
    functions: &[&FunctionFacts],
) -> SemanticTemplateSuggestion {
    let template_id = "access-control:role-gated-admin-surfaces";
    base_suggestion(
        recognition,
        template_id,
        SemanticTemplateKind::AccessControl,
        SuggestionSeverity::Critical,
        &format!("{role} role-gated surfaces"),
        "Suggested review target: role-gated entrypoints should remain restricted to the reviewed role authority.",
        "This suggestion is derived from explicit role auth signals. It does not determine whether the role hierarchy or deployed holders are safe; human review must confirm that intent.",
        functions,
        Vec::new(),
        vec![
            TemplateEvidenceType::SelectorAccessBreach,
            TemplateEvidenceType::Trace,
            TemplateEvidenceType::StateDiff,
        ],
    )
}

fn erc20_suggestions(
    graph: &AnalysisGraph,
    recognition: &RecognizedStandard,
) -> Vec<SemanticTemplateSuggestion> {
    let transfer_functions = functions_matching_signatures(
        graph,
        &recognition.contract_id,
        &[
            "transfer(address,uint256)",
            "transferFrom(address,address,uint256)",
        ],
    );
    let allowance_functions = functions_matching_signatures(
        graph,
        &recognition.contract_id,
        &[
            "allowance(address,address)",
            "approve(address,uint256)",
            "transferFrom(address,address,uint256)",
        ],
    );
    let core_functions =
        functions_matching_signatures(graph, &recognition.contract_id, ERC20_CORE_SIGNATURES);

    vec![
        base_suggestion(
            recognition,
            "erc20:transfer-accounting-review",
            SemanticTemplateKind::AssetAccounting,
            SuggestionSeverity::High,
            "ERC20 transfer accounting review",
            "Suggested review target: ERC20 transfer surfaces should preserve the reviewed token accounting boundaries.",
            "This is a standard-template review target for ERC20-like transfer behavior. It may need human adjustment for fee-on-transfer, rebasing, mint/burn, paused-token, or blocklist semantics.",
            if transfer_functions.is_empty() {
                &core_functions
            } else {
                &transfer_functions
            },
            Vec::new(),
            vec![
                TemplateEvidenceType::Trace,
                TemplateEvidenceType::StateDiff,
                TemplateEvidenceType::BalanceDelta,
            ],
        ),
        base_suggestion(
            recognition,
            "erc20:allowance-spend-boundary",
            SemanticTemplateKind::AccessControl,
            SuggestionSeverity::High,
            "ERC20 allowance spend boundary",
            "Suggested review target: allowance-based spending should stay within reviewed approval and spender boundaries.",
            "This is a standard-template review target for ERC20 allowance behavior. It is not a claim that all spender, permit, or non-standard token semantics have been proven automatically.",
            if allowance_functions.is_empty() {
                &core_functions
            } else {
                &allowance_functions
            },
            Vec::new(),
            vec![
                TemplateEvidenceType::SelectorAccessBreach,
                TemplateEvidenceType::Trace,
                TemplateEvidenceType::StateDiff,
            ],
        ),
    ]
}

fn erc4626_suggestions(
    graph: &AnalysisGraph,
    recognition: &RecognizedStandard,
) -> Vec<SemanticTemplateSuggestion> {
    let accounting_functions = erc4626_functions(
        graph,
        &recognition.contract_id,
        &[ERC4626_VIEW_SIGNATURES, ERC4626_MUTATION_SIGNATURES].concat(),
    );
    let preview_functions = erc4626_functions(
        graph,
        &recognition.contract_id,
        ERC4626_PREVIEW_MAX_SIGNATURES,
    );
    let mutation_functions =
        erc4626_functions(graph, &recognition.contract_id, ERC4626_MUTATION_SIGNATURES);

    vec![
        base_suggestion(
            recognition,
            "erc4626:asset-share-accounting-review",
            SemanticTemplateKind::AssetAccounting,
            SuggestionSeverity::Critical,
            "ERC4626 asset/share accounting review",
            "Suggested review target: asset and share conversion surfaces should match the reviewed ERC4626 accounting intent.",
            "This is a standard-template review target for ERC4626 vault accounting. It does not prove economic correctness, rounding safety, or inflation resistance automatically.",
            &accounting_functions,
            Vec::new(),
            vec![
                TemplateEvidenceType::Trace,
                TemplateEvidenceType::StateDiff,
                TemplateEvidenceType::BalanceDelta,
            ],
        ),
        base_suggestion(
            recognition,
            "erc4626:preview-execution-consistency",
            SemanticTemplateKind::AssetAccounting,
            SuggestionSeverity::High,
            "ERC4626 preview and execution consistency",
            "Suggested review target: preview and max-limit surfaces should be reviewed against the matching deposit, mint, withdraw, and redeem paths.",
            "This suggestion links recognized ERC4626 preview-style surfaces to execution surfaces. Human review must decide the acceptable rounding and limit policy.",
            if preview_functions.is_empty() {
                &accounting_functions
            } else {
                &preview_functions
            },
            Vec::new(),
            vec![TemplateEvidenceType::Trace, TemplateEvidenceType::StateDiff],
        ),
        base_suggestion(
            recognition,
            "erc4626:solvency-boundary",
            SemanticTemplateKind::Solvency,
            SuggestionSeverity::Critical,
            "ERC4626 solvency boundary review",
            "Suggested review target: withdrawal and redemption paths should be reviewed against the vault asset solvency boundary.",
            "This is a standard-template solvency review target for ERC4626-like vaults. It does not infer yield strategy, oracle, liquidity, or deep protocol economics from static structure.",
            &mutation_functions,
            Vec::new(),
            vec![
                TemplateEvidenceType::Trace,
                TemplateEvidenceType::StateDiff,
                TemplateEvidenceType::BalanceDelta,
                TemplateEvidenceType::MultiTxSequence,
            ],
        ),
    ]
}

fn pausable_suggestions(
    graph: &AnalysisGraph,
    recognition: &RecognizedStandard,
) -> Vec<SemanticTemplateSuggestion> {
    let functions = pausable_user_entrypoints(graph, &recognition.contract_id);
    if functions.is_empty() {
        return Vec::new();
    }

    vec![base_suggestion(
        recognition,
        "openzeppelin-pausable:user-entrypoint-guard",
        SemanticTemplateKind::PauseControl,
        SuggestionSeverity::High,
        "Pausable user entrypoint guard",
        "Suggested review target: recognized user entrypoints should follow the reviewed paused-state behavior.",
        "This is a template-guided pause expectation derived from explicit pause controls or pause guards. It is not an inferred statement about arbitrary protocol economics.",
        &functions,
        special_entrypoints(&functions),
        vec![
            TemplateEvidenceType::Trace,
            TemplateEvidenceType::StateDiff,
            TemplateEvidenceType::ReproductionScript,
        ],
    )]
}

fn upgradeable_suggestions(
    graph: &AnalysisGraph,
    recognition: &RecognizedStandard,
) -> Vec<SemanticTemplateSuggestion> {
    let functions =
        functions_matching_signatures(graph, &recognition.contract_id, UPGRADE_SIGNATURES);
    if functions.is_empty() {
        return Vec::new();
    }

    vec![base_suggestion(
        recognition,
        "upgradeable:upgrade-authority-boundary",
        SemanticTemplateKind::UpgradeControl,
        SuggestionSeverity::Critical,
        "Upgradeable authority boundary",
        "Suggested review target: upgrade entrypoints should remain restricted to the reviewed upgrade authority.",
        "This suggestion is derived from recognized upgrade surfaces and any attached auth signals. It does not prove implementation compatibility, storage-layout safety, or governance safety.",
        &functions,
        Vec::new(),
        vec![
            TemplateEvidenceType::SelectorAccessBreach,
            TemplateEvidenceType::Trace,
            TemplateEvidenceType::StateDiff,
        ],
    )]
}

fn erc4626_functions<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
    signatures: &[&str],
) -> Vec<&'a FunctionFacts> {
    functions_matching_signatures(graph, contract_id, signatures)
}

fn base_suggestion(
    recognition: &RecognizedStandard,
    template_id: &str,
    kind: SemanticTemplateKind,
    severity: SuggestionSeverity,
    title: &str,
    description: &str,
    rationale: &str,
    functions: &[&FunctionFacts],
    special_entrypoints: Vec<analyzer::types::EntrypointKind>,
    evidence_types: Vec<TemplateEvidenceType>,
) -> SemanticTemplateSuggestion {
    let mut provenance = recognition.provenance.clone();
    provenance.push("standards_recognizer.semantic_templates".to_string());
    dedup_sort(&mut provenance);

    SemanticTemplateSuggestion {
        id: suggestion_id(&recognition.contract_id, template_id),
        class: SuggestionClass::SemanticTemplate,
        template_id: template_id.to_string(),
        source_kind: recognition.kind.clone(),
        standard_reference: recognition.standard_reference.clone(),
        kind,
        severity,
        review_status: TemplateReviewStatus::RequiresHumanReview,
        title: title.to_string(),
        description: description.to_string(),
        rationale: rationale.to_string(),
        contract_ids: vec![recognition.contract_id.clone()],
        function_ids: function_ids(functions),
        selectors: selectors(functions),
        special_entrypoints,
        evidence_types,
        provenance,
        confidence: recognition.confidence,
    }
}
