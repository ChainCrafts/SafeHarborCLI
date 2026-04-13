pub mod loader;
pub mod persistence;
pub mod projection;
pub mod prompts;
pub mod session;
pub mod taxonomy;
pub mod types;
pub mod validation;
pub mod view;

pub use loader::{ReviewContext, load_draft_compile_input, load_review_context, sha256_file};
pub use projection::{project_reviewed_input, reviewed_input_to_manifest_scope};
pub use prompts::{ApproveDefaultsPrompter, ReviewPrompter, TerminalReviewPrompter};
pub use session::run_review;
pub use types::{
    AnalysisContractMapping, DraftCompileInput, ReviewDecision, ReviewRequest, ReviewState,
    ReviewedInput, SourceDigests,
};
pub use validation::{
    validate_draft_mappings, validate_review_state, validate_reviewed_input_for_compile,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        persistence::load_review_state,
        prompts::ReviewSummary,
        types::{ReviewAction, ReviewEdits, ReviewItemKind},
        view::ReviewItemView,
    };
    use analyzer::AnalysisGraph;
    use anyhow::Result;
    use manifest::{AccessKind, EvidenceType, Severity};
    use std::{
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("safeharbor-review-engine-test-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn foundry_fixture() -> PathBuf {
        fixture_root().join("examples/foundry-simple-vault/testdata")
    }

    fn simple_vault_input() -> PathBuf {
        fixture_root().join("examples/simple-vault/safeharbor.input.json")
    }

    fn write_draft_input(path: &Path) {
        let mut draft: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(simple_vault_input()).unwrap()).unwrap();
        draft["analysis_contract_mappings"] = serde_json::json!([
            {
                "manifest_contract_id": "vault_core",
                "source_analysis_contract_id": "src/SimpleVault.sol:SimpleVault"
            }
        ]);
        std::fs::write(path, serde_json::to_string_pretty(&draft).unwrap()).unwrap();
    }

    fn review_request(root: &Path) -> ReviewRequest {
        let draft_path = root.join("safeharbor.input.json");
        write_draft_input(&draft_path);
        ReviewRequest {
            analysis_graph_path: foundry_fixture().join("expected.analysis.graph.json"),
            structural_candidates_path: foundry_fixture()
                .join("expected.structural-candidates.json"),
            standards_recognition_path: foundry_fixture()
                .join("expected.standards-recognition.json"),
            draft_input_path: draft_path,
            state_path: root.join("review-state.json"),
            reviewed_input_path: root.join("reviewed-input.json"),
            low_confidence_threshold: 75,
        }
    }

    #[test]
    fn explicit_mappings_allow_repeated_source_and_reject_duplicate_manifest_id() {
        let graph: AnalysisGraph = serde_json::from_str(
            &std::fs::read_to_string(foundry_fixture().join("expected.analysis.graph.json"))
                .unwrap(),
        )
        .map(
            |persisted: analyzer::PersistedAnalysisGraph| AnalysisGraph {
                project: persisted.normalized_facts.project,
                contracts: persisted.normalized_facts.contracts,
                functions: persisted.normalized_facts.functions,
                modifiers: persisted.normalized_facts.modifiers,
                inheritance: persisted.normalized_facts.inheritance,
                detector_findings: persisted.detector_findings,
            },
        )
        .unwrap();

        let mut draft: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(simple_vault_input()).unwrap()).unwrap();
        let mut clone = draft["manifest"]["scope"]["contracts"][0].clone();
        clone["id"] = serde_json::Value::String("vault_clone".to_string());
        draft["manifest"]["scope"]["contracts"]
            .as_array_mut()
            .unwrap()
            .push(clone);
        draft["analysis_contract_mappings"] = serde_json::json!([
            {
                "manifest_contract_id": "vault_core",
                "source_analysis_contract_id": "src/SimpleVault.sol:SimpleVault"
            },
            {
                "manifest_contract_id": "vault_clone",
                "source_analysis_contract_id": "src/SimpleVault.sol:SimpleVault"
            }
        ]);
        let draft: DraftCompileInput = serde_json::from_value(draft).unwrap();
        validate_draft_mappings(&draft, &graph).unwrap();

        let mut duplicate = draft.clone();
        duplicate.analysis_contract_mappings[1].manifest_contract_id = "vault_core".to_string();
        let err = validate_draft_mappings(&duplicate, &graph).unwrap_err();
        assert!(err.to_string().contains("duplicate manifest contract id"));
    }

    #[test]
    fn approve_defaults_preserves_source_and_reviewed_access_classifications() {
        let root = unique_temp_dir();
        let request = review_request(&root);
        let mut prompter = ApproveDefaultsPrompter::new();
        let reviewed = run_review(request, &mut prompter).unwrap();

        let selector = reviewed.reviewed_scope.contracts[0]
            .selectors
            .iter()
            .find(|selector| selector.signature == "pause()")
            .unwrap();
        assert_eq!(
            selector.source_access_classification.kind,
            AccessKind::RoleGated
        );
        assert_eq!(
            selector.reviewed_access_classification.kind,
            AccessKind::RoleGated
        );
        assert_eq!(
            selector
                .reviewed_access_classification
                .required_role_ids
                .as_ref()
                .unwrap(),
            &vec!["owner".to_string()]
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[derive(Default)]
    struct RejectOneSemanticPrompter {
        rejected_id: Option<String>,
    }

    impl ReviewPrompter for RejectOneSemanticPrompter {
        fn should_discard_stale_state(&mut self) -> Result<bool> {
            Ok(true)
        }

        fn review_item(&mut self, item: &ReviewItemView) -> Result<ReviewDecision> {
            if item.item_kind == ReviewItemKind::SemanticTemplate && self.rejected_id.is_none() {
                self.rejected_id = Some(item.item_id.clone());
                return Ok(ReviewDecision {
                    item_id: item.item_id.clone(),
                    item_kind: item.item_kind.clone(),
                    action: ReviewAction::Rejected,
                    edits: None,
                    reviewer_note: None,
                    rejection_reason: Some("not applicable to this deployment".to_string()),
                });
            }
            Ok(ReviewDecision {
                item_id: item.item_id.clone(),
                item_kind: item.item_kind.clone(),
                action: ReviewAction::Approved,
                edits: None,
                reviewer_note: None,
                rejection_reason: None,
            })
        }

        fn confirm_final(&mut self, summary: &ReviewSummary) -> Result<bool> {
            Ok(summary.unresolved_count == 0)
        }
    }

    #[test]
    fn rejected_semantic_template_reason_stays_in_state_and_is_omitted_from_reviewed_input() {
        let root = unique_temp_dir();
        let request = review_request(&root);
        let state_path = request.state_path.clone();
        let mut prompter = RejectOneSemanticPrompter::default();
        let reviewed = run_review(request, &mut prompter).unwrap();
        let rejected_id = prompter.rejected_id.unwrap();
        let rejected_source_id = rejected_id.trim_start_matches("semantic:").to_string();

        let state = load_review_state(&state_path).unwrap().unwrap();
        let rejected = state
            .decisions
            .iter()
            .find(|decision| decision.item_id == rejected_id)
            .unwrap();
        assert_eq!(
            rejected.rejection_reason.as_deref(),
            Some("not applicable to this deployment")
        );
        assert!(
            !reviewed
                .reviewed_semantic_templates
                .iter()
                .any(|template| template.source_item_id == rejected_source_id)
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[derive(Default)]
    struct EditOneStructuralPrompter {
        edited_source_id: Option<String>,
    }

    impl ReviewPrompter for EditOneStructuralPrompter {
        fn should_discard_stale_state(&mut self) -> Result<bool> {
            Ok(true)
        }

        fn review_item(&mut self, item: &ReviewItemView) -> Result<ReviewDecision> {
            if item.item_kind == ReviewItemKind::StructuralInvariant
                && self.edited_source_id.is_none()
            {
                self.edited_source_id =
                    Some(item.item_id.trim_start_matches("structural:").to_string());
                return Ok(ReviewDecision {
                    item_id: item.item_id.clone(),
                    item_kind: item.item_kind.clone(),
                    action: ReviewAction::Edited,
                    edits: Some(ReviewEdits {
                        severity: Some(Severity::Low),
                        evidence_types: vec![EvidenceType::Trace],
                        ..ReviewEdits::default()
                    }),
                    reviewer_note: Some("downgraded during review".to_string()),
                    rejection_reason: None,
                });
            }
            Ok(ReviewDecision {
                item_id: item.item_id.clone(),
                item_kind: item.item_kind.clone(),
                action: ReviewAction::Approved,
                edits: None,
                reviewer_note: None,
                rejection_reason: None,
            })
        }

        fn confirm_final(&mut self, summary: &ReviewSummary) -> Result<bool> {
            Ok(summary.unresolved_count == 0)
        }
    }

    #[test]
    fn edited_structural_severity_and_evidence_propagate_to_reviewed_input() {
        let root = unique_temp_dir();
        let request = review_request(&root);
        let mut prompter = EditOneStructuralPrompter::default();
        let reviewed = run_review(request, &mut prompter).unwrap();
        let edited_source_id = prompter.edited_source_id.unwrap();
        let invariant = reviewed
            .reviewed_structural_invariants
            .iter()
            .find(|invariant| invariant.source_item_id == edited_source_id)
            .unwrap();

        assert_eq!(invariant.reviewed_severity, Severity::Low);
        assert_eq!(invariant.reviewed_evidence_types, vec![EvidenceType::Trace]);
        assert_eq!(
            invariant.reviewer_note.as_deref(),
            Some("downgraded during review")
        );

        std::fs::remove_dir_all(root).unwrap();
    }
}
