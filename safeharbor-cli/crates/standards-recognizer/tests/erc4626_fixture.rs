use analyzer::types::AnalysisGraph;
use standards_recognizer::{recognize_standards, types::RecognitionKind};

#[test]
fn recognizes_erc20_and_erc4626_from_graph_fixture() {
    let graph: AnalysisGraph =
        serde_json::from_str(include_str!("fixtures/erc4626_graph.json")).unwrap();
    let output = recognize_standards(&graph);

    assert!(
        output
            .recognized_standards
            .iter()
            .any(|recognition| recognition.kind == RecognitionKind::Erc20)
    );
    assert!(
        output
            .recognized_standards
            .iter()
            .any(|recognition| recognition.kind == RecognitionKind::Erc4626
                && recognition.confidence == 0.99)
    );
    assert!(
        output
            .semantic_template_suggestions
            .iter()
            .any(|suggestion| {
                suggestion.template_id == "erc4626:asset-share-accounting-review"
            })
    );
}
