use analyzer::types::AnalysisGraph;
use standards_recognizer::{recognize_standards, types::RecognitionKind};
use std::collections::{BTreeMap, BTreeSet};

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

    let recognized = output
        .recognized_standards
        .iter()
        .map(|recognition| {
            (
                serde_json::to_value(&recognition.kind)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
                serde_json::to_value(&recognition.recognition_type)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let semantic_template_ids = output
        .semantic_template_suggestions
        .iter()
        .map(|suggestion| suggestion.template_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let review_statuses = output
        .semantic_template_suggestions
        .iter()
        .map(|suggestion| {
            serde_json::to_value(&suggestion.review_status)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let actual = serde_json::json!({
        "recognized": recognized,
        "semantic_template_ids": semantic_template_ids,
        "review_statuses": review_statuses,
    });
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/erc4626_expected_semantic_projection.json"
    ))
    .unwrap();

    assert_eq!(actual, expected);
}
