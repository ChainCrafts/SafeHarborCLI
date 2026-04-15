use agent_sdk::{AgentManifest, AgentSdkError, EvidenceType};
use serde_json::Value;
use std::path::PathBuf;

fn fixture_bytes() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/simple-vault/expected.safeharbor.manifest.json"
    ))
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/simple-vault/expected.safeharbor.manifest.json")
}

fn sample_agent() -> AgentManifest {
    AgentManifest::from_bytes(fixture_bytes()).unwrap()
}

fn ids(invariants: Vec<&agent_sdk::Invariant>) -> Vec<String> {
    invariants
        .into_iter()
        .map(|invariant| invariant.id.clone())
        .collect()
}

fn evidence_names(evidence: &[EvidenceType]) -> Vec<String> {
    evidence
        .iter()
        .map(|evidence_type| {
            serde_json::to_value(evidence_type)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn loads_valid_manifest() {
    let agent = AgentManifest::from_path(fixture_path()).unwrap();

    assert_eq!(agent.manifest().protocol.name, "SimpleVault");
    assert_eq!(agent.manifest().invariants.len(), 3);
}

#[test]
fn rejects_invalid_manifest() {
    let mut value: Value = serde_json::from_slice(fixture_bytes()).unwrap();
    value["manifestStatus"] = Value::String("draft".to_string());
    let bytes = serde_json::to_vec(&value).unwrap();

    let err = AgentManifest::from_bytes(&bytes).unwrap_err();

    assert!(matches!(err, AgentSdkError::Validation(_)));
}

#[test]
fn looks_up_selector_by_hex() {
    let agent = sample_agent();

    let views = agent.selector_scope("0x8456CB59").unwrap();

    assert_eq!(views.len(), 1);
    assert_eq!(views[0].contract_id, "vault_core");
    assert_eq!(views[0].selector, "0x8456cb59");
    assert_eq!(views[0].signature.as_deref(), Some("pause()"));
    assert!(views[0].in_scope);
    assert_eq!(views[0].role_requirements, vec!["owner"]);
}

#[test]
fn looks_up_selector_by_signature() {
    let agent = sample_agent();

    let views = agent.selectors_by_signature("withdrawFees(uint256)");

    assert_eq!(views.len(), 1);
    assert_eq!(views[0].selector, "0x5e318e07");
    assert_eq!(views[0].role_requirements, vec!["owner"]);
}

#[test]
fn filters_critical_invariants() {
    let agent = sample_agent();
    let critical = agent
        .critical_invariants()
        .map(|invariant| invariant.id.clone())
        .collect::<Vec<_>>();

    assert_eq!(critical, vec!["INV-001", "INV-003"]);
}

#[test]
fn filters_high_or_critical_invariants() {
    let agent = sample_agent();
    let high_or_critical = agent
        .high_or_critical_invariants()
        .map(|invariant| invariant.id.clone())
        .collect::<Vec<_>>();

    assert_eq!(high_or_critical, vec!["INV-001", "INV-002", "INV-003"]);
}

#[test]
fn filters_contract_scoped_invariants() {
    let agent = sample_agent();

    assert_eq!(
        ids(agent.invariants_for_contract("vault_core").unwrap()),
        vec!["INV-001", "INV-002", "INV-003"]
    );
}

#[test]
fn lists_selectors_for_contract() {
    let agent = sample_agent();

    let views = agent.selectors_for_contract("vault_core").unwrap();

    assert_eq!(views.len(), 6);
    assert_eq!(views[0].signature.as_deref(), Some("deposit(uint256)"));
    assert_eq!(
        views[5].signature.as_deref(),
        Some("rescueToken(address,uint256)")
    );
    assert!(!views[5].in_scope);
}

#[test]
fn filters_selector_scoped_invariants_without_contract_inference() {
    let agent = sample_agent();

    assert_eq!(
        ids(agent.invariants_for_selector("0x5E318E07").unwrap()),
        vec!["INV-001", "INV-003"]
    );
    assert!(
        agent
            .invariants_for_selector("0x023b1fc9")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn filters_role_gated_selectors() {
    let agent = sample_agent();

    let views = agent.selectors_requiring_role("owner");
    let selectors = views
        .iter()
        .map(|view| (view.selector.as_str(), view.in_scope))
        .collect::<Vec<_>>();

    assert_eq!(
        selectors,
        vec![
            ("0x8456cb59", true),
            ("0x023b1fc9", true),
            ("0x5e318e07", true),
            ("0x33f3d628", false),
        ]
    );
}

#[test]
fn looks_up_role_requirements_for_selector() {
    let agent = sample_agent();

    assert_eq!(
        agent.role_requirements_for_selector("0x5e318e07").unwrap(),
        vec!["owner"]
    );
    assert!(
        agent
            .role_requirements_for_selector("0xb6b55f25")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn looks_up_evidence() {
    let agent = sample_agent();

    assert_eq!(
        evidence_names(agent.global_accepted_evidence_types()),
        vec![
            "trace",
            "state-diff",
            "balance-delta",
            "selector-access-breach",
            "reproduction-script",
        ]
    );
    assert_eq!(
        evidence_names(agent.evidence_types_for_invariant("INV-001").unwrap()),
        vec!["selector-access-breach", "trace", "state-diff"]
    );
}

#[test]
fn reports_unknown_contract_and_invariant_errors() {
    let agent = sample_agent();

    let contract_err = agent.invariants_for_contract("missing").unwrap_err();
    assert!(matches!(
        contract_err,
        AgentSdkError::UnknownContractId(contract_id) if contract_id == "missing"
    ));

    let invariant_err = agent.evidence_types_for_invariant("INV-999").unwrap_err();
    assert!(matches!(
        invariant_err,
        AgentSdkError::UnknownInvariantId(invariant_id) if invariant_id == "INV-999"
    ));
}

#[test]
fn selector_syntax_errors_are_distinct_from_unknown_selectors() {
    let agent = sample_agent();

    let invalid = agent.selector_scope("8456cb59").unwrap_err();
    assert!(matches!(invalid, AgentSdkError::InvalidSelector { .. }));

    assert!(agent.selector_scope("0xffffffff").unwrap().is_empty());
    assert!(!agent.is_selector_in_scope("0xffffffff").unwrap());
    assert!(
        agent
            .role_requirements_for_selector("0xffffffff")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn golden_selector_scope_decisions() {
    let agent = sample_agent();

    assert!(agent.is_selector_in_scope("0xb6b55f25").unwrap());
    assert!(agent.is_selector_in_scope("0x8456cb59").unwrap());
    assert!(!agent.is_selector_in_scope("0x33f3d628").unwrap());
}

#[test]
fn golden_evidence_expectations() {
    let agent = sample_agent();

    assert_eq!(
        evidence_names(agent.evidence_types_for_invariant("INV-003").unwrap()),
        vec![
            "trace",
            "state-diff",
            "balance-delta",
            "reproduction-script",
        ]
    );
}
