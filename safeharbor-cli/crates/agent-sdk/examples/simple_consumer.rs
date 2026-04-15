use agent_sdk::{AgentManifest, EvidenceType};
use std::{env, error::Error};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_path = env::args()
        .nth(1)
        .ok_or("usage: simple_consumer <manifest-path>")?;
    let agent = AgentManifest::from_path(manifest_path)?;

    println!("Protocol: {}", agent.manifest().protocol.name);
    println!("Critical invariants:");
    for invariant in agent.critical_invariants() {
        println!("- {}: {}", invariant.id, invariant.description);
    }

    let selector = "0x8456cb59";
    println!(
        "selector {selector} in scope: {}",
        agent.is_selector_in_scope(selector)?
    );

    let invariant_id = "INV-001";
    let evidence = agent
        .evidence_types_for_invariant(invariant_id)?
        .iter()
        .map(render_evidence_type)
        .collect::<Vec<_>>()
        .join(", ");
    println!("Evidence for {invariant_id}: {evidence}");

    Ok(())
}

fn render_evidence_type(evidence_type: &EvidenceType) -> String {
    serde_json::to_value(evidence_type)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| format!("{evidence_type:?}"))
}
