use crate::{AgentSdkError, Result};
use manifest::SafeHarborManifest;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectorRef {
    pub contract_index: usize,
    pub selector_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestIndex {
    pub contracts_by_id: HashMap<String, usize>,
    pub contracts_by_address: HashMap<String, usize>,
    pub selectors_by_hex: HashMap<String, Vec<SelectorRef>>,
    pub selectors_by_signature: HashMap<String, Vec<SelectorRef>>,
    pub invariants_by_id: HashMap<String, usize>,
}

impl ManifestIndex {
    pub fn build(manifest: &SafeHarborManifest) -> Result<Self> {
        let mut contracts_by_id = HashMap::new();
        let mut contracts_by_address = HashMap::new();
        let mut selectors_by_hex: HashMap<String, Vec<SelectorRef>> = HashMap::new();
        let mut selectors_by_signature: HashMap<String, Vec<SelectorRef>> = HashMap::new();
        let mut invariants_by_id = HashMap::new();

        for (contract_index, contract) in manifest.scope.contracts.iter().enumerate() {
            if contracts_by_id
                .insert(contract.id.clone(), contract_index)
                .is_some()
            {
                return Err(AgentSdkError::IndexBuild(format!(
                    "duplicate contract ID '{}'",
                    contract.id
                )));
            }

            let address = contract.address.trim();
            if !address.is_empty() {
                let normalized = address.to_ascii_lowercase();
                if contracts_by_address
                    .insert(normalized, contract_index)
                    .is_some()
                {
                    return Err(AgentSdkError::IndexBuild(format!(
                        "duplicate contract address '{}'",
                        contract.address
                    )));
                }
            }

            for (selector_index, selector) in contract
                .selectors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .enumerate()
            {
                let selector_ref = SelectorRef {
                    contract_index,
                    selector_index,
                };
                selectors_by_hex
                    .entry(selector.selector.to_ascii_lowercase())
                    .or_default()
                    .push(selector_ref.clone());
                selectors_by_signature
                    .entry(selector.signature.clone())
                    .or_default()
                    .push(selector_ref);
            }
        }

        for (invariant_index, invariant) in manifest.invariants.iter().enumerate() {
            if invariants_by_id
                .insert(invariant.id.clone(), invariant_index)
                .is_some()
            {
                return Err(AgentSdkError::IndexBuild(format!(
                    "duplicate invariant ID '{}'",
                    invariant.id
                )));
            }
        }

        Ok(Self {
            contracts_by_id,
            contracts_by_address,
            selectors_by_hex,
            selectors_by_signature,
            invariants_by_id,
        })
    }
}
