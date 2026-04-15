use crate::{AgentManifest, AgentSdkError, Invariant, Result, Severity};

impl AgentManifest {
    pub fn invariants(&self) -> impl Iterator<Item = &Invariant> {
        self.manifest.invariants.iter()
    }

    pub fn critical_invariants(&self) -> impl Iterator<Item = &Invariant> {
        self.invariants()
            .filter(|invariant| invariant.severity == Severity::Critical)
    }

    pub fn high_or_critical_invariants(&self) -> impl Iterator<Item = &Invariant> {
        self.invariants()
            .filter(|invariant| matches!(invariant.severity, Severity::High | Severity::Critical))
    }

    pub fn invariants_for_contract(&self, contract_id: &str) -> Result<Vec<&Invariant>> {
        if !self.index.contracts_by_id.contains_key(contract_id) {
            return Err(AgentSdkError::UnknownContractId(contract_id.to_string()));
        }

        Ok(self
            .invariants()
            .filter(|invariant| {
                invariant
                    .contracts
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|candidate| candidate == contract_id)
            })
            .collect())
    }

    pub fn invariants_for_selector(&self, selector_hex: &str) -> Result<Vec<&Invariant>> {
        let selector = crate::selectors::normalize_selector(selector_hex)?;

        Ok(self
            .invariants()
            .filter(|invariant| {
                invariant
                    .selectors
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&selector))
            })
            .collect())
    }
}
