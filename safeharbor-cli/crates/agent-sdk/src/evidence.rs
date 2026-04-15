use crate::{AgentManifest, AgentSdkError, EvidenceType, Result};

impl AgentManifest {
    pub fn global_accepted_evidence_types(&self) -> &[EvidenceType] {
        &self.manifest.evidence.accepted_types
    }

    pub fn evidence_types_for_invariant(&self, invariant_id: &str) -> Result<&[EvidenceType]> {
        let invariant_index = self
            .index
            .invariants_by_id
            .get(invariant_id)
            .ok_or_else(|| AgentSdkError::UnknownInvariantId(invariant_id.to_string()))?;

        Ok(&self.manifest.invariants[*invariant_index].evidence_types)
    }
}
