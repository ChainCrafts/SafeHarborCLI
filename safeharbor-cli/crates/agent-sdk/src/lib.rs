mod error;
mod evidence;
mod filters;
mod index;
mod loader;
mod selectors;

pub use error::{AgentSdkError, Result};
pub use manifest::{EvidenceType, Invariant, SafeHarborManifest, Severity};
pub use selectors::SelectorScopeView;

use index::ManifestIndex;

#[derive(Debug, Clone)]
pub struct AgentManifest {
    manifest: SafeHarborManifest,
    index: ManifestIndex,
}

impl AgentManifest {
    pub fn manifest(&self) -> &SafeHarborManifest {
        &self.manifest
    }
}
