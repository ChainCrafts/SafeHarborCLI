use crate::{AgentManifest, AgentSdkError, ManifestIndex, Result};
use manifest::{SafeHarborManifest, validate_manifest};
use std::{fs, path::Path};

impl AgentManifest {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| AgentSdkError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let manifest: SafeHarborManifest =
            serde_json::from_slice(bytes).map_err(AgentSdkError::Parse)?;
        validate_manifest(&manifest).map_err(|err| AgentSdkError::Validation(err.to_string()))?;
        let index = ManifestIndex::build(&manifest)?;

        Ok(Self { manifest, index })
    }
}
