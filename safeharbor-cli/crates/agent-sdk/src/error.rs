use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentSdkError {
    #[error("failed to read manifest: {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse manifest JSON")]
    Parse(#[source] serde_json::Error),

    #[error("manifest validation failed: {0}")]
    Validation(String),

    #[error("unknown contract ID: {0}")]
    UnknownContractId(String),

    #[error("unknown invariant ID: {0}")]
    UnknownInvariantId(String),

    #[error("invalid selector {selector}: expected 0x-prefixed 4-byte hex selector")]
    InvalidSelector { selector: String },

    #[error("failed to build manifest index: {0}")]
    IndexBuild(String),
}

pub type Result<T> = std::result::Result<T, AgentSdkError>;
