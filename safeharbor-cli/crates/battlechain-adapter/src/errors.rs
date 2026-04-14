use std::{io, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BattlechainError {
    #[error("{message}: {path}")]
    Artifact { path: PathBuf, message: String },

    #[error("failed to read {kind}: {path}")]
    Read {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to write {kind}: {path}")]
    Write {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse {kind} JSON: {path}")]
    Json {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Binding(String),

    #[error("{0}")]
    Client(String),
}

pub type Result<T> = std::result::Result<T, BattlechainError>;
