use crate::{
    types::{ReviewState, ReviewedInput},
    validation::validate_review_state,
};
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

pub fn load_review_state(path: &Path) -> Result<Option<ReviewState>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read review state: {}", path.display()))?;
    let state: ReviewState = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse review state: {}", path.display()))?;
    validate_review_state(&state)?;
    Ok(Some(state))
}

pub fn save_review_state(path: &Path, state: &ReviewState) -> Result<()> {
    write_json(path, state)
}

pub fn save_reviewed_input(path: &Path, reviewed: &ReviewedInput) -> Result<()> {
    write_json(path, reviewed)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create parent directory for {}", parent.display())
        })?;
    }
    let json = serde_json::to_string_pretty(value)
        .with_context(|| format!("failed to serialize JSON for {}", path.display()))?;
    std::fs::write(path, format!("{json}\n"))
        .with_context(|| format!("failed to write JSON: {}", path.display()))
}
