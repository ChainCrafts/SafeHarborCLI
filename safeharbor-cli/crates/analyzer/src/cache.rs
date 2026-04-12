use crate::types::{PersistedAnalysisGraph, ScanPaths};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn prepare_scan_paths(output_dir: &Path, cache_enabled: bool) -> Result<ScanPaths> {
    fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "failed to create scan output directory: {}",
            output_dir.display()
        )
    })?;

    let cache_dir = output_dir.join("cache");
    if cache_enabled {
        fs::create_dir_all(&cache_dir).with_context(|| {
            format!(
                "failed to create scan cache directory: {}",
                cache_dir.display()
            )
        })?;
    }

    Ok(ScanPaths {
        output_dir: output_dir.to_path_buf(),
        cache_dir: cache_dir.clone(),
        analysis_graph_path: output_dir.join("analysis.graph.json"),
        structural_candidates_path: output_dir.join("structural-candidates.json"),
        aderyn_report_path: if cache_enabled {
            cache_dir.join("aderyn-report.json")
        } else {
            temp_report_path()
        },
    })
}

pub fn write_analysis_graph(path: &Path, graph: &PersistedAnalysisGraph) -> Result<()> {
    write_json_pretty(path, graph)
}

pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory for {}", path.display()))?;
    }

    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("failed to serialize JSON for {}", path.display()))?;
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

pub fn cleanup_temporary_outputs(paths: &ScanPaths, cache_enabled: bool) -> Result<()> {
    if !cache_enabled && paths.aderyn_report_path.exists() {
        fs::remove_file(&paths.aderyn_report_path).with_context(|| {
            format!(
                "failed to remove temporary aderyn report {}",
                paths.aderyn_report_path.display()
            )
        })?;
    }

    Ok(())
}

fn temp_report_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("safeharbor-aderyn-report-{unique}.json"))
}
