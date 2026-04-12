mod aderyn;
mod artifacts;
mod cache;
mod normalize;
mod project;
pub mod types;

use anyhow::Result;
use std::io::Write;
use std::process::{Command, Stdio};

pub use cache::{
    cleanup_temporary_outputs, prepare_scan_paths, write_analysis_graph, write_json_pretty,
};
pub use project::{
    FoundryProject, forge_version, make_repo_relative, normalize_repo_relative_path,
};
pub use types::{
    AnalysisGraph, AnalysisRun, PersistedAnalysisGraph, ScanMetadata, ScanMetadataBase, ScanPaths,
    ScanRequest,
};

pub fn run_scan(request: &ScanRequest) -> Result<AnalysisRun> {
    let paths = cache::prepare_scan_paths(&request.output_dir, request.cache)?;
    let project = project::FoundryProject::discover(&request.repo_root, &request.forge_bin)?;
    let forge_version = project::forge_version(&request.forge_bin)?;

    project.build(&request.forge_bin)?;

    let artifacts = artifacts::load_artifacts(&project)?;
    let aderyn_run = aderyn::run_aderyn(&project, &request.aderyn_bin, &paths.aderyn_report_path)?;
    let graph =
        normalize::build_analysis_graph(&project, &artifacts, aderyn_run.detector_findings)?;
    let metadata_base = ScanMetadataBase {
        generated_at: current_rfc3339_timestamp()?,
        tool_version: request.tool_version.clone(),
        repo_root: ".".to_string(),
        input_digest: input_digest(&graph)?,
        aderyn_version: aderyn_run.version,
        forge_version,
    };

    Ok(AnalysisRun {
        graph,
        metadata_base,
        paths,
    })
}

pub fn persisted_analysis_graph(
    graph: &AnalysisGraph,
    metadata: ScanMetadata,
) -> PersistedAnalysisGraph {
    PersistedAnalysisGraph {
        metadata,
        normalized_facts: graph.normalized_facts(),
        detector_findings: graph.detector_findings.clone(),
    }
}

fn input_digest(graph: &AnalysisGraph) -> Result<String> {
    let material = serde_json::to_vec(&(graph.normalized_facts(), &graph.detector_findings))?;
    sha256_hex(&material)
}

fn current_rfc3339_timestamp() -> Result<String> {
    let output = Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn sha256_hex(bytes: &[u8]) -> Result<String> {
    if let Some(digest) = run_digest_command("sha256sum", &[], bytes)? {
        return Ok(digest);
    }
    if let Some(digest) = run_digest_command("shasum", &["-a", "256"], bytes)? {
        return Ok(digest);
    }
    if let Some(digest) = run_digest_command("openssl", &["dgst", "-sha256"], bytes)? {
        return Ok(digest);
    }

    anyhow::bail!("failed to compute sha256 digest: no supported digest command found")
}

fn run_digest_command(command: &str, args: &[&str], input: &[u8]) -> Result<Option<String>> {
    let mut child = match Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input)?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let digest = stdout
        .split_whitespace()
        .find(|token| token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
        .unwrap_or_default()
        .trim();
    if digest.is_empty() {
        Ok(None)
    } else {
        Ok(Some(digest.to_string()))
    }
}
