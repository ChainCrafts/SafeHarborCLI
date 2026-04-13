use crate::{
    types::{DraftCompileInput, ReviewRequest, SourceDigests},
    validation::validate_draft_mappings,
};
use analyzer::{
    AnalysisGraph, PersistedAnalysisGraph,
    types::{DetectorFinding, NormalizedFacts},
};
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use standards_recognizer::types::PersistedStandardsRecognition;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use structural_extractor::PersistedStructuralCandidates;

#[derive(Debug, Clone)]
pub struct ReviewContext {
    pub request: ReviewRequest,
    pub analysis_graph: AnalysisGraph,
    pub structural_candidates: PersistedStructuralCandidates,
    pub standards_recognition: PersistedStandardsRecognition,
    pub draft_input: DraftCompileInput,
    pub source_digests: SourceDigests,
}

pub fn load_review_context(request: ReviewRequest) -> Result<ReviewContext> {
    let analysis_graph: PersistedAnalysisGraph = read_json(&request.analysis_graph_path)?;
    let structural_candidates: PersistedStructuralCandidates =
        read_json(&request.structural_candidates_path)?;
    let standards_recognition: PersistedStandardsRecognition =
        read_json(&request.standards_recognition_path)?;
    let draft_input = load_draft_compile_input(&request.draft_input_path)?;

    let graph = persisted_graph_to_graph(analysis_graph);
    validate_artifact_metadata(
        &structural_candidates,
        &standards_recognition,
        &request.structural_candidates_path,
        &request.standards_recognition_path,
    )?;
    validate_draft_mappings(&draft_input, &graph)?;

    let source_digests = SourceDigests {
        analysis_graph: sha256_file(&request.analysis_graph_path)?,
        structural_candidates: sha256_file(&request.structural_candidates_path)?,
        standards_recognition: sha256_file(&request.standards_recognition_path)?,
        draft_metadata: sha256_file(&request.draft_input_path)?,
    };

    Ok(ReviewContext {
        request,
        analysis_graph: graph,
        structural_candidates,
        standards_recognition,
        draft_input,
        source_digests,
    })
}

pub fn load_draft_compile_input(path: &Path) -> Result<DraftCompileInput> {
    read_json(path)
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read file for digest: {}", path.display()))?;
    sha256_hex(&bytes).with_context(|| format!("failed to digest {}", path.display()))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read JSON file: {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse JSON file: {}", path.display()))
}

fn persisted_graph_to_graph(persisted: PersistedAnalysisGraph) -> AnalysisGraph {
    let NormalizedFacts {
        project,
        contracts,
        functions,
        modifiers,
        inheritance,
    } = persisted.normalized_facts;
    let detector_findings: Vec<DetectorFinding> = persisted.detector_findings;

    AnalysisGraph {
        project,
        contracts,
        functions,
        modifiers,
        inheritance,
        detector_findings,
    }
}

fn validate_artifact_metadata(
    structural: &PersistedStructuralCandidates,
    standards: &PersistedStandardsRecognition,
    structural_path: &PathBuf,
    standards_path: &PathBuf,
) -> Result<()> {
    if structural.metadata.schema_version != "structural_candidates/v1" {
        bail!(
            "unsupported structural candidates schema version in {}: {}",
            structural_path.display(),
            structural.metadata.schema_version
        );
    }
    if standards.metadata.schema_version != "standards_recognition/v1" {
        bail!(
            "unsupported standards recognition schema version in {}: {}",
            standards_path.display(),
            standards.metadata.schema_version
        );
    }
    if structural.metadata.input_digest != standards.metadata.input_digest {
        bail!(
            "scan artifact input digests do not match: structural={}, standards={}",
            structural.metadata.input_digest,
            standards.metadata.input_digest
        );
    }
    Ok(())
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

    bail!("failed to compute sha256 digest: no supported digest command found")
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
        .unwrap_or_default();
    if digest.is_empty() {
        Ok(None)
    } else {
        Ok(Some(digest.to_ascii_lowercase()))
    }
}
