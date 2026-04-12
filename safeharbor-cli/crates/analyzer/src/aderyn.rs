use crate::{
    project::{FoundryProject, normalize_repo_relative_path, read_version_string},
    types::{DetectorFinding, DetectorLocation, DetectorSeverity},
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::{fs, path::Path, process::Command};

#[derive(Debug, Clone)]
pub struct AderynRun {
    pub version: String,
    pub detector_findings: Vec<DetectorFinding>,
}

#[derive(Debug, Deserialize)]
struct AderynJsonReport {
    #[serde(default)]
    high_issues: IssueBucket,
    #[serde(default)]
    low_issues: IssueBucket,
}

#[derive(Debug, Default, Deserialize)]
struct IssueBucket {
    #[serde(default)]
    issues: Vec<AderynIssueBody>,
}

#[derive(Debug, Deserialize)]
struct AderynIssueBody {
    title: String,
    description: String,
    detector_name: String,
    #[serde(default)]
    instances: Vec<AderynIssueInstance>,
}

#[derive(Debug, Deserialize)]
struct AderynIssueInstance {
    contract_path: String,
    line_no: usize,
    src: String,
    src_char: String,
    hint: Option<String>,
}

pub fn run_aderyn(
    project: &FoundryProject,
    aderyn_bin: &Path,
    output_path: &Path,
) -> Result<AderynRun> {
    let version = read_version_string(aderyn_bin, "--version")?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create output directory for aderyn report: {}",
                parent.display()
            )
        })?;
    }

    let output = Command::new(aderyn_bin)
        .arg(&project.repo_root)
        .arg("-o")
        .arg(output_path)
        .arg("--no-snippets")
        .arg("--skip-update-check")
        .current_dir(&project.repo_root)
        .output()
        .with_context(|| format!("failed to start aderyn via {}", aderyn_bin.display()))?;

    if !output.status.success() {
        bail!(
            "aderyn scan failed for {}:\nstdout:\n{}\nstderr:\n{}",
            project.repo_root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let raw = fs::read_to_string(output_path).with_context(|| {
        format!(
            "failed to read aderyn JSON report from {}",
            output_path.display()
        )
    })?;

    Ok(AderynRun {
        version,
        detector_findings: parse_report_str(&raw)?,
    })
}

pub(crate) fn parse_report_str(raw: &str) -> Result<Vec<DetectorFinding>> {
    let report: AderynJsonReport =
        serde_json::from_str(raw).context("failed to parse aderyn JSON report")?;
    Ok(parse_detector_findings(report))
}

fn parse_detector_findings(report: AderynJsonReport) -> Vec<DetectorFinding> {
    let mut findings = Vec::new();

    findings.extend(report.high_issues.issues.into_iter().map(|issue| {
        DetectorFinding {
            detector_id: issue.detector_name,
            severity: DetectorSeverity::High,
            title: issue.title,
            description: issue.description,
            locations: issue
                .instances
                .into_iter()
                .map(|instance| DetectorLocation {
                    contract_path: normalize_repo_relative_path(Path::new(&instance.contract_path)),
                    line_no: instance.line_no,
                    src: instance.src,
                    src_char: instance.src_char,
                    hint: instance.hint,
                })
                .collect(),
        }
    }));

    findings.extend(report.low_issues.issues.into_iter().map(|issue| {
        DetectorFinding {
            detector_id: issue.detector_name,
            severity: DetectorSeverity::Low,
            title: issue.title,
            description: issue.description,
            locations: issue
                .instances
                .into_iter()
                .map(|instance| DetectorLocation {
                    contract_path: normalize_repo_relative_path(Path::new(&instance.contract_path)),
                    line_no: instance.line_no,
                    src: instance.src,
                    src_char: instance.src_char,
                    hint: instance.hint,
                })
                .collect(),
        }
    }));

    findings.sort_by(|left, right| {
        left.detector_id
            .cmp(&right.detector_id)
            .then(left.title.cmp(&right.title))
            .then(left.description.cmp(&right.description))
    });

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_findings_from_high_and_low_issue_buckets() {
        let report: AderynJsonReport = serde_json::from_str(
            r#"{
  "high_issues": {
    "issues": [
      {
        "title": "Dangerous admin path",
        "description": "upgradeTo is privileged",
        "detector_name": "centralization-risk",
        "instances": [
          {
            "contract_path": "./src/SimpleVault.sol",
            "line_no": 10,
            "src": "1:2:0",
            "src_char": "1:2",
            "hint": "owner-only path"
          }
        ]
      }
    ]
  },
  "low_issues": {
    "issues": [
      {
        "title": "Payable entrypoint",
        "description": "deposit accepts ETH",
        "detector_name": "payable-surface",
        "instances": []
      }
    ]
  }
}"#,
        )
        .unwrap();

        let findings = parse_detector_findings(report);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].detector_id, "centralization-risk");
        assert_eq!(
            findings[0].locations[0].contract_path,
            "src/SimpleVault.sol"
        );
        assert_eq!(findings[1].severity, DetectorSeverity::Low);
    }
}
