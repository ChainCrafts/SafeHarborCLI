use crate::project::{FoundryProject, make_repo_relative, normalize_repo_relative_path};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone)]
pub struct ArtifactContract {
    pub artifact_ref: String,
    pub source_path: String,
    pub contract_name: String,
    pub abi: Vec<AbiEntry>,
    pub method_identifiers: BTreeMap<String, String>,
    pub contract_ast: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiParam {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub components: Vec<AbiParam>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AbiEntry {
    #[serde(rename = "type")]
    pub entry_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<AbiParam>,
    #[serde(rename = "stateMutability", default)]
    pub _state_mutability: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArtifactEnvelope {
    abi: Vec<AbiEntry>,
    #[serde(rename = "methodIdentifiers", default)]
    method_identifiers: BTreeMap<String, String>,
    ast: ArtifactAst,
}

#[derive(Debug, Deserialize)]
struct ArtifactAst {
    #[serde(rename = "absolutePath")]
    absolute_path: String,
    nodes: Vec<Value>,
}

pub fn load_artifacts(project: &FoundryProject) -> Result<Vec<ArtifactContract>> {
    let mut contracts = Vec::new();
    let mut artifact_paths = Vec::new();
    collect_json_files(&project.artifact_dir, &mut artifact_paths)?;

    for path in artifact_paths {
        if should_skip_artifact(&project.artifact_dir, &path) {
            continue;
        }

        let Some(contract_name) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read artifact {}", path.display()))?;
        let envelope: ArtifactEnvelope = match serde_json::from_str(&raw) {
            Ok(envelope) => envelope,
            Err(_) => continue,
        };

        if envelope.abi.is_empty() && envelope.ast.nodes.is_empty() {
            continue;
        }

        let Some(contract_ast) = find_contract_node(&envelope.ast.nodes, contract_name) else {
            continue;
        };

        contracts.push(ArtifactContract {
            artifact_ref: make_repo_relative(&project.repo_root, &path),
            source_path: normalize_repo_relative_path(Path::new(&envelope.ast.absolute_path)),
            contract_name: contract_name.to_string(),
            abi: envelope.abi,
            method_identifiers: envelope.method_identifiers,
            contract_ast,
        });
    }

    contracts.sort_by(|left, right| {
        left.source_path
            .cmp(&right.source_path)
            .then(left.contract_name.cmp(&right.contract_name))
            .then(left.artifact_ref.cmp(&right.artifact_ref))
    });

    Ok(contracts)
}

fn should_skip_artifact(artifact_root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(artifact_root).unwrap_or(path);
    let relative = normalize_repo_relative_path(relative);

    relative.starts_with("build-info/")
}

fn collect_json_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read artifact directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_json_files(&path, files)?;
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    Ok(())
}

fn find_contract_node(nodes: &[Value], contract_name: &str) -> Option<Value> {
    nodes
        .iter()
        .find(|node| {
            node.get("nodeType").and_then(Value::as_str) == Some("ContractDefinition")
                && node.get("name").and_then(Value::as_str) == Some(contract_name)
        })
        .cloned()
}

pub fn abi_signature(entry: &AbiEntry) -> Option<String> {
    if entry.entry_type != "function" {
        return None;
    }

    let params = entry
        .inputs
        .iter()
        .map(render_abi_type)
        .collect::<Vec<_>>()
        .join(",");
    Some(format!("{}({params})", entry.name))
}

fn render_abi_type(param: &AbiParam) -> String {
    if !param.type_name.starts_with("tuple") {
        return param.type_name.clone();
    }

    let suffix = param.type_name.trim_start_matches("tuple");
    let inner = param
        .components
        .iter()
        .map(render_abi_type)
        .collect::<Vec<_>>()
        .join(",");

    format!("({inner}){suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::FoundryProject;
    use std::path::PathBuf;

    fn fixture_project() -> FoundryProject {
        let repo_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/foundry-simple-vault");
        FoundryProject {
            repo_root: repo_root.clone(),
            foundry_config_path: repo_root.join("foundry.toml"),
            src_dir: "src".to_string(),
            test_dir: "test".to_string(),
            script_dir: "script".to_string(),
            libs: vec!["lib".to_string()],
            artifact_dir: repo_root.join("out"),
            artifact_dir_relative: "out".to_string(),
        }
    }

    #[test]
    fn renders_tuple_signatures() {
        let entry = AbiEntry {
            entry_type: "function".to_string(),
            name: "configure".to_string(),
            inputs: vec![
                AbiParam {
                    type_name: "tuple".to_string(),
                    components: vec![
                        AbiParam {
                            type_name: "address".to_string(),
                            components: Vec::new(),
                        },
                        AbiParam {
                            type_name: "uint256".to_string(),
                            components: Vec::new(),
                        },
                    ],
                },
                AbiParam {
                    type_name: "tuple[]".to_string(),
                    components: vec![AbiParam {
                        type_name: "bytes32".to_string(),
                        components: Vec::new(),
                    }],
                },
            ],
            _state_mutability: Some("nonpayable".to_string()),
        };

        assert_eq!(
            abi_signature(&entry).as_deref(),
            Some("configure((address,uint256),(bytes32)[])")
        );
    }

    #[test]
    fn loads_fixture_artifact_with_ast_and_methods() {
        let artifacts = load_artifacts(&fixture_project()).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].contract_name, "SimpleVault");
        assert_eq!(artifacts[0].source_path, "src/SimpleVault.sol");
        assert_eq!(
            artifacts[0]
                .method_identifiers
                .get("upgradeTo(address)")
                .map(String::as_str),
            Some("3659cfe6")
        );
    }
}
