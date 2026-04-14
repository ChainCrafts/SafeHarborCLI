use crate::{
    binding::{build_agreement_binding, validate_agreement_binding},
    config::{BattlechainOverrides, WorkspaceArtifacts, resolve_network_config},
    errors::{BattlechainError, Result},
    types::{
        AgreementBinding, CheckGroup, CheckStatus, PREPARE_SCHEMA_VERSION, ReadinessCheck,
        ResolvedNetworkConfig,
    },
};
use manifest::SafeHarborManifest;
use safeharbor_config::LoadedConfig;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareArtifact {
    pub schema_version: String,
    pub manifest_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub resolved_network: ResolvedNetworkConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agreement_binding: Option<AgreementBinding>,
    pub readiness_checks: Vec<ReadinessCheck>,
    pub next_steps: Vec<String>,
}

impl PrepareArtifact {
    pub fn has_failures(&self) -> bool {
        self.readiness_checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }

    pub fn has_warnings(&self) -> bool {
        self.readiness_checks
            .iter()
            .any(|check| check.status == CheckStatus::Warn)
    }
}

pub fn prepare_battlechain(
    loaded: &LoadedConfig,
    overrides: &BattlechainOverrides,
) -> Result<PrepareArtifact> {
    let artifacts = WorkspaceArtifacts::from_loaded_config(loaded);
    let battlechain_config = loaded.battlechain_config();
    let resolved_network = resolve_network_config(&battlechain_config, overrides)?;

    let manifest_path =
        artifacts
            .manifest_path
            .as_ref()
            .ok_or_else(|| BattlechainError::Artifact {
                path: artifacts.config_path.clone(),
                message: "missing [output].manifest required for battlechain prepare".to_string(),
            })?;
    let manifest = read_manifest_file(manifest_path)?;

    let manifest_hash = sha256_file(manifest_path)
        .ok()
        .map(|digest| format!("sha256:{digest}"));
    let manifest_display_path = artifacts.display_path(manifest_path);
    let binding = build_agreement_binding(
        &manifest,
        &resolved_network,
        &battlechain_config,
        overrides,
        manifest_display_path.clone(),
        manifest_hash.clone(),
    )?;

    let mut checks = artifacts.artifact_checks();
    checks.push(ReadinessCheck::pass(
        CheckGroup::LocalArtifacts,
        "manifest parseable",
        format!("parsed {}", manifest_path.display()),
    ));
    checks.extend(network_checks(&resolved_network));
    checks.extend(deployment_compatibility_checks(
        Some(&manifest),
        &resolved_network,
    ));
    checks.extend(validate_agreement_binding(binding.as_ref()));

    if manifest_hash.is_some() {
        checks.push(ReadinessCheck::pass(
            CheckGroup::LocalArtifacts,
            "manifest hash available",
            "computed local manifest sha256 hash",
        ));
    } else {
        checks.push(ReadinessCheck::warn(
            CheckGroup::LocalArtifacts,
            "manifest hash available",
            "could not compute local manifest sha256 hash",
            "Install sha256sum, shasum, or openssl so prepare can include a stable manifest hash.",
        ));
    }

    let artifact = PrepareArtifact {
        schema_version: PREPARE_SCHEMA_VERSION.to_string(),
        manifest_path: manifest_display_path,
        manifest_hash,
        resolved_network,
        agreement_binding: binding,
        readiness_checks: checks,
        next_steps: next_steps(),
    };

    write_prepare_artifact(&artifacts.prepare_path, &artifact)?;

    Ok(artifact)
}

pub(crate) fn read_manifest_file(path: &Path) -> Result<SafeHarborManifest> {
    let raw = fs::read_to_string(path).map_err(|source| BattlechainError::Read {
        kind: "manifest",
        path: path.to_path_buf(),
        source,
    })?;

    serde_json::from_str(&raw).map_err(|source| BattlechainError::Json {
        kind: "manifest",
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn write_prepare_artifact(path: &Path, artifact: &PrepareArtifact) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| BattlechainError::Write {
            kind: "BattleChain prepare directory",
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let json = serde_json::to_string_pretty(artifact).map_err(|err| {
        BattlechainError::Client(format!("failed to serialize prepare artifact: {err}"))
    })?;
    fs::write(path, format!("{json}\n")).map_err(|source| BattlechainError::Write {
        kind: "BattleChain prepare artifact",
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn network_checks(network: &ResolvedNetworkConfig) -> Vec<ReadinessCheck> {
    let mut checks = vec![
        ReadinessCheck::pass(
            CheckGroup::NetworkConfig,
            "named network valid",
            format!("resolved {}", network.network),
        ),
        ReadinessCheck::pass(
            CheckGroup::NetworkConfig,
            "chain ID valid",
            format!("resolved chain ID {}", network.chain_id),
        ),
    ];

    match network.rpc_url.as_deref() {
        Some(url) if is_http_url(url) => checks.push(ReadinessCheck::pass(
            CheckGroup::NetworkConfig,
            "RPC configured",
            format!("RPC URL configured at {url}"),
        )),
        Some(url) => checks.push(ReadinessCheck::fail(
            CheckGroup::NetworkConfig,
            "RPC URL valid",
            format!("RPC URL is not http(s): {url}"),
            "Set [battlechain].rpc_url to an http(s) JSON-RPC endpoint.",
        )),
        None => checks.push(ReadinessCheck::warn(
            CheckGroup::NetworkConfig,
            "RPC configured",
            "no BattleChain RPC URL configured",
            "Set [battlechain].rpc_url or pass --rpc-url for remote checks.",
        )),
    }

    match network.explorer_base_url.as_deref() {
        Some(url) if is_http_url(url) => checks.push(ReadinessCheck::pass(
            CheckGroup::NetworkConfig,
            "explorer URL well formed",
            format!("explorer URL configured at {url}"),
        )),
        Some(url) => checks.push(ReadinessCheck::warn(
            CheckGroup::NetworkConfig,
            "explorer URL well formed",
            format!("explorer URL is not http(s): {url}"),
            "Set [battlechain].explorer_base_url to an http(s) URL or remove it.",
        )),
        None => checks.push(ReadinessCheck::warn(
            CheckGroup::NetworkConfig,
            "explorer URL well formed",
            "no explorer URL configured",
            "Set [battlechain].explorer_base_url when a BattleChain explorer is available.",
        )),
    }

    checks
}

pub(crate) fn deployment_compatibility_checks(
    manifest: Option<&SafeHarborManifest>,
    network: &ResolvedNetworkConfig,
) -> Vec<ReadinessCheck> {
    let Some(manifest) = manifest else {
        return vec![ReadinessCheck::warn(
            CheckGroup::NetworkConfig,
            "manifest deployment compatible",
            "manifest deployment could not be checked because the manifest is unavailable",
            "Run shcli compile and rerun the BattleChain adapter command.",
        )];
    };

    let mut checks = Vec::new();
    if manifest.deployment.chain_id == 0 || manifest.deployment.network.trim().is_empty() {
        checks.push(ReadinessCheck::warn(
            CheckGroup::NetworkConfig,
            "manifest deployment compatible",
            "manifest deployment information is incomplete",
            "Recompile with deployment.chainId and deployment.network populated.",
        ));
        return checks;
    }

    if manifest.deployment.chain_id != network.chain_id {
        checks.push(ReadinessCheck::fail(
            CheckGroup::NetworkConfig,
            "manifest chain matches",
            format!(
                "manifest chain ID {} does not match resolved chain ID {}",
                manifest.deployment.chain_id, network.chain_id
            ),
            "Use matching [battlechain].chain_id/[battlechain].network values or recompile for the intended deployment.",
        ));
    } else {
        checks.push(ReadinessCheck::pass(
            CheckGroup::NetworkConfig,
            "manifest chain matches",
            format!("manifest chain ID {} matches", network.chain_id),
        ));
    }

    if manifest.deployment.network != network.network {
        checks.push(ReadinessCheck::fail(
            CheckGroup::NetworkConfig,
            "manifest network matches",
            format!(
                "manifest network '{}' does not match resolved network '{}'",
                manifest.deployment.network, network.network
            ),
            "Use matching [battlechain].network or recompile for the intended deployment.",
        ));
    } else {
        checks.push(ReadinessCheck::pass(
            CheckGroup::NetworkConfig,
            "manifest network matches",
            format!("manifest network {} matches", network.network),
        ));
    }

    checks
}

pub(crate) fn is_http_url(value: &str) -> bool {
    let value = value.trim();
    (value.starts_with("https://") || value.starts_with("http://"))
        && !value.contains(char::is_whitespace)
        && value.len() > "http://".len()
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|source| BattlechainError::Read {
        kind: "file for digest",
        path: path.to_path_buf(),
        source,
    })?;

    if let Some(digest) = run_digest_command("sha256sum", &[], &bytes)? {
        return Ok(digest);
    }
    if let Some(digest) = run_digest_command("shasum", &["-a", "256"], &bytes)? {
        return Ok(digest);
    }
    if let Some(digest) = run_digest_command("openssl", &["dgst", "-sha256"], &bytes)? {
        return Ok(digest);
    }

    Err(BattlechainError::Client(
        "failed to compute sha256 digest: no supported digest command found".to_string(),
    ))
}

fn run_digest_command(command: &str, args: &[&str], input: &[u8]) -> Result<Option<String>> {
    let mut child = match Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(BattlechainError::Client(format!(
                "failed to run digest command {command}: {err}"
            )));
        }
    };

    child
        .stdin
        .as_mut()
        .expect("digest child stdin is piped")
        .write_all(input)
        .map_err(|err| BattlechainError::Client(format!("failed to write to {command}: {err}")))?;

    let output = child
        .wait_with_output()
        .map_err(|err| BattlechainError::Client(format!("failed to wait for {command}: {err}")))?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let digest = stdout
        .split_whitespace()
        .find(|token| token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()))
        .unwrap_or("");

    if digest.is_empty() {
        Ok(None)
    } else {
        Ok(Some(digest.to_ascii_lowercase()))
    }
}

fn next_steps() -> Vec<String> {
    vec![
        "Run shcli status for a compact local/remote lifecycle view.".to_string(),
        "Run shcli doctor for grouped readiness diagnostics.".to_string(),
        "Add RPC and agreement metadata before lifecycle actions that require remote reads."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BattlechainOverrides;
    use safeharbor_config::load_config;
    use serde_json::Value;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("safeharbor-battlechain-prepare-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn sample_manifest() -> SafeHarborManifest {
        read_manifest_file(
            &fixture_root().join("examples/simple-vault/expected.safeharbor.manifest.json"),
        )
        .unwrap()
    }

    fn network() -> ResolvedNetworkConfig {
        ResolvedNetworkConfig {
            network: "battlechain-testnet".to_string(),
            chain_id: 627,
            rpc_url: None,
            currency_symbol: None,
            explorer_base_url: None,
            network_source: crate::types::ValueSource::Default,
            chain_id_source: crate::types::ValueSource::Default,
            rpc_url_source: None,
            explorer_base_url_source: None,
        }
    }

    fn write_workspace(root: &Path) {
        fs::create_dir_all(root.join("examples/simple-vault/out")).unwrap();
        fs::create_dir_all(root.join(".safeharbor/review")).unwrap();
        fs::copy(
            fixture_root().join("examples/simple-vault/expected.safeharbor.manifest.json"),
            root.join("examples/simple-vault/out/safeharbor.manifest.json"),
        )
        .unwrap();
        fs::write(
            root.join("examples/simple-vault/out/safeharbor.summary.md"),
            "# Summary\n",
        )
        .unwrap();
        fs::write(
            root.join("examples/simple-vault/safeharbor.input.json"),
            "{}",
        )
        .unwrap();
        fs::write(root.join(".safeharbor/review/reviewed-input.json"), "{}").unwrap();
        fs::write(
            root.join("safeharbor.toml"),
            r#"
[input]
file = "examples/simple-vault/safeharbor.input.json"

[output]
manifest = "examples/simple-vault/out/safeharbor.manifest.json"
summary = "examples/simple-vault/out/safeharbor.summary.md"

[schema]
file = "schemas/safeharbor.manifest.schema.json"

[review]
reviewed_input = ".safeharbor/review/reviewed-input.json"

[battlechain]
network = "battlechain-testnet"
chain_id = 627
"#,
        )
        .unwrap();
    }

    #[test]
    fn writes_prepare_artifact_for_sample_project() {
        let root = unique_temp_dir();
        write_workspace(&root);
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let artifact = prepare_battlechain(&loaded, &BattlechainOverrides::default()).unwrap();
        let value: Value = serde_json::from_str(
            &fs::read_to_string(root.join(".safeharbor/battlechain/prepare.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(artifact.schema_version, PREPARE_SCHEMA_VERSION);
        assert_eq!(value["schemaVersion"], PREPARE_SCHEMA_VERSION);
        assert_eq!(
            value["manifestPath"],
            "examples/simple-vault/out/safeharbor.manifest.json"
        );
        assert_eq!(value["resolvedNetwork"]["network"], "battlechain-testnet");
        assert_eq!(value["resolvedNetwork"]["chainId"], 627);
        assert!(
            value["manifestHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn proven_manifest_chain_mismatch_is_failure() {
        let mut manifest = sample_manifest();
        manifest.deployment.chain_id = 1;

        let checks = deployment_compatibility_checks(Some(&manifest), &network());

        assert!(checks.iter().any(
            |check| check.name == "manifest chain matches" && check.status == CheckStatus::Fail
        ));
    }

    #[test]
    fn incomplete_manifest_deployment_is_warning() {
        let mut manifest = sample_manifest();
        manifest.deployment.network = String::new();

        let checks = deployment_compatibility_checks(Some(&manifest), &network());

        assert_eq!(checks[0].status, CheckStatus::Warn);
    }
}
