use crate::{
    defaults::{default_network, known_network, known_network_names},
    errors::{BattlechainError, Result},
    types::{CheckGroup, ReadinessCheck, ResolvedNetworkConfig, ValueSource},
};
use safeharbor_config::{BattlechainConfig, LoadedConfig, resolve_relative_to};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BattlechainOverrides {
    pub network: Option<String>,
    pub rpc_url: Option<String>,
    pub chain_id: Option<u64>,
    pub agreement_address: Option<String>,
    pub explorer_base_url: Option<String>,
    pub recovery_address: Option<String>,
    pub bounty_pct: Option<f64>,
    pub commitment_window_days: Option<u32>,
    pub lifecycle_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceArtifacts {
    pub workspace_root: PathBuf,
    pub config_path: PathBuf,
    pub draft_input_path: Option<PathBuf>,
    pub reviewed_input_path: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
    pub summary_path: Option<PathBuf>,
    pub battlechain_dir: PathBuf,
    pub prepare_path: PathBuf,
}

impl WorkspaceArtifacts {
    pub fn from_loaded_config(loaded: &LoadedConfig) -> Self {
        let workspace_root = loaded.workspace_root.clone();
        let draft_input_path = loaded
            .app
            .input
            .as_ref()
            .map(|input| workspace_root.join(&input.file));

        let reviewed_input_path = Some(
            workspace_root.join(
                loaded
                    .app
                    .review
                    .as_ref()
                    .and_then(|review| review.reviewed_input.clone())
                    .unwrap_or_else(default_reviewed_input_path),
            ),
        );

        let manifest_path = loaded
            .app
            .output
            .as_ref()
            .map(|output| workspace_root.join(&output.manifest));

        let summary_path = loaded.app.output.as_ref().map(|output| {
            workspace_root.join(
                output
                    .summary
                    .clone()
                    .unwrap_or_else(|| default_summary_path(&output.manifest)),
            )
        });

        let battlechain_dir = workspace_root.join(".safeharbor/battlechain");
        let prepare_path = battlechain_dir.join("prepare.json");

        Self {
            workspace_root,
            config_path: loaded.config_path.clone(),
            draft_input_path,
            reviewed_input_path,
            manifest_path,
            summary_path,
            battlechain_dir,
            prepare_path,
        }
    }

    pub fn artifact_checks(&self) -> Vec<ReadinessCheck> {
        vec![
            path_presence_check(
                "manifest present",
                self.manifest_path.as_ref(),
                "Add [output].manifest to safeharbor.toml and run shcli compile.",
            ),
            path_presence_check(
                "reviewed input present",
                self.reviewed_input_path.as_ref(),
                "Run shcli review --approve-defaults or complete interactive review.",
            ),
            path_presence_check(
                "draft metadata present",
                self.draft_input_path.as_ref(),
                "Add [input].file to safeharbor.toml and keep the draft metadata file in place.",
            ),
            path_presence_check(
                "summary present",
                self.summary_path.as_ref(),
                "Run shcli compile to emit the manifest summary.",
            ),
        ]
    }

    pub fn display_path(&self, path: &Path) -> String {
        display_path(&self.workspace_root, path)
    }
}

pub fn resolve_network_config(
    battlechain_config: &BattlechainConfig,
    overrides: &BattlechainOverrides,
) -> Result<ResolvedNetworkConfig> {
    let default = default_network();
    let (network_name, network_source) = pick_string(
        overrides.network.as_deref(),
        battlechain_config.network.as_deref(),
        Some(default.name),
    )
    .expect("default network must be present");

    let known = known_network(&network_name).ok_or_else(|| {
        BattlechainError::Config(format!(
            "unknown BattleChain network '{network_name}'; known networks: {}",
            known_network_names().join(", ")
        ))
    })?;

    let (chain_id, chain_id_source) = pick_u64(
        overrides.chain_id,
        battlechain_config.chain_id,
        Some(known.chain_id),
    )
    .expect("default chain ID must be present");

    if chain_id != known.chain_id {
        return Err(BattlechainError::Config(format!(
            "BattleChain network '{}' requires chain ID {}, but {} supplied chain ID {chain_id}",
            known.name, known.chain_id, chain_id_source
        )));
    }

    let (rpc_url, rpc_url_source) = pick_string(
        overrides.rpc_url.as_deref(),
        battlechain_config.rpc_url.as_deref(),
        known.default_rpc_url,
    )
    .map(|(value, source)| (Some(value), Some(source)))
    .unwrap_or((None, None));

    let (explorer_base_url, explorer_base_url_source) = pick_string(
        overrides.explorer_base_url.as_deref(),
        battlechain_config.explorer_base_url.as_deref(),
        known.explorer_base_url,
    )
    .map(|(value, source)| (Some(value), Some(source)))
    .unwrap_or((None, None));

    Ok(ResolvedNetworkConfig {
        network: network_name,
        chain_id,
        rpc_url,
        currency_symbol: known.currency_symbol.map(ToString::to_string),
        explorer_base_url,
        network_source,
        chain_id_source,
        rpc_url_source,
        explorer_base_url_source,
    })
}

pub fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn resolve_path_from_workspace(root: &Path, path: &Path) -> PathBuf {
    resolve_relative_to(root, path)
}

fn path_presence_check(
    name: impl Into<String>,
    path: Option<&PathBuf>,
    fix_hint: impl Into<String>,
) -> ReadinessCheck {
    let name = name.into();
    match path {
        Some(path) if path.is_file() => ReadinessCheck::pass(
            CheckGroup::LocalArtifacts,
            name,
            format!("found {}", path.display()),
        ),
        Some(path) => ReadinessCheck::fail(
            CheckGroup::LocalArtifacts,
            name,
            format!("missing {}", path.display()),
            fix_hint,
        ),
        None => ReadinessCheck::fail(
            CheckGroup::LocalArtifacts,
            name,
            "path is not configured",
            fix_hint,
        ),
    }
}

fn pick_string(
    cli: Option<&str>,
    config: Option<&str>,
    default: Option<&str>,
) -> Option<(String, ValueSource)> {
    if let Some(value) = non_blank(cli) {
        return Some((value.to_string(), ValueSource::Cli));
    }
    if let Some(value) = non_blank(config) {
        return Some((value.to_string(), ValueSource::Config));
    }
    non_blank(default).map(|value| (value.to_string(), ValueSource::Default))
}

fn pick_u64(
    cli: Option<u64>,
    config: Option<u64>,
    default: Option<u64>,
) -> Option<(u64, ValueSource)> {
    if let Some(value) = cli {
        return Some((value, ValueSource::Cli));
    }
    if let Some(value) = config {
        return Some((value, ValueSource::Config));
    }
    default.map(|value| (value, ValueSource::Default))
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn default_reviewed_input_path() -> PathBuf {
    PathBuf::from(".safeharbor/review/reviewed-input.json")
}

fn default_summary_path(manifest: &Path) -> PathBuf {
    manifest.with_file_name("safeharbor.summary.md")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_default_network() {
        let resolved = resolve_network_config(
            &BattlechainConfig::default(),
            &BattlechainOverrides::default(),
        )
        .unwrap();

        assert_eq!(resolved.network, "battlechain-testnet");
        assert_eq!(resolved.chain_id, 627);
        assert_eq!(resolved.rpc_url, None);
        assert_eq!(resolved.currency_symbol, None);
        assert_eq!(resolved.network_source, ValueSource::Default);
    }

    #[test]
    fn cli_overrides_config_for_network_values() {
        let cfg = BattlechainConfig {
            network: Some("battlechain-testnet".to_string()),
            rpc_url: Some("https://config-rpc.example".to_string()),
            chain_id: Some(627),
            ..BattlechainConfig::default()
        };
        let overrides = BattlechainOverrides {
            rpc_url: Some("https://cli-rpc.example".to_string()),
            ..BattlechainOverrides::default()
        };

        let resolved = resolve_network_config(&cfg, &overrides).unwrap();

        assert_eq!(resolved.rpc_url.as_deref(), Some("https://cli-rpc.example"));
        assert_eq!(resolved.rpc_url_source, Some(ValueSource::Cli));
    }

    #[test]
    fn rejects_named_network_chain_id_conflicts() {
        let cfg = BattlechainConfig {
            network: Some("battlechain-testnet".to_string()),
            chain_id: Some(999),
            ..BattlechainConfig::default()
        };

        let err = resolve_network_config(&cfg, &BattlechainOverrides::default()).unwrap_err();

        assert!(err.to_string().contains("requires chain ID 627"));
    }
}
