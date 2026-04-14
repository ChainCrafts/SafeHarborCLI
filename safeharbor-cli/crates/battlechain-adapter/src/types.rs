use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf};

pub const PREPARE_SCHEMA_VERSION: &str = "battlechain_prepare/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueSource {
    Cli,
    Config,
    Default,
    Manifest,
    LocalBinding,
    Remote,
}

impl fmt::Display for ValueSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Cli => "cli",
            Self::Config => "config",
            Self::Default => "default",
            Self::Manifest => "manifest",
            Self::LocalBinding => "local",
            Self::Remote => "remote",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleSource {
    Remote,
    Local,
    ConfigUnverified,
}

impl fmt::Display for LifecycleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Remote => "remote",
            Self::Local => "local",
            Self::ConfigUnverified => "config-unverified",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleValue {
    pub state: String,
    pub source: LifecycleSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedNetworkConfig {
    pub network: String,
    pub chain_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_base_url: Option<String>,
    pub network_source: ValueSource,
    pub chain_id_source: ValueSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_url_source: Option<ValueSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_base_url_source: Option<ValueSource>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgreementBinding {
    pub agreement_address: String,
    pub chain_id: u64,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounty_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_window_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LifecycleValue>,
    pub linked_manifest_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckGroup {
    LocalArtifacts,
    NetworkConfig,
    AgreementMetadata,
    Remote,
}

impl fmt::Display for CheckGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::LocalArtifacts => "local_artifacts",
            Self::NetworkConfig => "network_config",
            Self::AgreementMetadata => "agreement_metadata",
            Self::Remote => "remote",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessCheck {
    pub group: CheckGroup,
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<String>,
}

impl ReadinessCheck {
    pub fn pass(group: CheckGroup, name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            group,
            name: name.into(),
            status: CheckStatus::Pass,
            message: message.into(),
            fix_hint: None,
        }
    }

    pub fn warn(
        group: CheckGroup,
        name: impl Into<String>,
        message: impl Into<String>,
        fix_hint: impl Into<String>,
    ) -> Self {
        Self {
            group,
            name: name.into(),
            status: CheckStatus::Warn,
            message: message.into(),
            fix_hint: Some(fix_hint.into()),
        }
    }

    pub fn fail(
        group: CheckGroup,
        name: impl Into<String>,
        message: impl Into<String>,
        fix_hint: impl Into<String>,
    ) -> Self {
        Self {
            group,
            name: name.into(),
            status: CheckStatus::Fail,
            message: message.into(),
            fix_hint: Some(fix_hint.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPresence {
    pub path: PathBuf,
    pub exists: bool,
}
