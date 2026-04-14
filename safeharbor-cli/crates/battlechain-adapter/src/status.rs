use crate::{
    binding::{build_agreement_binding, is_address, validate_agreement_binding},
    client::BattlechainClient,
    config::{BattlechainOverrides, WorkspaceArtifacts, resolve_network_config},
    errors::Result,
    prepare::{
        deployment_compatibility_checks, is_http_url, network_checks, read_manifest_file,
        sha256_file,
    },
    types::{
        AgreementBinding, CheckGroup, CheckStatus, LifecycleSource, LifecycleValue, ReadinessCheck,
        ResolvedNetworkConfig,
    },
};
use safeharbor_config::{BattlechainConfig, LoadedConfig};

#[derive(Debug, Clone, PartialEq)]
pub struct StatusReport {
    pub manifest_path: Option<String>,
    pub manifest_present: bool,
    pub protocol_slug: Option<String>,
    pub manifest_revision: Option<u64>,
    pub network: ResolvedNetworkConfig,
    pub agreement_address: Option<String>,
    pub lifecycle_state: Option<LifecycleValue>,
    pub remote_chain_id: Option<u64>,
    pub rpc_state: String,
    pub agreement_readable: Option<bool>,
    pub checks: Vec<ReadinessCheck>,
}

impl StatusReport {
    pub fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("BattleChain status\n");
        match (&self.manifest_path, self.manifest_present) {
            (Some(path), true) => {
                out.push_str(&format!("manifest: present at {path}\n"));
            }
            (Some(path), false) => {
                out.push_str(&format!("manifest: missing at {path}\n"));
            }
            (None, _) => out.push_str("manifest: not configured\n"),
        }
        if let Some(protocol) = &self.protocol_slug {
            out.push_str(&format!("protocol: {protocol}\n"));
        }
        if let Some(revision) = self.manifest_revision {
            out.push_str(&format!("revision: {revision}\n"));
        }
        out.push_str(&format!(
            "network: {} chain {}\n",
            self.network.network, self.network.chain_id
        ));
        out.push_str(&format!("rpc: {}\n", self.rpc_state));
        match self.remote_chain_id {
            Some(chain_id) => out.push_str(&format!("remote chain: {chain_id}\n")),
            None => out.push_str("remote chain: unavailable\n"),
        }
        match &self.agreement_address {
            Some(address) => out.push_str(&format!("agreement: {address}\n")),
            None => out.push_str("agreement: missing\n"),
        }
        match self.agreement_readable {
            Some(true) => out.push_str("agreement readable: yes\n"),
            Some(false) => out.push_str("agreement readable: no\n"),
            None => out.push_str("agreement readable: unavailable\n"),
        }
        match &self.lifecycle_state {
            Some(lifecycle) => out.push_str(&format!(
                "lifecycle: {} ({})\n",
                lifecycle.state, lifecycle.source
            )),
            None => out.push_str("lifecycle: unavailable\n"),
        }
        let pass = self
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Pass)
            .count();
        let warn = self
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Warn)
            .count();
        let fail = self
            .checks
            .iter()
            .filter(|check| check.status == CheckStatus::Fail)
            .count();
        out.push_str(&format!("checks: {pass} pass, {warn} warn, {fail} fail\n"));
        out
    }
}

pub fn run_status(
    loaded: &LoadedConfig,
    overrides: &BattlechainOverrides,
    client: &dyn BattlechainClient,
) -> Result<StatusReport> {
    let artifacts = WorkspaceArtifacts::from_loaded_config(loaded);
    let battlechain_config = loaded.battlechain_config();
    let network = resolve_network_config(&battlechain_config, overrides)?;

    let mut checks = artifacts.artifact_checks();
    checks.extend(network_checks(&network));

    let manifest_path_display = artifacts
        .manifest_path
        .as_ref()
        .map(|path| artifacts.display_path(path));
    let mut manifest_present = false;
    let mut protocol_slug = None;
    let mut manifest_revision = None;
    let mut binding = None;
    let mut local_lifecycle = config_lifecycle_seed(&battlechain_config, overrides);

    if let Some(manifest_path) = artifacts.manifest_path.as_ref() {
        match read_manifest_file(manifest_path) {
            Ok(manifest) => {
                manifest_present = true;
                protocol_slug = Some(manifest.protocol.slug.clone());
                manifest_revision = Some(manifest.manifest_revision);
                checks.push(ReadinessCheck::pass(
                    CheckGroup::LocalArtifacts,
                    "manifest parseable",
                    format!("parsed {}", manifest_path.display()),
                ));
                checks.extend(deployment_compatibility_checks(Some(&manifest), &network));
                let manifest_hash = sha256_file(manifest_path)
                    .ok()
                    .map(|digest| format!("sha256:{digest}"));
                let built_binding = build_agreement_binding(
                    &manifest,
                    &network,
                    &battlechain_config,
                    overrides,
                    artifacts.display_path(manifest_path),
                    manifest_hash,
                )?;
                if let Some(binding) = &built_binding {
                    local_lifecycle = binding.lifecycle_state.clone().or(local_lifecycle);
                }
                checks.extend(validate_agreement_binding(built_binding.as_ref()));
                binding = built_binding;
            }
            Err(err) => checks.push(ReadinessCheck::fail(
                CheckGroup::LocalArtifacts,
                "manifest parseable",
                format!("{err}"),
                "Run shcli compile to regenerate a parseable manifest.",
            )),
        }
    } else {
        checks.extend(deployment_compatibility_checks(None, &network));
        checks.extend(validate_agreement_binding(None));
    }

    let remote = evaluate_remote(&network, binding.as_ref(), client);
    checks.extend(remote.checks.clone());

    let lifecycle_state = remote.lifecycle_state.or(local_lifecycle);

    Ok(StatusReport {
        manifest_path: manifest_path_display,
        manifest_present,
        protocol_slug,
        manifest_revision,
        network,
        agreement_address: binding.map(|binding| binding.agreement_address),
        lifecycle_state,
        remote_chain_id: remote.remote_chain_id,
        rpc_state: remote.rpc_state,
        agreement_readable: remote.agreement_readable,
        checks,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct RemoteEvaluation {
    pub checks: Vec<ReadinessCheck>,
    pub remote_chain_id: Option<u64>,
    pub rpc_state: String,
    pub agreement_readable: Option<bool>,
    pub lifecycle_state: Option<LifecycleValue>,
}

pub(crate) fn evaluate_remote(
    network: &ResolvedNetworkConfig,
    binding: Option<&AgreementBinding>,
    client: &dyn BattlechainClient,
) -> RemoteEvaluation {
    let Some(rpc_url) = network.rpc_url.as_deref() else {
        return RemoteEvaluation {
            checks: vec![ReadinessCheck::warn(
                CheckGroup::Remote,
                "RPC reachable",
                "remote checks skipped because no RPC URL is configured",
                "Set [battlechain].rpc_url or pass --rpc-url.",
            )],
            remote_chain_id: None,
            rpc_state: "not configured".to_string(),
            agreement_readable: None,
            lifecycle_state: None,
        };
    };

    if !is_http_url(rpc_url) {
        return RemoteEvaluation {
            checks: vec![ReadinessCheck::fail(
                CheckGroup::Remote,
                "RPC reachable",
                format!("remote checks skipped because RPC URL is invalid: {rpc_url}"),
                "Set [battlechain].rpc_url to an http(s) JSON-RPC endpoint.",
            )],
            remote_chain_id: None,
            rpc_state: "invalid URL".to_string(),
            agreement_readable: None,
            lifecycle_state: None,
        };
    }

    let mut checks = Vec::new();
    let remote_chain_id = match client.chain_id(rpc_url) {
        Ok(chain_id) => {
            checks.push(ReadinessCheck::pass(
                CheckGroup::Remote,
                "RPC reachable",
                format!("RPC responded with chain ID {chain_id}"),
            ));
            if chain_id == network.chain_id {
                checks.push(ReadinessCheck::pass(
                    CheckGroup::Remote,
                    "correct chain detected",
                    format!("remote chain ID {chain_id} matches"),
                ));
            } else {
                checks.push(ReadinessCheck::fail(
                    CheckGroup::Remote,
                    "correct chain detected",
                    format!(
                        "remote chain ID {chain_id} does not match resolved chain ID {}",
                        network.chain_id
                    ),
                    "Point [battlechain].rpc_url at the configured BattleChain network or fix [battlechain].chain_id.",
                ));
            }
            Some(chain_id)
        }
        Err(err) => {
            checks.push(ReadinessCheck::fail(
                CheckGroup::Remote,
                "RPC reachable",
                format!("{err}"),
                "Check [battlechain].rpc_url and network connectivity.",
            ));
            None
        }
    };

    let Some(binding) = binding else {
        checks.push(ReadinessCheck::warn(
            CheckGroup::Remote,
            "agreement readable",
            "agreement read skipped because no agreement address is bound",
            "Set [battlechain].agreement_address or compile adapters.battlechain metadata.",
        ));
        return RemoteEvaluation {
            checks,
            remote_chain_id,
            rpc_state: if remote_chain_id.is_some() {
                "reachable".to_string()
            } else {
                "unreachable".to_string()
            },
            agreement_readable: None,
            lifecycle_state: None,
        };
    };

    if !is_address(&binding.agreement_address) || remote_chain_id.is_none() {
        checks.push(ReadinessCheck::warn(
            CheckGroup::Remote,
            "agreement readable",
            "agreement read skipped because agreement metadata or RPC is not ready",
            "Fix agreement metadata and RPC checks first.",
        ));
        return RemoteEvaluation {
            checks,
            remote_chain_id,
            rpc_state: if remote_chain_id.is_some() {
                "reachable".to_string()
            } else {
                "unreachable".to_string()
            },
            agreement_readable: None,
            lifecycle_state: None,
        };
    }

    let agreement_readable = match client.agreement_code(rpc_url, &binding.agreement_address) {
        Ok(Some(_code)) => {
            checks.push(ReadinessCheck::pass(
                CheckGroup::Remote,
                "agreement readable",
                "agreement address has contract code",
            ));
            Some(true)
        }
        Ok(None) => {
            checks.push(ReadinessCheck::fail(
                CheckGroup::Remote,
                "agreement readable",
                "agreement address has no contract code",
                "Check the agreement address and configured BattleChain network.",
            ));
            Some(false)
        }
        Err(err) => {
            checks.push(ReadinessCheck::fail(
                CheckGroup::Remote,
                "agreement readable",
                format!("{err}"),
                "Check the agreement address and RPC endpoint.",
            ));
            None
        }
    };

    let lifecycle_state = match client.lifecycle_state(rpc_url, &binding.agreement_address) {
        Ok(Some(state)) => {
            checks.push(ReadinessCheck::pass(
                CheckGroup::Remote,
                "lifecycle readable",
                format!("remote lifecycle state {state}"),
            ));
            Some(LifecycleValue {
                state,
                source: LifecycleSource::Remote,
            })
        }
        Ok(None) => {
            checks.push(ReadinessCheck::warn(
                CheckGroup::Remote,
                "lifecycle readable",
                "remote lifecycle read is not available for this BattleChain ABI in V1",
                "Use local lifecycle as last-known state until the BattleChain lifecycle ABI is configured.",
            ));
            None
        }
        Err(err) => {
            checks.push(ReadinessCheck::fail(
                CheckGroup::Remote,
                "lifecycle readable",
                format!("{err}"),
                "Check the agreement address, RPC endpoint, and BattleChain lifecycle ABI support.",
            ));
            None
        }
    };

    RemoteEvaluation {
        checks,
        remote_chain_id,
        rpc_state: "reachable".to_string(),
        agreement_readable,
        lifecycle_state,
    }
}

fn config_lifecycle_seed(
    battlechain_config: &BattlechainConfig,
    overrides: &BattlechainOverrides,
) -> Option<LifecycleValue> {
    overrides
        .lifecycle_state
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            battlechain_config
                .lifecycle_state
                .as_ref()
                .filter(|value| !value.trim().is_empty())
        })
        .map(|state| LifecycleValue {
            state: state.clone(),
            source: LifecycleSource::ConfigUnverified,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ValueSource;

    struct MockClient {
        chain_id: u64,
        code: Option<String>,
        lifecycle: Option<String>,
    }

    impl BattlechainClient for MockClient {
        fn chain_id(&self, _rpc_url: &str) -> Result<u64> {
            Ok(self.chain_id)
        }

        fn agreement_code(
            &self,
            _rpc_url: &str,
            _agreement_address: &str,
        ) -> Result<Option<String>> {
            Ok(self.code.clone())
        }

        fn lifecycle_state(
            &self,
            _rpc_url: &str,
            _agreement_address: &str,
        ) -> Result<Option<String>> {
            Ok(self.lifecycle.clone())
        }
    }

    struct UnreachableClient;

    impl BattlechainClient for UnreachableClient {
        fn chain_id(&self, _rpc_url: &str) -> Result<u64> {
            Err(crate::errors::BattlechainError::Client(
                "network down".to_string(),
            ))
        }

        fn agreement_code(
            &self,
            _rpc_url: &str,
            _agreement_address: &str,
        ) -> Result<Option<String>> {
            Err(crate::errors::BattlechainError::Client(
                "network down".to_string(),
            ))
        }
    }

    fn network() -> ResolvedNetworkConfig {
        ResolvedNetworkConfig {
            network: "battlechain-testnet".to_string(),
            chain_id: 627,
            rpc_url: Some("http://127.0.0.1:8545".to_string()),
            currency_symbol: None,
            explorer_base_url: None,
            network_source: ValueSource::Default,
            chain_id_source: ValueSource::Default,
            rpc_url_source: Some(ValueSource::Config),
            explorer_base_url_source: None,
        }
    }

    fn binding() -> AgreementBinding {
        AgreementBinding {
            agreement_address: "0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8".to_string(),
            chain_id: 627,
            network: "battlechain-testnet".to_string(),
            recovery_address: None,
            bounty_pct: None,
            commitment_window_days: None,
            lifecycle_state: Some(LifecycleValue {
                state: "LOCAL".to_string(),
                source: LifecycleSource::Local,
            }),
            linked_manifest_path: "manifest.json".to_string(),
            manifest_hash: None,
        }
    }

    #[test]
    fn remote_lifecycle_takes_precedence_when_available() {
        let remote = evaluate_remote(
            &network(),
            Some(&binding()),
            &MockClient {
                chain_id: 627,
                code: Some("0x6000".to_string()),
                lifecycle: Some("REMOTE_READY".to_string()),
            },
        );

        assert_eq!(
            remote.lifecycle_state.unwrap(),
            LifecycleValue {
                state: "REMOTE_READY".to_string(),
                source: LifecycleSource::Remote,
            }
        );
    }

    #[test]
    fn mismatched_remote_chain_is_a_failure() {
        let remote = evaluate_remote(
            &network(),
            Some(&binding()),
            &MockClient {
                chain_id: 1,
                code: Some("0x6000".to_string()),
                lifecycle: None,
            },
        );

        assert!(remote.checks.iter().any(
            |check| check.name == "correct chain detected" && check.status == CheckStatus::Fail
        ));
    }

    #[test]
    fn missing_rpc_is_a_warning() {
        let mut network = network();
        network.rpc_url = None;

        let remote = evaluate_remote(
            &network,
            Some(&binding()),
            &MockClient {
                chain_id: 627,
                code: Some("0x6000".to_string()),
                lifecycle: None,
            },
        );

        assert_eq!(remote.checks[0].status, CheckStatus::Warn);
        assert_eq!(remote.rpc_state, "not configured");
    }

    #[test]
    fn unreachable_rpc_is_a_remote_failure() {
        let remote = evaluate_remote(&network(), Some(&binding()), &UnreachableClient);

        assert!(
            remote
                .checks
                .iter()
                .any(|check| check.name == "RPC reachable" && check.status == CheckStatus::Fail)
        );
        assert_eq!(remote.rpc_state, "unreachable");
    }

    #[test]
    fn renders_lifecycle_aware_status_summary() {
        let report = StatusReport {
            manifest_path: Some("out/safeharbor.manifest.json".to_string()),
            manifest_present: true,
            protocol_slug: Some("simple-vault".to_string()),
            manifest_revision: Some(1),
            network: network(),
            agreement_address: Some("0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8".to_string()),
            lifecycle_state: Some(LifecycleValue {
                state: "REMOTE_READY".to_string(),
                source: LifecycleSource::Remote,
            }),
            remote_chain_id: Some(627),
            rpc_state: "reachable".to_string(),
            agreement_readable: Some(true),
            checks: vec![
                ReadinessCheck::pass(CheckGroup::LocalArtifacts, "manifest present", "found"),
                ReadinessCheck::warn(CheckGroup::Remote, "lifecycle readable", "mock", "fix"),
            ],
        };

        assert_eq!(
            report.render_text(),
            "BattleChain status\nmanifest: present at out/safeharbor.manifest.json\nprotocol: simple-vault\nrevision: 1\nnetwork: battlechain-testnet chain 627\nrpc: reachable\nremote chain: 627\nagreement: 0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8\nagreement readable: yes\nlifecycle: REMOTE_READY (remote)\nchecks: 1 pass, 1 warn, 0 fail\n"
        );
    }
}
