use crate::{
    config::BattlechainOverrides,
    errors::{BattlechainError, Result},
    types::{
        AgreementBinding, CheckGroup, LifecycleSource, LifecycleValue, ReadinessCheck,
        ResolvedNetworkConfig,
    },
};
use manifest::{BattlechainAdapter, SafeHarborManifest};
use safeharbor_config::BattlechainConfig;

pub fn build_agreement_binding(
    manifest: &SafeHarborManifest,
    network: &ResolvedNetworkConfig,
    battlechain_config: &BattlechainConfig,
    overrides: &BattlechainOverrides,
    linked_manifest_path: String,
    manifest_hash: Option<String>,
) -> Result<Option<AgreementBinding>> {
    let manifest_adapter = manifest
        .adapters
        .as_ref()
        .and_then(|adapters| adapters.battlechain.as_ref());

    validate_manifest_metadata_conflicts(manifest_adapter, battlechain_config, overrides)?;

    let agreement_address = manifest_adapter
        .map(|adapter| adapter.agreement_address.clone())
        .or_else(|| {
            first_string(
                overrides.agreement_address.as_ref(),
                battlechain_config.agreement_address.as_ref(),
            )
        });

    let Some(agreement_address) = agreement_address else {
        return Ok(None);
    };

    let recovery_address = manifest_adapter
        .map(|adapter| adapter.recovery_address.clone())
        .or_else(|| {
            first_string(
                overrides.recovery_address.as_ref(),
                battlechain_config.recovery_address.as_ref(),
            )
        });

    let bounty_pct = manifest_adapter
        .map(|adapter| adapter.bounty_pct)
        .or(overrides.bounty_pct)
        .or(battlechain_config.bounty_pct);

    let commitment_window_days = manifest_adapter
        .map(|adapter| adapter.commitment_window_days)
        .or(overrides.commitment_window_days)
        .or(battlechain_config.commitment_window_days);

    let lifecycle_state = if let Some(adapter) = manifest_adapter {
        Some(LifecycleValue {
            state: adapter.lifecycle_state.clone(),
            source: LifecycleSource::Local,
        })
    } else {
        first_string(
            overrides.lifecycle_state.as_ref(),
            battlechain_config.lifecycle_state.as_ref(),
        )
        .map(|state| LifecycleValue {
            state,
            source: LifecycleSource::ConfigUnverified,
        })
    };

    Ok(Some(AgreementBinding {
        agreement_address,
        chain_id: network.chain_id,
        network: network.network.clone(),
        recovery_address,
        bounty_pct,
        commitment_window_days,
        lifecycle_state,
        linked_manifest_path,
        manifest_hash,
    }))
}

pub fn validate_agreement_binding(binding: Option<&AgreementBinding>) -> Vec<ReadinessCheck> {
    let Some(binding) = binding else {
        return vec![
            ReadinessCheck::warn(
                CheckGroup::AgreementMetadata,
                "agreement address present",
                "no BattleChain agreement address is configured",
                "Add adapters.battlechain.agreementAddress to the manifest draft or set [battlechain].agreement_address.",
            ),
            ReadinessCheck::warn(
                CheckGroup::AgreementMetadata,
                "recovery address present",
                "no recovery address can be checked without agreement metadata",
                "Set [battlechain].recovery_address or compile a manifest with adapters.battlechain metadata.",
            ),
            ReadinessCheck::warn(
                CheckGroup::AgreementMetadata,
                "bounty pct present",
                "no bounty percentage can be checked without agreement metadata",
                "Set [battlechain].bounty_pct or compile a manifest with adapters.battlechain metadata.",
            ),
        ];
    };

    let mut checks = Vec::new();
    if is_address(&binding.agreement_address) {
        checks.push(ReadinessCheck::pass(
            CheckGroup::AgreementMetadata,
            "agreement address present",
            format!("agreement address {}", binding.agreement_address),
        ));
    } else {
        checks.push(ReadinessCheck::fail(
            CheckGroup::AgreementMetadata,
            "agreement address valid",
            format!("invalid agreement address {}", binding.agreement_address),
            "Use a 20-byte hex address with 0x prefix.",
        ));
    }

    match binding.recovery_address.as_deref() {
        Some(address) if is_address(address) => checks.push(ReadinessCheck::pass(
            CheckGroup::AgreementMetadata,
            "recovery address present",
            format!("recovery address {address}"),
        )),
        Some(address) => checks.push(ReadinessCheck::fail(
            CheckGroup::AgreementMetadata,
            "recovery address valid",
            format!("invalid recovery address {address}"),
            "Use a 20-byte hex address with 0x prefix.",
        )),
        None => checks.push(ReadinessCheck::warn(
            CheckGroup::AgreementMetadata,
            "recovery address present",
            "no recovery address is bound locally",
            "Set [battlechain].recovery_address or compile a manifest with adapters.battlechain.recoveryAddress.",
        )),
    }

    match binding.bounty_pct {
        Some(value) if (0.0..=100.0).contains(&value) => checks.push(ReadinessCheck::pass(
            CheckGroup::AgreementMetadata,
            "bounty pct present",
            format!("bounty percentage {value}"),
        )),
        Some(value) => checks.push(ReadinessCheck::fail(
            CheckGroup::AgreementMetadata,
            "bounty pct valid",
            format!("bounty percentage {value} is outside 0..=100"),
            "Set a bounty percentage between 0 and 100.",
        )),
        None => checks.push(ReadinessCheck::warn(
            CheckGroup::AgreementMetadata,
            "bounty pct present",
            "no bounty percentage is bound locally",
            "Set [battlechain].bounty_pct or compile a manifest with adapters.battlechain.bountyPct.",
        )),
    }

    if binding.commitment_window_days.is_some() {
        checks.push(ReadinessCheck::pass(
            CheckGroup::AgreementMetadata,
            "commitment window present",
            "commitment window is bound locally",
        ));
    } else {
        checks.push(ReadinessCheck::warn(
            CheckGroup::AgreementMetadata,
            "commitment window present",
            "no commitment window is bound locally",
            "Set [battlechain].commitment_window_days or compile a manifest with adapters.battlechain.commitmentWindowDays.",
        ));
    }

    checks
}

pub fn is_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_manifest_metadata_conflicts(
    manifest_adapter: Option<&BattlechainAdapter>,
    battlechain_config: &BattlechainConfig,
    overrides: &BattlechainOverrides,
) -> Result<()> {
    let Some(adapter) = manifest_adapter else {
        return Ok(());
    };

    check_string_conflict(
        "agreement address",
        &adapter.agreement_address,
        overrides.agreement_address.as_ref(),
        "[battlechain] CLI override",
    )?;
    check_string_conflict(
        "agreement address",
        &adapter.agreement_address,
        battlechain_config.agreement_address.as_ref(),
        "[battlechain].agreement_address",
    )?;
    check_string_conflict(
        "recovery address",
        &adapter.recovery_address,
        overrides.recovery_address.as_ref(),
        "[battlechain] CLI override",
    )?;
    check_string_conflict(
        "recovery address",
        &adapter.recovery_address,
        battlechain_config.recovery_address.as_ref(),
        "[battlechain].recovery_address",
    )?;
    check_f64_conflict(
        "bounty pct",
        adapter.bounty_pct,
        overrides.bounty_pct,
        "[battlechain] CLI override",
    )?;
    check_f64_conflict(
        "bounty pct",
        adapter.bounty_pct,
        battlechain_config.bounty_pct,
        "[battlechain].bounty_pct",
    )?;
    check_u32_conflict(
        "commitment window days",
        adapter.commitment_window_days,
        overrides.commitment_window_days,
        "[battlechain] CLI override",
    )?;
    check_u32_conflict(
        "commitment window days",
        adapter.commitment_window_days,
        battlechain_config.commitment_window_days,
        "[battlechain].commitment_window_days",
    )?;

    Ok(())
}

fn check_string_conflict(
    field: &str,
    manifest_value: &str,
    candidate: Option<&String>,
    source: &str,
) -> Result<()> {
    if let Some(candidate) = candidate {
        if !candidate.trim().is_empty() && candidate != manifest_value {
            return Err(BattlechainError::Binding(format!(
                "manifest BattleChain {field} is {manifest_value}, but {source} supplies {candidate}; do not override compiled manifest adapter metadata"
            )));
        }
    }
    Ok(())
}

fn check_f64_conflict(
    field: &str,
    manifest_value: f64,
    candidate: Option<f64>,
    source: &str,
) -> Result<()> {
    if let Some(candidate) = candidate {
        if (candidate - manifest_value).abs() > f64::EPSILON {
            return Err(BattlechainError::Binding(format!(
                "manifest BattleChain {field} is {manifest_value}, but {source} supplies {candidate}; do not override compiled manifest adapter metadata"
            )));
        }
    }
    Ok(())
}

fn check_u32_conflict(
    field: &str,
    manifest_value: u32,
    candidate: Option<u32>,
    source: &str,
) -> Result<()> {
    if let Some(candidate) = candidate {
        if candidate != manifest_value {
            return Err(BattlechainError::Binding(format!(
                "manifest BattleChain {field} is {manifest_value}, but {source} supplies {candidate}; do not override compiled manifest adapter metadata"
            )));
        }
    }
    Ok(())
}

fn first_string(cli: Option<&String>, config: Option<&String>) -> Option<String> {
    cli.filter(|value| !value.trim().is_empty())
        .or_else(|| config.filter(|value| !value.trim().is_empty()))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use manifest::read_manifest;
    use std::path::PathBuf;

    fn sample_manifest() -> SafeHarborManifest {
        read_manifest(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/simple-vault/expected.safeharbor.manifest.json"),
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

    #[test]
    fn manifest_adapter_wins_over_config_seed() {
        let manifest = sample_manifest();
        let cfg = BattlechainConfig {
            lifecycle_state: Some("CONFIG_ONLY".to_string()),
            ..BattlechainConfig::default()
        };

        let binding = build_agreement_binding(
            &manifest,
            &network(),
            &cfg,
            &BattlechainOverrides::default(),
            "manifest.json".to_string(),
            None,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            binding.lifecycle_state.unwrap(),
            LifecycleValue {
                state: "AGREEMENT_CREATED".to_string(),
                source: LifecycleSource::Local,
            }
        );
        assert_eq!(binding.bounty_pct, Some(10.0));
    }

    #[test]
    fn config_lifecycle_is_unverified_when_manifest_has_no_adapter() {
        let mut manifest = sample_manifest();
        manifest.adapters = None;
        let cfg = BattlechainConfig {
            agreement_address: Some("0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8".to_string()),
            lifecycle_state: Some("CONFIG_SEEDED".to_string()),
            ..BattlechainConfig::default()
        };

        let binding = build_agreement_binding(
            &manifest,
            &network(),
            &cfg,
            &BattlechainOverrides::default(),
            "manifest.json".to_string(),
            None,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            binding.lifecycle_state.unwrap(),
            LifecycleValue {
                state: "CONFIG_SEEDED".to_string(),
                source: LifecycleSource::ConfigUnverified,
            }
        );
    }

    #[test]
    fn rejects_manifest_config_conflict() {
        let manifest = sample_manifest();
        let cfg = BattlechainConfig {
            agreement_address: Some("0x0000000000000000000000000000000000000001".to_string()),
            ..BattlechainConfig::default()
        };

        let err = build_agreement_binding(
            &manifest,
            &network(),
            &cfg,
            &BattlechainOverrides::default(),
            "manifest.json".to_string(),
            None,
        )
        .unwrap_err();

        assert!(err.to_string().contains("do not override"));
    }

    #[test]
    fn classifies_missing_agreement_metadata_as_warnings() {
        let checks = validate_agreement_binding(None);

        assert!(
            checks
                .iter()
                .all(|check| check.status == crate::types::CheckStatus::Warn)
        );
    }
}
