use crate::{
    client::BattlechainClient,
    config::BattlechainOverrides,
    errors::Result,
    status::run_status,
    types::{CheckGroup, CheckStatus, ReadinessCheck},
};
use safeharbor_config::LoadedConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub checks: Vec<ReadinessCheck>,
}

impl DoctorReport {
    pub fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("BattleChain doctor\n");
        for group in [
            CheckGroup::LocalArtifacts,
            CheckGroup::NetworkConfig,
            CheckGroup::AgreementMetadata,
            CheckGroup::Remote,
        ] {
            out.push_str(&format!("{}\n", group));
            for check in self.checks.iter().filter(|check| check.group == group) {
                out.push_str(&format!(
                    "[{}] {} - {}\n",
                    check.status, check.name, check.message
                ));
                if let Some(fix_hint) = &check.fix_hint {
                    out.push_str(&format!("  fix: {fix_hint}\n"));
                }
            }
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
        out.push_str(&format!("summary: {pass} pass, {warn} warn, {fail} fail\n"));
        out
    }
}

pub fn run_doctor(
    loaded: &LoadedConfig,
    overrides: &BattlechainOverrides,
    client: &dyn BattlechainClient,
) -> Result<DoctorReport> {
    let status = run_status(loaded, overrides, client)?;
    Ok(DoctorReport {
        checks: status.checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_groups_checks() {
        let report = DoctorReport {
            checks: vec![ReadinessCheck::warn(
                CheckGroup::Remote,
                "RPC reachable",
                "remote checks skipped",
                "set RPC",
            )],
        };

        let rendered = report.render_text();

        assert!(rendered.contains("remote"));
        assert!(rendered.contains("[WARN] RPC reachable"));
        assert!(rendered.contains("summary: 0 pass, 1 warn, 0 fail"));
    }

    #[test]
    fn renders_healthy_doctor_output() {
        let report = DoctorReport {
            checks: vec![
                ReadinessCheck::pass(CheckGroup::LocalArtifacts, "manifest present", "found"),
                ReadinessCheck::pass(CheckGroup::NetworkConfig, "chain ID valid", "chain 627"),
                ReadinessCheck::pass(
                    CheckGroup::AgreementMetadata,
                    "agreement address present",
                    "agreement set",
                ),
                ReadinessCheck::pass(CheckGroup::Remote, "RPC reachable", "chain 627"),
            ],
        };

        assert_eq!(
            report.render_text(),
            "BattleChain doctor\nlocal_artifacts\n[PASS] manifest present - found\nnetwork_config\n[PASS] chain ID valid - chain 627\nagreement_metadata\n[PASS] agreement address present - agreement set\nremote\n[PASS] RPC reachable - chain 627\nsummary: 4 pass, 0 warn, 0 fail\n"
        );
    }

    #[test]
    fn renders_broken_doctor_output_with_fix() {
        let report = DoctorReport {
            checks: vec![ReadinessCheck::fail(
                CheckGroup::NetworkConfig,
                "manifest chain matches",
                "manifest chain ID 1 does not match resolved chain ID 627",
                "Fix the configured chain.",
            )],
        };

        assert_eq!(
            report.render_text(),
            "BattleChain doctor\nlocal_artifacts\nnetwork_config\n[FAIL] manifest chain matches - manifest chain ID 1 does not match resolved chain ID 627\n  fix: Fix the configured chain.\nagreement_metadata\nremote\nsummary: 0 pass, 0 warn, 1 fail\n"
        );
    }
}
