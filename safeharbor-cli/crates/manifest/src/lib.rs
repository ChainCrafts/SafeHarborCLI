use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeHarborManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "manifestRevision")]
    pub manifest_revision: u64,
    #[serde(rename = "manifestStatus")]
    pub manifest_status: String,
    pub protocol: Protocol,
    pub source: Source,
    pub deployment: Deployment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapters: Option<Adapters>,
    pub scope: Scope,
    pub roles: Vec<Role>,
    pub invariants: Vec<Invariant>,
    pub evidence: Evidence,
    pub review: Review,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocol {
    pub name: String,
    pub slug: String,
    pub repository: String,
    #[serde(rename = "repoCommit")]
    pub repo_commit: String,
    #[serde(rename = "buildSystem")]
    pub build_system: String,
    #[serde(rename = "compilerVersion")]
    pub compiler_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub root: String,
    #[serde(rename = "primaryContracts")]
    pub primary_contracts: Vec<String>,
    #[serde(rename = "artifactRefs")]
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub network: String,
    pub contracts: Vec<DeploymentContract>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentContract {
    pub name: String,
    pub address: String,
    #[serde(rename = "abiRef")]
    pub abi_ref: String,
    #[serde(rename = "bytecodeDigestAlgo")]
    pub bytecode_digest_algo: String,
    #[serde(rename = "bytecodeHash")]
    pub bytecode_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battlechain: Option<BattlechainAdapter>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BattlechainAdapter {
    #[serde(rename = "agreementAddress")]
    pub agreement_address: String,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: String,
    #[serde(rename = "bountyPct")]
    pub bounty_pct: f64,
    #[serde(rename = "recoveryAddress")]
    pub recovery_address: String,
    #[serde(rename = "commitmentWindowDays")]
    pub commitment_window_days: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub contracts: Vec<ScopeContract>,
    #[serde(rename = "attackFlow")]
    pub attack_flow: AttackFlow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeContract {
    pub id: String,
    pub name: String,
    pub address: String,
    #[serde(rename = "inScope")]
    pub in_scope: bool,
    #[serde(rename = "outOfScopeReason", skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<ScopeSelector>>,
    #[serde(rename = "specialEntrypoints", skip_serializing_if = "Option::is_none")]
    pub special_entrypoints: Option<Vec<SpecialEntrypoint>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSelector {
    pub selector: String,
    pub signature: String,
    pub payable: bool,
    #[serde(rename = "inScope")]
    pub in_scope: bool,
    pub access: Access,
    #[serde(rename = "outOfScopeReason", skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecialEntrypoint {
    pub entrypoint: SpecialEntrypointKind,
    pub payable: bool,
    #[serde(rename = "inScope")]
    pub in_scope: bool,
    pub access: Access,
    #[serde(rename = "outOfScopeReason", skip_serializing_if = "Option::is_none")]
    pub out_of_scope_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpecialEntrypointKind {
    Receive,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub kind: AccessKind,
    #[serde(rename = "requiredRoleIds", skip_serializing_if = "Option::is_none")]
    pub required_role_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    Permissionless,
    RoleGated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttackFlow {
    #[serde(rename = "allowedModes")]
    pub allowed_modes: Vec<AttackMode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    SingleTx,
    MultiTx,
    MultiBlock,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub holders: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invariant {
    pub id: String,
    pub class: InvariantClass,
    pub kind: InvariantKind,
    pub severity: Severity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contracts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selectors: Option<Vec<String>>,
    #[serde(rename = "specialEntrypoints", skip_serializing_if = "Option::is_none")]
    pub special_entrypoints: Option<Vec<SpecialEntrypointKind>>,
    #[serde(rename = "evidenceTypes")]
    pub evidence_types: Vec<EvidenceType>,
    pub rationale: String,
    pub origin: InvariantOrigin,
    #[serde(
        rename = "derivationConfidence",
        skip_serializing_if = "Option::is_none"
    )]
    pub derivation_confidence: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantClass {
    Structural,
    SemanticTemplate,
    HumanAuthored,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    AccessControl,
    SelectorScope,
    PauseControl,
    UpgradeControl,
    FeeBoundary,
    AssetAccounting,
    Solvency,
    MintBurnIntegrity,
    RoleAssumption,
    ExternalDependency,
    SettlementFlow,
    TimeWindow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceType {
    Trace,
    StateDiff,
    BalanceDelta,
    SelectorAccessBreach,
    MultiTxSequence,
    ReproductionScript,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantOrigin {
    #[serde(rename = "type")]
    pub origin_type: InvariantClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(rename = "detectorId", skip_serializing_if = "Option::is_none")]
    pub detector_id: Option<String>,
    #[serde(rename = "templateId", skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(rename = "standardReference", skip_serializing_if = "Option::is_none")]
    pub standard_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    #[serde(rename = "acceptedTypes")]
    pub accepted_types: Vec<EvidenceType>,
    #[serde(rename = "minimumRequired")]
    pub minimum_required: Vec<EvidenceType>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Review {
    #[serde(rename = "reviewedBy")]
    pub reviewed_by: Vec<String>,
    #[serde(rename = "reviewedAt")]
    pub reviewed_at: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    #[serde(rename = "generatedBy")]
    pub generated_by: String,
    #[serde(rename = "generatedByVersion")]
    pub generated_by_version: String,
    #[serde(rename = "analysisEngines")]
    pub analysis_engines: Vec<AnalysisEngine>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisEngine {
    pub name: String,
    pub role: String,
}

pub fn read_manifest(path: &Path) -> Result<SafeHarborManifest> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest file: {}", path.display()))?;

    let manifest: SafeHarborManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse manifest JSON: {}", path.display()))?;

    Ok(manifest)
}

pub fn write_manifest(path: &Path, manifest: &SafeHarborManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create manifest output directory: {}",
                parent.display()
            )
        })?;
    }

    let json =
        serde_json::to_string_pretty(manifest).context("failed to serialize manifest as JSON")?;

    fs::write(path, format!("{json}\n"))
        .with_context(|| format!("failed to write manifest file: {}", path.display()))?;

    Ok(())
}

pub fn validate_manifest_schema(manifest: &SafeHarborManifest, schema_path: &Path) -> Result<()> {
    let schema_json = read_json_file(schema_path, "schema")?;
    let instance = serde_json::to_value(manifest).context("failed to convert manifest to JSON")?;

    validate_instance(&instance, &schema_json)
}

pub fn validate_file(manifest_path: &Path, schema_path: &Path) -> Result<()> {
    let schema_json = read_json_file(schema_path, "schema")?;
    let instance = read_json_file(manifest_path, "manifest")?;

    validate_instance(&instance, &schema_json)
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read file for digest: {}", path.display()))?;
    sha256_hex(&bytes).with_context(|| format!("failed to digest {}", path.display()))
}

pub fn sha256_hex(bytes: &[u8]) -> Result<String> {
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

fn read_json_file(path: &Path, kind: &str) -> Result<Value> {
    serde_json::from_reader(
        fs::File::open(path)
            .with_context(|| format!("failed to open {kind}: {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {kind} JSON: {}", path.display()))
}

fn validate_instance(instance: &Value, schema_json: &Value) -> Result<()> {
    let validator =
        jsonschema::validator_for(schema_json).context("failed to compile JSON schema")?;
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|e| e.to_string())
        .collect();

    if !errors.is_empty() {
        bail!("manifest schema validation failed:\n{}", errors.join("\n"));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let dir = std::env::temp_dir().join(format!("safeharbor-manifest-test-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn schema_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/safeharbor.manifest.schema.json")
    }

    fn sample_manifest() -> SafeHarborManifest {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/simple-vault/expected.safeharbor.manifest.json"
        )))
        .unwrap()
    }

    #[test]
    fn writes_and_reads_manifest_roundtrip() {
        let dir = unique_temp_dir();
        let path = dir.join("manifest.json");

        let manifest = sample_manifest();
        write_manifest(&path, &manifest).unwrap();
        let loaded = read_manifest(&path).unwrap();

        assert_eq!(loaded, manifest);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn validates_good_manifest_against_schema() {
        let manifest = sample_manifest();
        let schema = schema_path();
        validate_manifest_schema(&manifest, &schema).unwrap();
    }

    #[test]
    fn computes_stable_manifest_file_digest() {
        let digest = sha256_file(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/simple-vault/expected.safeharbor.manifest.json"),
        )
        .unwrap();

        assert_eq!(
            digest,
            "674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb06"
        );
    }

    #[test]
    fn rejects_invalid_manifest_file_against_schema() {
        let dir = unique_temp_dir();
        let manifest_path = dir.join("bad.json");
        let schema = schema_path();

        std::fs::write(
            &manifest_path,
            r#"
{
  "schemaVersion": "1.0.0",
  "protocol": {
    "name": "Broken"
  }
}
"#,
        )
        .unwrap();

        let err = validate_file(&manifest_path, &schema).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("manifest schema validation failed"));

        std::fs::remove_dir_all(dir).unwrap();
    }
}
