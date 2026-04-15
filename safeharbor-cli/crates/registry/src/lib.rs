use battlechain_adapter::{
    BattlechainOverrides, config::resolve_network_config, errors::BattlechainError,
    types::ResolvedNetworkConfig,
};
use manifest::{SafeHarborManifest, read_manifest, sha256_file};
use safeharbor_config::LoadedConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, RegistryError>;

const PUBLISH_SIGNATURE: &str = "publish(address,bytes32,string)";
const CURRENT_PUBLICATION_SIGNATURE: &str = "currentPublication(address)";
pub const REGISTRY_PUBLISH_SCHEMA_VERSION: &str = "registry_publish/v1";

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("missing [output].manifest required for registry publish: {config_path}")]
    MissingManifestPath { config_path: PathBuf },

    #[error("manifest file not found: {path}")]
    MissingManifestFile { path: PathBuf },

    #[error("failed to load compiled manifest {path}: {message}")]
    ManifestLoad { path: PathBuf, message: String },

    #[error("failed to compute manifest digest for {path}: {message}")]
    Digest { path: PathBuf, message: String },

    #[error("missing manifest URI: pass --manifest-uri <URI>")]
    MissingManifestUri,

    #[error(
        "missing agreement address: adapters.battlechain.agreementAddress is absent and no --agreement-address or [battlechain].agreement_address was provided"
    )]
    MissingAgreementAddress,

    #[error("missing registry address: pass --registry-address or set [registry].address")]
    MissingRegistryAddress,

    #[error("invalid {kind} address {value}: use a 20-byte hex address with 0x prefix")]
    InvalidAddress { kind: &'static str, value: String },

    #[error(
        "manifest BattleChain agreement address is {manifest}, but {source_name} supplies {candidate}; do not override compiled manifest adapter metadata"
    )]
    AgreementConflict {
        manifest: String,
        source_name: &'static str,
        candidate: String,
    },

    #[error(
        "manifest chain ID {manifest_chain_id} does not match resolved chain ID {resolved_chain_id}"
    )]
    ManifestChainMismatch {
        manifest_chain_id: u64,
        resolved_chain_id: u64,
    },

    #[error(
        "manifest network '{manifest_network}' does not match resolved network '{resolved_network}'"
    )]
    ManifestNetworkMismatch {
        manifest_network: String,
        resolved_network: String,
    },

    #[error(
        "remote chain ID {remote_chain_id} does not match resolved chain ID {resolved_chain_id}"
    )]
    RemoteChainMismatch {
        remote_chain_id: u64,
        resolved_chain_id: u64,
    },

    #[error("registry RPC URL is not http(s): {0}")]
    InvalidRpcUrl(String),

    #[error("failed to create {kind} directory {path}: {source}")]
    CreateDir {
        kind: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write {kind} {path}: {source}")]
    Write {
        kind: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{0}")]
    Abi(String),

    #[error("{0}")]
    Rpc(String),

    #[error(transparent)]
    Battlechain(#[from] BattlechainError),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryOverrides {
    pub network: Option<String>,
    pub rpc_url: Option<String>,
    pub chain_id: Option<u64>,
    pub agreement_address: Option<String>,
    pub registry_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedPublish {
    pub manifest_path: PathBuf,
    pub manifest_display_path: String,
    pub registry_address: String,
    pub agreement_address: String,
    pub manifest_hash: [u8; 32],
    pub manifest_hash_hex: String,
    pub manifest_digest: String,
    pub manifest_uri: String,
    pub calldata: String,
    pub readback_calldata: String,
    pub network: ResolvedNetworkConfig,
    pub remote_chain_id: Option<u64>,
    pub readback: Option<ReadbackReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryPublishArtifact {
    pub schema_version: String,
    pub manifest_path: String,
    pub manifest_digest: String,
    pub manifest_hash: String,
    pub manifest_uri: String,
    pub agreement_address: String,
    pub registry_address: String,
    pub network: ResolvedNetworkConfig,
    pub publish_calldata: String,
    pub readback_calldata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_chain_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readback: Option<RegistryReadbackArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryReadbackArtifact {
    pub status: ReadbackStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<PublicationArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationArtifact {
    pub agreement: String,
    pub manifest_hash: String,
    pub manifest_uri: String,
    pub publisher: String,
    pub published_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRecord {
    pub agreement: String,
    pub manifest_hash: [u8; 32],
    pub manifest_hash_hex: String,
    pub manifest_uri: String,
    pub publisher: String,
    pub published_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadbackStatus {
    NoPublication,
    Match,
    HashMismatch,
    UriMismatch,
    HashAndUriMismatch,
}

impl fmt::Display for ReadbackStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPublication => f.write_str("no publication"),
            Self::Match => f.write_str("match"),
            Self::HashMismatch => f.write_str("hash mismatch"),
            Self::UriMismatch => f.write_str("manifest URI mismatch"),
            Self::HashAndUriMismatch => f.write_str("hash and manifest URI mismatch"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadbackReport {
    pub status: ReadbackStatus,
    pub current: Option<PublicationRecord>,
}

pub trait RegistryRpcClient {
    fn chain_id(&self, rpc_url: &str) -> Result<u64>;
    fn eth_call(&self, rpc_url: &str, to: &str, data: &str) -> Result<String>;
}

pub struct HttpRegistryRpcClient {
    client: reqwest::blocking::Client,
}

impl HttpRegistryRpcClient {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|err| RegistryError::Rpc(format!("failed to initialize RPC client: {err}")))?;

        Ok(Self { client })
    }

    fn rpc_call(&self, rpc_url: &str, method: &str, params: Value) -> Result<Value> {
        let response = self
            .client
            .post(rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .map_err(|err| RegistryError::Rpc(format!("RPC request failed: {err}")))?;

        if !response.status().is_success() {
            return Err(RegistryError::Rpc(format!(
                "RPC request failed with HTTP status {}",
                response.status()
            )));
        }

        let body: RpcResponse = response
            .json()
            .map_err(|err| RegistryError::Rpc(format!("failed to parse RPC response: {err}")))?;

        if let Some(error) = body.error {
            return Err(RegistryError::Rpc(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        body.result
            .ok_or_else(|| RegistryError::Rpc("RPC response did not include result".to_string()))
    }
}

impl RegistryRpcClient for HttpRegistryRpcClient {
    fn chain_id(&self, rpc_url: &str) -> Result<u64> {
        let result = self.rpc_call(rpc_url, "eth_chainId", json!([]))?;
        let hex = result.as_str().ok_or_else(|| {
            RegistryError::Rpc("eth_chainId result was not a hex string".to_string())
        })?;

        parse_hex_u64(hex)
    }

    fn eth_call(&self, rpc_url: &str, to: &str, data: &str) -> Result<String> {
        let result = self.rpc_call(
            rpc_url,
            "eth_call",
            json!([{"to": to, "data": data}, "latest"]),
        )?;
        let raw = result.as_str().ok_or_else(|| {
            RegistryError::Rpc("eth_call result was not a hex string".to_string())
        })?;

        Ok(raw.to_string())
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

pub fn prepare_registry_publish(
    loaded: &LoadedConfig,
    manifest_uri: &str,
    overrides: &RegistryOverrides,
    client: &dyn RegistryRpcClient,
) -> Result<PreparedPublish> {
    let manifest_uri = non_blank(Some(manifest_uri))
        .ok_or(RegistryError::MissingManifestUri)?
        .to_string();
    let manifest_path = loaded
        .app
        .output
        .as_ref()
        .map(|output| loaded.workspace_root.join(&output.manifest))
        .ok_or_else(|| RegistryError::MissingManifestPath {
            config_path: loaded.config_path.clone(),
        })?;
    if !manifest_path.is_file() {
        return Err(RegistryError::MissingManifestFile {
            path: manifest_path,
        });
    }

    let manifest = read_manifest(&manifest_path).map_err(|err| RegistryError::ManifestLoad {
        path: manifest_path.clone(),
        message: err.to_string(),
    })?;
    let manifest_hash_hex = sha256_file(&manifest_path).map_err(|err| RegistryError::Digest {
        path: manifest_path.clone(),
        message: err.to_string(),
    })?;
    let manifest_hash = parse_hash32(&manifest_hash_hex)?;

    let battlechain_config = loaded.battlechain_config();
    let network = resolve_network_config(
        &battlechain_config,
        &BattlechainOverrides {
            network: overrides.network.clone(),
            rpc_url: overrides.rpc_url.clone(),
            chain_id: overrides.chain_id,
            agreement_address: overrides.agreement_address.clone(),
            ..BattlechainOverrides::default()
        },
    )?;
    validate_manifest_network(&manifest, &network)?;

    let agreement_address = resolve_agreement_address(
        &manifest,
        battlechain_config.agreement_address.as_deref(),
        overrides.agreement_address.as_deref(),
    )?;
    let registry_address = resolve_registry_address(
        loaded.registry_config().address.as_deref(),
        overrides.registry_address.as_deref(),
    )?;

    let calldata = encode_publish_calldata(&agreement_address, &manifest_hash, &manifest_uri)?;
    let readback_calldata = encode_current_publication_calldata(&agreement_address)?;
    let mut remote_chain_id = None;
    let mut readback = None;

    if let Some(rpc_url) = network.rpc_url.as_deref() {
        if !is_http_url(rpc_url) {
            return Err(RegistryError::InvalidRpcUrl(rpc_url.to_string()));
        }
        let chain_id = client.chain_id(rpc_url)?;
        if chain_id != network.chain_id {
            return Err(RegistryError::RemoteChainMismatch {
                remote_chain_id: chain_id,
                resolved_chain_id: network.chain_id,
            });
        }
        remote_chain_id = Some(chain_id);

        let raw = client.eth_call(rpc_url, &registry_address, &readback_calldata)?;
        let current = decode_current_publication_result(&raw)?;
        readback = Some(compare_publication(
            current,
            &manifest_hash,
            manifest_uri.as_str(),
        ));
    }

    Ok(PreparedPublish {
        manifest_display_path: display_path(&loaded.workspace_root, &manifest_path),
        manifest_path,
        registry_address,
        agreement_address,
        manifest_hash,
        manifest_digest: format!("sha256:{manifest_hash_hex}"),
        manifest_hash_hex,
        manifest_uri,
        calldata,
        readback_calldata,
        network,
        remote_chain_id,
        readback,
    })
}

pub fn registry_publish_artifact_path(loaded: &LoadedConfig) -> PathBuf {
    loaded
        .workspace_root
        .join(".safeharbor/registry/publish.json")
}

pub fn registry_publish_artifact(prepared: &PreparedPublish) -> RegistryPublishArtifact {
    RegistryPublishArtifact {
        schema_version: REGISTRY_PUBLISH_SCHEMA_VERSION.to_string(),
        manifest_path: prepared.manifest_display_path.clone(),
        manifest_digest: prepared.manifest_digest.clone(),
        manifest_hash: prepared.manifest_hash_hex.clone(),
        manifest_uri: prepared.manifest_uri.clone(),
        agreement_address: prepared.agreement_address.clone(),
        registry_address: prepared.registry_address.clone(),
        network: prepared.network.clone(),
        publish_calldata: prepared.calldata.clone(),
        readback_calldata: prepared.readback_calldata.clone(),
        remote_chain_id: prepared.remote_chain_id,
        readback: prepared.readback.as_ref().map(readback_artifact),
    }
}

pub fn write_registry_publish_artifact(
    path: &Path,
    prepared: &PreparedPublish,
) -> Result<RegistryPublishArtifact> {
    let artifact = registry_publish_artifact(prepared);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RegistryError::CreateDir {
            kind: "registry publish artifact",
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let json = serde_json::to_string_pretty(&artifact).map_err(|err| {
        RegistryError::Abi(format!(
            "failed to serialize registry publish artifact: {err}"
        ))
    })?;
    fs::write(path, format!("{json}\n")).map_err(|source| RegistryError::Write {
        kind: "registry publish artifact",
        path: path.to_path_buf(),
        source,
    })?;

    Ok(artifact)
}

fn readback_artifact(report: &ReadbackReport) -> RegistryReadbackArtifact {
    RegistryReadbackArtifact {
        status: report.status,
        current: report.current.as_ref().map(publication_artifact),
    }
}

fn publication_artifact(record: &PublicationRecord) -> PublicationArtifact {
    PublicationArtifact {
        agreement: record.agreement.clone(),
        manifest_hash: format!("sha256:{}", record.manifest_hash_hex),
        manifest_uri: record.manifest_uri.clone(),
        publisher: record.publisher.clone(),
        published_at: record.published_at,
    }
}

pub fn compare_publication(
    current: Option<PublicationRecord>,
    expected_hash: &[u8; 32],
    expected_uri: &str,
) -> ReadbackReport {
    let Some(record) = current else {
        return ReadbackReport {
            status: ReadbackStatus::NoPublication,
            current: None,
        };
    };

    let hash_matches = &record.manifest_hash == expected_hash;
    let uri_matches = record.manifest_uri == expected_uri;
    let status = match (hash_matches, uri_matches) {
        (true, true) => ReadbackStatus::Match,
        (false, true) => ReadbackStatus::HashMismatch,
        (true, false) => ReadbackStatus::UriMismatch,
        (false, false) => ReadbackStatus::HashAndUriMismatch,
    };

    ReadbackReport {
        status,
        current: Some(record),
    }
}

pub fn encode_publish_calldata(
    agreement: &str,
    manifest_hash: &[u8; 32],
    manifest_uri: &str,
) -> Result<String> {
    let agreement = parse_address(agreement, "agreement")?;
    let uri_bytes = manifest_uri.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&function_selector(PUBLISH_SIGNATURE));
    encoded.extend_from_slice(&address_word(&agreement));
    encoded.extend_from_slice(manifest_hash);
    encoded.extend_from_slice(&u256_word(96));
    encoded.extend_from_slice(&u256_word(uri_bytes.len() as u128));
    encoded.extend_from_slice(uri_bytes);
    pad_to_word_from(&mut encoded, 4);

    Ok(hex_prefixed(&encoded))
}

pub fn encode_current_publication_calldata(agreement: &str) -> Result<String> {
    let agreement = parse_address(agreement, "agreement")?;
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&function_selector(CURRENT_PUBLICATION_SIGNATURE));
    encoded.extend_from_slice(&address_word(&agreement));
    Ok(hex_prefixed(&encoded))
}

pub fn decode_current_publication_result(raw: &str) -> Result<Option<PublicationRecord>> {
    let bytes = decode_hex(raw)?;
    if bytes.len() < 160 {
        return Err(RegistryError::Abi(format!(
            "currentPublication response is too short: {} bytes",
            bytes.len()
        )));
    }

    let tuple_start = tuple_start_offset(&bytes)?;
    let agreement = word_to_address(read_word_at(&bytes, tuple_start, 0)?);
    let manifest_hash = word_to_hash(read_word_at(&bytes, tuple_start, 1)?);
    let string_offset = word_to_usize(read_word_at(&bytes, tuple_start, 2)?)?;
    let publisher = word_to_address(read_word_at(&bytes, tuple_start, 3)?);
    let published_at = word_to_u64(read_word_at(&bytes, tuple_start, 4)?)?;
    let manifest_uri = read_abi_string(&bytes, tuple_start + string_offset)?;

    if agreement == ZERO_ADDRESS
        && manifest_hash == [0u8; 32]
        && manifest_uri.is_empty()
        && publisher == ZERO_ADDRESS
        && published_at == 0
    {
        return Ok(None);
    }

    Ok(Some(PublicationRecord {
        agreement,
        manifest_hash,
        manifest_hash_hex: hex_unprefixed(&manifest_hash),
        manifest_uri,
        publisher,
        published_at,
    }))
}

fn resolve_agreement_address(
    manifest: &SafeHarborManifest,
    config_agreement: Option<&str>,
    cli_agreement: Option<&str>,
) -> Result<String> {
    let manifest_agreement = manifest
        .adapters
        .as_ref()
        .and_then(|adapters| adapters.battlechain.as_ref())
        .map(|battlechain| battlechain.agreement_address.as_str())
        .and_then(|value| non_blank(Some(value)));

    if let Some(manifest_agreement) = manifest_agreement {
        let normalized_manifest = normalize_address(manifest_agreement, "agreement")?;
        check_agreement_conflict(
            &normalized_manifest,
            cli_agreement,
            "CLI --agreement-address",
        )?;
        check_agreement_conflict(
            &normalized_manifest,
            config_agreement,
            "[battlechain].agreement_address",
        )?;
        return Ok(normalized_manifest);
    }

    if let Some(value) = non_blank(cli_agreement) {
        return normalize_address(value, "agreement");
    }
    if let Some(value) = non_blank(config_agreement) {
        return normalize_address(value, "agreement");
    }

    Err(RegistryError::MissingAgreementAddress)
}

fn resolve_registry_address(
    config_registry: Option<&str>,
    cli_registry: Option<&str>,
) -> Result<String> {
    if let Some(value) = non_blank(cli_registry) {
        return normalize_address(value, "registry");
    }
    if let Some(value) = non_blank(config_registry) {
        return normalize_address(value, "registry");
    }

    Err(RegistryError::MissingRegistryAddress)
}

fn check_agreement_conflict(
    manifest_agreement: &str,
    candidate: Option<&str>,
    source: &'static str,
) -> Result<()> {
    let Some(candidate) = non_blank(candidate) else {
        return Ok(());
    };
    let normalized_candidate = normalize_address(candidate, "agreement")?;
    if normalized_candidate != manifest_agreement {
        return Err(RegistryError::AgreementConflict {
            manifest: manifest_agreement.to_string(),
            source_name: source,
            candidate: normalized_candidate,
        });
    }
    Ok(())
}

fn validate_manifest_network(
    manifest: &SafeHarborManifest,
    network: &ResolvedNetworkConfig,
) -> Result<()> {
    if manifest.deployment.chain_id != network.chain_id {
        return Err(RegistryError::ManifestChainMismatch {
            manifest_chain_id: manifest.deployment.chain_id,
            resolved_chain_id: network.chain_id,
        });
    }
    if manifest.deployment.network != network.network {
        return Err(RegistryError::ManifestNetworkMismatch {
            manifest_network: manifest.deployment.network.clone(),
            resolved_network: network.network.clone(),
        });
    }
    Ok(())
}

fn parse_hash32(value: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 32 {
        return Err(RegistryError::Abi(format!(
            "manifest digest must be 32 bytes, got {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn normalize_address(value: &str, kind: &'static str) -> Result<String> {
    parse_address(value, kind).map(|bytes| address_hex(&bytes))
}

fn parse_address(value: &str, kind: &'static str) -> Result<[u8; 20]> {
    let raw = value.trim();
    if raw.len() != 42
        || !raw.starts_with("0x")
        || !raw[2..].chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(RegistryError::InvalidAddress {
            kind,
            value: value.to_string(),
        });
    }
    let bytes = decode_hex(raw)?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes);
    Ok(address)
}

fn address_word(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address);
    out
}

fn word_to_address(word: &[u8]) -> String {
    let mut address = [0u8; 20];
    address.copy_from_slice(&word[12..32]);
    address_hex(&address)
}

fn word_to_hash(word: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(word);
    hash
}

fn word_to_u64(word: &[u8]) -> Result<u64> {
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(RegistryError::Abi(
            "ABI word does not fit into uint64".to_string(),
        ));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(buf))
}

fn word_to_usize(word: &[u8]) -> Result<usize> {
    let value = word_to_u64(word)?;
    usize::try_from(value)
        .map_err(|_| RegistryError::Abi(format!("ABI offset does not fit into usize: {value}")))
}

fn tuple_start_offset(bytes: &[u8]) -> Result<usize> {
    if bytes.len() >= 192 {
        let first_word = read_word_at(bytes, 0, 0)?;
        if word_to_usize(first_word)? == 32 {
            return Ok(32);
        }
    }
    Ok(0)
}

fn read_word_at(bytes: &[u8], base: usize, index: usize) -> Result<&[u8]> {
    let start = index
        .checked_mul(32)
        .and_then(|offset| base.checked_add(offset))
        .ok_or_else(|| RegistryError::Abi("ABI word offset overflowed".to_string()))?;
    let end = start + 32;
    bytes.get(start..end).ok_or_else(|| {
        RegistryError::Abi(format!(
            "ABI response is missing word {index}; length is {} bytes",
            bytes.len()
        ))
    })
}

fn read_abi_string(bytes: &[u8], offset: usize) -> Result<String> {
    let len_word = bytes.get(offset..offset + 32).ok_or_else(|| {
        RegistryError::Abi(format!("ABI string offset {offset} is out of bounds"))
    })?;
    let len = word_to_usize(len_word)?;
    let start = offset + 32;
    let end = start + len;
    let raw = bytes.get(start..end).ok_or_else(|| {
        RegistryError::Abi(format!(
            "ABI string data is out of bounds: offset={offset}, length={len}"
        ))
    })?;

    String::from_utf8(raw.to_vec())
        .map_err(|err| RegistryError::Abi(format!("ABI string is not valid UTF-8: {err}")))
}

fn u256_word(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

#[cfg(test)]
fn pad_to_word(bytes: &mut Vec<u8>) {
    pad_to_word_from(bytes, 0);
}

fn pad_to_word_from(bytes: &mut Vec<u8>, start_offset: usize) {
    let payload_len = bytes.len() - start_offset;
    let rem = payload_len % 32;
    if rem != 0 {
        bytes.resize(bytes.len() + (32 - rem), 0);
    }
}

fn function_selector(signature: &str) -> [u8; 4] {
    let digest = keccak256(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| RegistryError::Rpc(format!("expected hex quantity, got {value}")))?;
    u64::from_str_radix(digits, 16)
        .map_err(|err| RegistryError::Rpc(format!("invalid hex quantity {value}: {err}")))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    if digits.len() % 2 != 0 {
        return Err(RegistryError::Abi(format!(
            "hex value has odd length: {value}"
        )));
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for chunk in digits.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RegistryError::Abi(format!(
            "invalid hex character '{}'",
            byte as char
        ))),
    }
}

fn hex_prefixed(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    out.push_str(&hex_unprefixed(bytes));
    out
}

fn hex_unprefixed(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn address_hex(address: &[u8; 20]) -> String {
    hex_prefixed(address)
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn is_http_url(value: &str) -> bool {
    let value = value.trim();
    (value.starts_with("https://") || value.starts_with("http://"))
        && !value.contains(char::is_whitespace)
        && value.len() > "http://".len()
}

fn display_path(root: &std::path::Path, path: &std::path::Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut chunks = input.chunks_exact(RATE);

    for chunk in &mut chunks {
        absorb_block(&mut state, chunk);
        keccakf(&mut state);
    }

    let remainder = chunks.remainder();
    let mut block = [0u8; RATE];
    block[..remainder.len()].copy_from_slice(remainder);
    block[remainder.len()] = 0x01;
    block[RATE - 1] |= 0x80;
    absorb_block(&mut state, &block);
    keccakf(&mut state);

    let mut out = [0u8; 32];
    for (i, lane) in state.iter().take(4).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(chunk);
        state[i] ^= u64::from_le_bytes(lane);
    }
}

fn keccakf(a: &mut [u64; 25]) {
    const ROUNDS: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const RHO: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];

    for rc in ROUNDS {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(RHO[x][y]);
            }
        }

        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        a[0] ^= rc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use battlechain_adapter::types::ValueSource;
    use safeharbor_config::load_config;
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    struct NoopClient;

    impl RegistryRpcClient for NoopClient {
        fn chain_id(&self, _rpc_url: &str) -> Result<u64> {
            Err(RegistryError::Rpc("unexpected chain_id call".to_string()))
        }

        fn eth_call(&self, _rpc_url: &str, _to: &str, _data: &str) -> Result<String> {
            Err(RegistryError::Rpc("unexpected eth_call".to_string()))
        }
    }

    struct FakeClient {
        chain_id: u64,
        call_result: String,
    }

    impl RegistryRpcClient for FakeClient {
        fn chain_id(&self, _rpc_url: &str) -> Result<u64> {
            Ok(self.chain_id)
        }

        fn eth_call(&self, _rpc_url: &str, _to: &str, _data: &str) -> Result<String> {
            Ok(self.call_result.clone())
        }
    }

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("safeharbor-registry-test-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn sample_manifest_path() -> PathBuf {
        fixture_root().join("examples/simple-vault/expected.safeharbor.manifest.json")
    }

    fn write_workspace(root: &Path, include_manifest: bool, include_registry: bool) {
        fs::create_dir_all(root.join("out")).unwrap();
        if include_manifest {
            fs::copy(
                sample_manifest_path(),
                root.join("out/safeharbor.manifest.json"),
            )
            .unwrap();
        }
        let registry = if include_registry {
            r#"
[registry]
address = "0x1111111111111111111111111111111111111111"
"#
        } else {
            ""
        };
        fs::write(
            root.join("safeharbor.toml"),
            format!(
                r#"
[output]
manifest = "out/safeharbor.manifest.json"

[battlechain]
network = "battlechain-testnet"
chain_id = 627
{registry}
"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn derives_function_selectors_from_signatures() {
        assert_eq!(
            hex_prefixed(&function_selector(PUBLISH_SIGNATURE)),
            "0xb0f844bf"
        );
        assert_eq!(
            hex_prefixed(&function_selector(CURRENT_PUBLICATION_SIGNATURE)),
            "0x01acb687"
        );
    }

    #[test]
    fn generates_publish_calldata() {
        let hash = parse_hash32("674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb06")
            .unwrap();
        let calldata = encode_publish_calldata(
            "0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8",
            &hash,
            "ipfs://bafy-safeharbor-test",
        )
        .unwrap();

        assert_eq!(
            calldata,
            "0xb0f844bf0000000000000000000000004a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb060000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001b697066733a2f2f626166792d73616665686172626f722d746573740000000000"
        );
    }

    #[test]
    fn reports_missing_manifest_path() {
        let root = unique_temp_dir();
        fs::write(root.join("safeharbor.toml"), "").unwrap();
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let err = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &NoopClient,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing [output].manifest"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_missing_manifest_file() {
        let root = unique_temp_dir();
        write_workspace(&root, false, true);
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let err = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &NoopClient,
        )
        .unwrap_err();

        assert!(err.to_string().contains("manifest file not found"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_missing_agreement_address() {
        let root = unique_temp_dir();
        write_workspace(&root, true, true);
        let mut manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("out/safeharbor.manifest.json")).unwrap(),
        )
        .unwrap();
        manifest.as_object_mut().unwrap().remove("adapters");
        fs::write(
            root.join("out/safeharbor.manifest.json"),
            format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
        )
        .unwrap();
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let err = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &NoopClient,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing agreement address"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_missing_registry_address() {
        let root = unique_temp_dir();
        write_workspace(&root, true, false);
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let err = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &NoopClient,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing registry address"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_agreement_wins_and_conflicting_cli_fails() {
        let root = unique_temp_dir();
        write_workspace(&root, true, true);
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let prepared = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &NoopClient,
        )
        .unwrap();
        assert_eq!(
            prepared.agreement_address,
            "0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8"
        );

        let err = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides {
                agreement_address: Some("0x0000000000000000000000000000000000000001".to_string()),
                ..RegistryOverrides::default()
            },
            &NoopClient,
        )
        .unwrap_err();
        assert!(err.to_string().contains("do not override"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cli_agreement_is_used_when_manifest_has_no_adapter() {
        let root = unique_temp_dir();
        write_workspace(&root, true, true);
        let mut manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(root.join("out/safeharbor.manifest.json")).unwrap(),
        )
        .unwrap();
        manifest.as_object_mut().unwrap().remove("adapters");
        fs::write(
            root.join("out/safeharbor.manifest.json"),
            format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
        )
        .unwrap();
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let prepared = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides {
                agreement_address: Some("0x0000000000000000000000000000000000000001".to_string()),
                ..RegistryOverrides::default()
            },
            &NoopClient,
        )
        .unwrap();

        assert_eq!(
            prepared.agreement_address,
            "0x0000000000000000000000000000000000000001"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reports_remote_chain_mismatch() {
        let root = unique_temp_dir();
        write_workspace(&root, true, true);
        fs::write(
            root.join("safeharbor.toml"),
            r#"
[output]
manifest = "out/safeharbor.manifest.json"

[battlechain]
network = "battlechain-testnet"
chain_id = 627
rpc_url = "http://127.0.0.1:8545"

[registry]
address = "0x1111111111111111111111111111111111111111"
"#,
        )
        .unwrap();
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();

        let err = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &FakeClient {
                chain_id: 1,
                call_result: empty_publication_result(),
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("remote chain ID 1"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn readback_statuses_distinguish_match_and_mismatches() {
        let expected_hash = [1u8; 32];
        let other_hash = [2u8; 32];
        let record = PublicationRecord {
            agreement: "0x0000000000000000000000000000000000000001".to_string(),
            manifest_hash: expected_hash,
            manifest_hash_hex: hex_unprefixed(&expected_hash),
            manifest_uri: "ipfs://one".to_string(),
            publisher: "0x0000000000000000000000000000000000000002".to_string(),
            published_at: 1,
        };

        assert_eq!(
            compare_publication(None, &expected_hash, "ipfs://one").status,
            ReadbackStatus::NoPublication
        );
        assert_eq!(
            compare_publication(Some(record.clone()), &expected_hash, "ipfs://one").status,
            ReadbackStatus::Match
        );
        assert_eq!(
            compare_publication(Some(record.clone()), &other_hash, "ipfs://one").status,
            ReadbackStatus::HashMismatch
        );
        assert_eq!(
            compare_publication(Some(record.clone()), &expected_hash, "ipfs://two").status,
            ReadbackStatus::UriMismatch
        );
        assert_eq!(
            compare_publication(Some(record), &other_hash, "ipfs://two").status,
            ReadbackStatus::HashAndUriMismatch
        );
    }

    #[test]
    fn decodes_empty_and_populated_publication_results() {
        assert_eq!(
            decode_current_publication_result(&empty_publication_result()).unwrap(),
            None
        );

        let hash = [7u8; 32];
        let raw = publication_result(
            "0x0000000000000000000000000000000000000001",
            &hash,
            "ipfs://manifest",
            "0x0000000000000000000000000000000000000002",
            42,
        );
        let decoded = decode_current_publication_result(&raw).unwrap().unwrap();

        assert_eq!(decoded.manifest_hash, hash);
        assert_eq!(decoded.manifest_uri, "ipfs://manifest");
        assert_eq!(decoded.published_at, 42);
    }

    fn empty_publication_result() -> String {
        publication_result(ZERO_ADDRESS, &[0u8; 32], "", ZERO_ADDRESS, 0)
    }

    fn publication_result(
        agreement: &str,
        hash: &[u8; 32],
        uri: &str,
        publisher: &str,
        published_at: u64,
    ) -> String {
        let agreement = parse_address(agreement, "agreement").unwrap();
        let publisher = parse_address(publisher, "publisher").unwrap();
        let mut tuple = Vec::new();
        tuple.extend_from_slice(&address_word(&agreement));
        tuple.extend_from_slice(hash);
        tuple.extend_from_slice(&u256_word(160));
        tuple.extend_from_slice(&address_word(&publisher));
        tuple.extend_from_slice(&u256_word(published_at as u128));
        tuple.extend_from_slice(&u256_word(uri.len() as u128));
        tuple.extend_from_slice(uri.as_bytes());
        pad_to_word(&mut tuple);

        let mut encoded = Vec::new();
        encoded.extend_from_slice(&u256_word(32));
        encoded.extend_from_slice(&tuple);
        hex_prefixed(&encoded)
    }

    #[test]
    fn records_stable_sample_manifest_digest() {
        let digest = sha256_file(&sample_manifest_path()).unwrap();

        assert_eq!(
            digest,
            "674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb06"
        );
    }

    #[test]
    fn prepared_publish_reports_readback_match() {
        let root = unique_temp_dir();
        write_workspace(&root, true, true);
        fs::write(
            root.join("safeharbor.toml"),
            r#"
[output]
manifest = "out/safeharbor.manifest.json"

[battlechain]
network = "battlechain-testnet"
chain_id = 627
rpc_url = "http://127.0.0.1:8545"

[registry]
address = "0x1111111111111111111111111111111111111111"
"#,
        )
        .unwrap();
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();
        let hash = parse_hash32("674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb06")
            .unwrap();

        let prepared = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &FakeClient {
                chain_id: 627,
                call_result: publication_result(
                    "0x4a13d7c0b6e9f24c1d8a3e5b7f02c6d9a1e4b3f8",
                    &hash,
                    "ipfs://manifest",
                    "0x0000000000000000000000000000000000000002",
                    42,
                ),
            },
        )
        .unwrap();

        assert_eq!(prepared.readback.unwrap().status, ReadbackStatus::Match);
        assert_eq!(prepared.remote_chain_id, Some(627));
        assert_eq!(prepared.network.chain_id_source, ValueSource::Config);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn writes_deterministic_publish_artifact_without_rpc() {
        let root = unique_temp_dir();
        write_workspace(&root, true, true);
        let loaded = load_config(&root.join("safeharbor.toml")).unwrap();
        let path = registry_publish_artifact_path(&loaded);

        let prepared = prepare_registry_publish(
            &loaded,
            "ipfs://manifest",
            &RegistryOverrides::default(),
            &NoopClient,
        )
        .unwrap();

        let first = write_registry_publish_artifact(&path, &prepared).unwrap();
        let first_bytes = fs::read_to_string(&path).unwrap();
        let second = write_registry_publish_artifact(&path, &prepared).unwrap();
        let second_bytes = fs::read_to_string(&path).unwrap();

        assert_eq!(first, second);
        assert_eq!(first_bytes, second_bytes);
        assert_eq!(first.schema_version, REGISTRY_PUBLISH_SCHEMA_VERSION);
        assert_eq!(first.manifest_path, "out/safeharbor.manifest.json");
        assert_eq!(
            first.manifest_digest,
            "sha256:674c0d3873ce664666da4fb5b0188d520c31c25e2b8a5649b52de588c8a4cb06"
        );
        assert_eq!(
            first.registry_address,
            "0x1111111111111111111111111111111111111111"
        );
        assert!(first.remote_chain_id.is_none());
        assert!(first.readback.is_none());

        fs::remove_dir_all(root).unwrap();
    }
}
