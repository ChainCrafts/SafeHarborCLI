use crate::errors::{BattlechainError, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

pub trait BattlechainClient {
    fn chain_id(&self, rpc_url: &str) -> Result<u64>;
    fn agreement_code(&self, rpc_url: &str, agreement_address: &str) -> Result<Option<String>>;

    fn lifecycle_state(&self, _rpc_url: &str, _agreement_address: &str) -> Result<Option<String>> {
        Ok(None)
    }
}

pub struct NoopBattlechainClient;

impl BattlechainClient for NoopBattlechainClient {
    fn chain_id(&self, _rpc_url: &str) -> Result<u64> {
        Err(BattlechainError::Client(
            "no BattleChain RPC client configured".to_string(),
        ))
    }

    fn agreement_code(&self, _rpc_url: &str, _agreement_address: &str) -> Result<Option<String>> {
        Err(BattlechainError::Client(
            "no BattleChain RPC client configured".to_string(),
        ))
    }
}

pub struct HttpBattlechainClient {
    client: reqwest::blocking::Client,
}

impl HttpBattlechainClient {
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|err| {
                BattlechainError::Client(format!("failed to initialize RPC client: {err}"))
            })?;

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
            .map_err(|err| BattlechainError::Client(format!("RPC request failed: {err}")))?;

        if !response.status().is_success() {
            return Err(BattlechainError::Client(format!(
                "RPC request failed with HTTP status {}",
                response.status()
            )));
        }

        let body: RpcResponse = response.json().map_err(|err| {
            BattlechainError::Client(format!("failed to parse RPC response: {err}"))
        })?;

        if let Some(error) = body.error {
            return Err(BattlechainError::Client(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        body.result.ok_or_else(|| {
            BattlechainError::Client("RPC response did not include result".to_string())
        })
    }
}

impl BattlechainClient for HttpBattlechainClient {
    fn chain_id(&self, rpc_url: &str) -> Result<u64> {
        let result = self.rpc_call(rpc_url, "eth_chainId", json!([]))?;
        let hex = result.as_str().ok_or_else(|| {
            BattlechainError::Client("eth_chainId result was not a hex string".to_string())
        })?;

        parse_hex_u64(hex)
    }

    fn agreement_code(&self, rpc_url: &str, agreement_address: &str) -> Result<Option<String>> {
        let result = self.rpc_call(rpc_url, "eth_getCode", json!([agreement_address, "latest"]))?;
        let code = result.as_str().ok_or_else(|| {
            BattlechainError::Client("eth_getCode result was not a hex string".to_string())
        })?;

        if code == "0x" || code == "0x0" {
            Ok(None)
        } else {
            Ok(Some(code.to_string()))
        }
    }
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| BattlechainError::Client(format!("expected hex quantity, got {value}")))?;
    u64::from_str_radix(digits, 16)
        .map_err(|err| BattlechainError::Client(format!("invalid hex quantity {value}: {err}")))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rpc_chain_id_hex() {
        assert_eq!(parse_hex_u64("0x273").unwrap(), 627);
    }

    #[test]
    fn rejects_non_hex_chain_id() {
        assert!(
            parse_hex_u64("627")
                .unwrap_err()
                .to_string()
                .contains("expected hex")
        );
    }
}
