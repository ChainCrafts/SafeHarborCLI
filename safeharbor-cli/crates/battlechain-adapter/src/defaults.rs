#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BattlechainNetworkDefault {
    pub name: &'static str,
    pub chain_id: u64,
    pub default_rpc_url: Option<&'static str>,
    pub currency_symbol: Option<&'static str>,
    pub explorer_base_url: Option<&'static str>,
}

pub const DEFAULT_NETWORK_NAME: &str = "battlechain-testnet";

const NETWORKS: &[BattlechainNetworkDefault] = &[BattlechainNetworkDefault {
    name: DEFAULT_NETWORK_NAME,
    chain_id: 627,
    default_rpc_url: None,
    currency_symbol: None,
    explorer_base_url: None,
}];

pub fn default_network() -> BattlechainNetworkDefault {
    known_network(DEFAULT_NETWORK_NAME).expect("default BattleChain network must be registered")
}

pub fn known_network(name: &str) -> Option<BattlechainNetworkDefault> {
    NETWORKS
        .iter()
        .copied()
        .find(|network| network.name == name)
}

pub fn known_network_names() -> Vec<&'static str> {
    NETWORKS.iter().map(|network| network.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_fixture_testnet_only() {
        assert_eq!(known_network_names(), vec!["battlechain-testnet"]);
        let network = default_network();
        assert_eq!(network.chain_id, 627);
        assert_eq!(network.default_rpc_url, None);
        assert_eq!(network.currency_symbol, None);
    }
}
