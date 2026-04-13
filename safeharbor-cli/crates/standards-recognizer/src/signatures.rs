use analyzer::types::{
    AnalysisGraph, ContractFacts, EntrypointKind, FunctionFacts, StateMutability, Visibility,
};
use std::collections::BTreeSet;

pub const ERC20_CORE_SIGNATURES: &[&str] = &[
    "allowance(address,address)",
    "approve(address,uint256)",
    "balanceOf(address)",
    "totalSupply()",
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
];

pub const ERC20_METADATA_SIGNATURES: &[&str] = &["decimals()", "name()", "symbol()"];

pub const ERC4626_VIEW_SIGNATURES: &[&str] = &[
    "asset()",
    "convertToAssets(uint256)",
    "convertToShares(uint256)",
    "totalAssets()",
];

pub const ERC4626_MUTATION_SIGNATURES: &[&str] = &[
    "deposit(uint256,address)",
    "mint(uint256,address)",
    "redeem(uint256,address,address)",
    "withdraw(uint256,address,address)",
];

pub const ERC4626_PREVIEW_MAX_SIGNATURES: &[&str] = &[
    "maxDeposit(address)",
    "maxMint(address)",
    "maxRedeem(address)",
    "maxWithdraw(address)",
    "previewDeposit(uint256)",
    "previewMint(uint256)",
    "previewRedeem(uint256)",
    "previewWithdraw(uint256)",
];

pub const ACCESS_CONTROL_MANAGEMENT_SIGNATURES: &[&str] = &[
    "getRoleAdmin(bytes32)",
    "grantRole(bytes32,address)",
    "hasRole(bytes32,address)",
    "renounceRole(bytes32,address)",
    "revokeRole(bytes32,address)",
];

pub const OWNABLE_MANAGEMENT_SIGNATURES: &[&str] = &[
    "acceptOwnership()",
    "owner()",
    "renounceOwnership()",
    "transferOwnership(address)",
];

pub const UPGRADE_SIGNATURES: &[&str] = &[
    "proxiableUUID()",
    "upgradeTo(address)",
    "upgradeToAndCall(address,bytes)",
];

pub fn functions_for_contract<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    graph
        .functions
        .iter()
        .filter(|function| function.contract_id == contract_id)
        .collect()
}

pub fn callable_functions_for_contract<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
) -> Vec<&'a FunctionFacts> {
    functions_for_contract(graph, contract_id)
        .into_iter()
        .filter(|function| is_callable_surface(function))
        .collect()
}

pub fn functions_matching_signatures<'a>(
    graph: &'a AnalysisGraph,
    contract_id: &str,
    signatures: &[&str],
) -> Vec<&'a FunctionFacts> {
    let expected = signatures.iter().copied().collect::<BTreeSet<_>>();
    functions_for_contract(graph, contract_id)
        .into_iter()
        .filter(|function| {
            function
                .signature
                .as_deref()
                .is_some_and(|signature| expected.contains(signature))
        })
        .collect()
}

pub fn count_present_signatures(
    graph: &AnalysisGraph,
    contract_id: &str,
    signatures: &[&str],
) -> usize {
    let present = signature_set(graph, contract_id);
    signatures
        .iter()
        .filter(|signature| present.contains(**signature))
        .count()
}

pub fn has_all_signatures(graph: &AnalysisGraph, contract_id: &str, signatures: &[&str]) -> bool {
    count_present_signatures(graph, contract_id, signatures) == signatures.len()
}

pub fn signature_set(graph: &AnalysisGraph, contract_id: &str) -> BTreeSet<String> {
    functions_for_contract(graph, contract_id)
        .into_iter()
        .filter_map(|function| function.signature.clone())
        .collect()
}

pub fn has_named_base(contract: &ContractFacts, names: &[&str]) -> bool {
    contract.bases.iter().any(|base| {
        names.iter().any(|candidate| {
            base.as_str() == *candidate || normalize_name(base) == normalize_name(candidate)
        })
    })
}

pub fn function_ids(functions: &[&FunctionFacts]) -> Vec<String> {
    let mut ids = functions
        .iter()
        .map(|function| function.id.clone())
        .collect::<Vec<_>>();
    dedup_sort(&mut ids);
    ids
}

pub fn selectors(functions: &[&FunctionFacts]) -> Vec<String> {
    let mut selectors = functions
        .iter()
        .filter_map(|function| function.selector.clone())
        .collect::<Vec<_>>();
    dedup_sort(&mut selectors);
    selectors
}

pub fn special_entrypoints(functions: &[&FunctionFacts]) -> Vec<EntrypointKind> {
    let mut entrypoints = functions
        .iter()
        .filter(|function| {
            matches!(
                function.entrypoint_kind,
                EntrypointKind::Receive | EntrypointKind::Fallback
            )
        })
        .map(|function| function.entrypoint_kind.clone())
        .collect::<Vec<_>>();
    entrypoints.sort();
    entrypoints.dedup();
    entrypoints
}

pub fn is_callable_surface(function: &FunctionFacts) -> bool {
    matches!(
        function.entrypoint_kind,
        EntrypointKind::Receive | EntrypointKind::Fallback
    ) || (function.entrypoint_kind == EntrypointKind::Normal
        && matches!(
            function.visibility,
            Visibility::External | Visibility::Public
        ))
}

pub fn is_state_changing(function: &FunctionFacts) -> bool {
    matches!(
        function.state_mutability,
        StateMutability::Nonpayable | StateMutability::Payable | StateMutability::Unknown
    )
}

pub fn recognition_id(contract_id: &str, kind: &str) -> String {
    format!("recognition-{}-{kind}", slug(contract_id))
}

pub fn suggestion_id(contract_id: &str, template: &str) -> String {
    format!("suggestion-{}-{}", slug(contract_id), slug(template))
}

pub fn dedup_sort(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
    values.sort();
}

pub fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn slug(value: &str) -> String {
    let mut out = String::new();
    let mut previous_dash = true;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            out.push('-');
            previous_dash = true;
        }
    }

    out.trim_matches('-').to_string()
}
