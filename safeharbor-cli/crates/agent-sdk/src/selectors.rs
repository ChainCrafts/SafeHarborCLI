use crate::{AgentManifest, AgentSdkError, Result, index::SelectorRef};
use manifest::{Access, AccessKind, ScopeContract, ScopeSelector};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorScopeView {
    pub contract_id: String,
    pub contract_name: String,
    pub contract_address: Option<String>,
    pub selector: String,
    pub signature: Option<String>,
    pub in_scope: bool,
    pub access: Option<String>,
    pub role_requirements: Vec<String>,
}

impl AgentManifest {
    pub fn is_selector_in_scope(&self, selector_hex: &str) -> Result<bool> {
        Ok(self
            .selector_scope(selector_hex)?
            .iter()
            .any(|selector| selector.in_scope))
    }

    pub fn selector_scope(&self, selector_hex: &str) -> Result<Vec<SelectorScopeView>> {
        let selector = normalize_selector(selector_hex)?;
        Ok(self
            .index
            .selectors_by_hex
            .get(&selector)
            .map(|refs| {
                refs.iter()
                    .map(|selector_ref| self.view(selector_ref))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn selectors_for_contract(&self, contract_id: &str) -> Result<Vec<SelectorScopeView>> {
        let contract_index = self
            .index
            .contracts_by_id
            .get(contract_id)
            .ok_or_else(|| AgentSdkError::UnknownContractId(contract_id.to_string()))?;
        let contract = &self.manifest.scope.contracts[*contract_index];

        Ok(contract
            .selectors
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|selector| view_from_parts(contract, selector))
            .collect())
    }

    pub fn selectors_by_signature(&self, signature: &str) -> Vec<SelectorScopeView> {
        self.index
            .selectors_by_signature
            .get(signature)
            .map(|refs| {
                refs.iter()
                    .map(|selector_ref| self.view(selector_ref))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn selectors_requiring_role(&self, role: &str) -> Vec<SelectorScopeView> {
        self.manifest
            .scope
            .contracts
            .iter()
            .flat_map(|contract| {
                contract
                    .selectors
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(move |selector| (contract, selector))
            })
            .filter(|(_, selector)| {
                selector
                    .access
                    .required_role_ids
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|candidate| candidate == role)
            })
            .map(|(contract, selector)| view_from_parts(contract, selector))
            .collect()
    }

    pub fn role_requirements_for_selector(&self, selector_hex: &str) -> Result<Vec<String>> {
        let selector = normalize_selector(selector_hex)?;
        let mut roles = Vec::new();

        for selector_ref in self
            .index
            .selectors_by_hex
            .get(&selector)
            .into_iter()
            .flatten()
        {
            let selector = self.selector(selector_ref);
            for role in selector.access.required_role_ids.as_deref().unwrap_or(&[]) {
                if !roles.contains(role) {
                    roles.push(role.clone());
                }
            }
        }

        Ok(roles)
    }

    fn view(&self, selector_ref: &SelectorRef) -> SelectorScopeView {
        let contract = &self.manifest.scope.contracts[selector_ref.contract_index];
        let selector = self.selector(selector_ref);

        view_from_parts(contract, selector)
    }

    fn selector(&self, selector_ref: &SelectorRef) -> &ScopeSelector {
        &self.manifest.scope.contracts[selector_ref.contract_index]
            .selectors
            .as_ref()
            .expect("selector refs are built only from selector-bearing contracts")
            [selector_ref.selector_index]
    }
}

pub(crate) fn normalize_selector(selector: &str) -> Result<String> {
    if selector.len() == 10
        && selector.starts_with("0x")
        && selector[2..].chars().all(|ch| ch.is_ascii_hexdigit())
    {
        Ok(selector.to_ascii_lowercase())
    } else {
        Err(AgentSdkError::InvalidSelector {
            selector: selector.to_string(),
        })
    }
}

fn view_from_parts(contract: &ScopeContract, selector: &ScopeSelector) -> SelectorScopeView {
    SelectorScopeView {
        contract_id: contract.id.clone(),
        contract_name: contract.name.clone(),
        contract_address: non_empty(contract.address.as_str()).map(ToString::to_string),
        selector: selector.selector.to_ascii_lowercase(),
        signature: Some(selector.signature.clone()),
        in_scope: contract.in_scope && selector.in_scope,
        access: Some(access_kind(&selector.access).to_string()),
        role_requirements: role_requirements(&selector.access),
    }
}

fn access_kind(access: &Access) -> &'static str {
    match access.kind {
        AccessKind::Permissionless => "permissionless",
        AccessKind::RoleGated => "role_gated",
        AccessKind::Unknown => "unknown",
    }
}

fn role_requirements(access: &Access) -> Vec<String> {
    access.required_role_ids.as_deref().unwrap_or(&[]).to_vec()
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
