use crate::{
    artifacts::{ArtifactContract, abi_signature},
    project::FoundryProject,
    types::{
        AnalysisGraph, AuthSignal, AuthSignalKind, AuthSignalSource, CallKind, CallTarget,
        ContractFacts, ContractKind, DetectorFinding, EntrypointKind, FunctionFacts,
        InheritanceEdge, ModifierFacts, StateMutability, Visibility,
    },
};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub fn build_analysis_graph(
    project: &FoundryProject,
    artifacts: &[ArtifactContract],
    mut detector_findings: Vec<DetectorFinding>,
) -> Result<AnalysisGraph> {
    let mut contracts = Vec::new();
    let mut modifiers = Vec::new();
    let mut functions = Vec::new();
    let mut inheritance = Vec::new();
    let mut contract_ids_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut modifier_signals_by_contract: BTreeMap<(String, String), Vec<AuthSignal>> =
        BTreeMap::new();

    for artifact in artifacts {
        let contract_id = contract_id(&artifact.source_path, &artifact.contract_name);
        let contract_kind = contract_kind(&artifact.contract_ast);
        let bases = base_contract_names(&artifact.contract_ast);

        contracts.push(ContractFacts {
            id: contract_id.clone(),
            name: artifact.contract_name.clone(),
            source_path: artifact.source_path.clone(),
            kind: contract_kind,
            bases: bases.clone(),
            artifact_ref: Some(artifact.artifact_ref.clone()),
        });
        contract_ids_by_name
            .entry(artifact.contract_name.clone())
            .or_default()
            .push(contract_id.clone());

        for modifier in modifier_facts(&contract_id, &artifact.source_path, &artifact.contract_ast)
        {
            modifier_signals_by_contract.insert(
                (contract_id.clone(), modifier.name.clone()),
                modifier.auth_signals.clone(),
            );
            modifiers.push(modifier);
        }
    }

    for contract in &contracts {
        for base_contract_name in &contract.bases {
            let base_contract_id = contract_ids_by_name
                .get(base_contract_name)
                .and_then(|matches| (matches.len() == 1).then(|| matches[0].clone()));
            inheritance.push(InheritanceEdge {
                contract_id: contract.id.clone(),
                base_contract_id,
                base_contract_name: base_contract_name.clone(),
            });
        }
    }

    for artifact in artifacts {
        let contract_id = contract_id(&artifact.source_path, &artifact.contract_name);
        let local_modifier_signals = modifier_signals_by_contract.clone();
        let abi_by_selector = abi_signatures_by_selector(artifact);

        for function_node in contract_child_nodes(&artifact.contract_ast, "FunctionDefinition") {
            let entrypoint_kind = entrypoint_kind(function_node);
            let visibility = visibility(function_node);
            let state_mutability = state_mutability(function_node);
            let name = function_name(function_node, entrypoint_kind.clone());
            let selector_no_prefix = function_node
                .get("functionSelector")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let signature = if entrypoint_kind == EntrypointKind::Normal {
                selector_no_prefix
                    .as_ref()
                    .and_then(|selector| abi_by_selector.get(selector).cloned())
                    .or_else(|| ast_signature(function_node))
            } else {
                None
            };
            let selector = selector_no_prefix.map(|selector| format!("0x{selector}"));
            let modifiers_used = modifier_invocations(function_node);
            let mut auth_signals = Vec::new();
            let mut modifier_names = Vec::new();

            for invocation in &modifiers_used {
                modifier_names.push(invocation.name.clone());
                auth_signals.extend(auth_signals_from_modifier_invocation(invocation));
                if let Some(local_signals) =
                    local_modifier_signals.get(&(contract_id.clone(), invocation.name.clone()))
                {
                    auth_signals.extend(local_signals.clone());
                }
            }

            if let Some(body) = function_node.get("body") {
                auth_signals.extend(detect_auth_signals(body, AuthSignalSource::FunctionBody));
            }

            let calls = function_node
                .get("body")
                .map(detect_call_targets)
                .unwrap_or_default();

            sort_and_dedup_auth_signals(&mut auth_signals);
            modifier_names.sort();
            modifier_names.dedup();
            let mut calls = calls;
            sort_and_dedup_calls(&mut calls);

            functions.push(FunctionFacts {
                id: function_id(&contract_id, signature.as_deref(), &entrypoint_kind),
                contract_id: contract_id.clone(),
                name,
                signature,
                selector,
                entrypoint_kind,
                visibility,
                state_mutability,
                modifiers: modifier_names,
                auth_signals,
                calls,
            });
        }
    }

    contracts.sort_by(|left, right| left.id.cmp(&right.id));
    modifiers.sort_by(|left, right| left.id.cmp(&right.id));
    functions.sort_by(|left, right| left.id.cmp(&right.id));
    inheritance.sort_by(|left, right| {
        left.contract_id
            .cmp(&right.contract_id)
            .then(left.base_contract_name.cmp(&right.base_contract_name))
    });
    for finding in &mut detector_findings {
        finding.locations.sort_by(|left, right| {
            left.contract_path
                .cmp(&right.contract_path)
                .then(left.line_no.cmp(&right.line_no))
                .then(left.src.cmp(&right.src))
        });
    }

    Ok(AnalysisGraph {
        project: project.to_project_facts(),
        contracts,
        functions,
        modifiers,
        inheritance,
        detector_findings,
    })
}

fn abi_signatures_by_selector(artifact: &ArtifactContract) -> BTreeMap<String, String> {
    let mut signatures = BTreeMap::new();

    for entry in &artifact.abi {
        let Some(signature) = abi_signature(entry) else {
            continue;
        };
        if let Some(selector) = artifact.method_identifiers.get(&signature) {
            signatures.insert(selector.clone(), signature);
        }
    }

    signatures
}

fn modifier_facts(
    contract_id: &str,
    source_path: &str,
    contract_ast: &Value,
) -> Vec<ModifierFacts> {
    let mut modifiers = Vec::new();

    for modifier_node in contract_child_nodes(contract_ast, "ModifierDefinition") {
        let Some(name) = modifier_node.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut auth_signals =
            named_modifier_auth_signal(name, None, AuthSignalSource::ModifierDefinition);
        if let Some(body) = modifier_node.get("body") {
            auth_signals.extend(detect_auth_signals(
                body,
                AuthSignalSource::ModifierDefinition,
            ));
        }
        sort_and_dedup_auth_signals(&mut auth_signals);

        modifiers.push(ModifierFacts {
            id: format!("{contract_id}#modifier:{name}"),
            contract_id: contract_id.to_string(),
            name: name.to_string(),
            source_path: source_path.to_string(),
            auth_signals,
        });
    }

    modifiers
}

fn contract_id(source_path: &str, contract_name: &str) -> String {
    format!("{source_path}:{contract_name}")
}

fn function_id(
    contract_id: &str,
    signature: Option<&str>,
    entrypoint_kind: &EntrypointKind,
) -> String {
    let suffix = signature
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| match entrypoint_kind {
            EntrypointKind::Constructor => "constructor".to_string(),
            EntrypointKind::Receive => "receive".to_string(),
            EntrypointKind::Fallback => "fallback".to_string(),
            EntrypointKind::Normal => "unknown".to_string(),
        });
    format!("{contract_id}#{suffix}")
}

fn contract_kind(contract_ast: &Value) -> ContractKind {
    match contract_ast
        .get("contractKind")
        .and_then(Value::as_str)
        .unwrap_or("contract")
    {
        "interface" => ContractKind::Interface,
        "library" => ContractKind::Library,
        _ if contract_ast
            .get("abstract")
            .and_then(Value::as_bool)
            .unwrap_or(false) =>
        {
            ContractKind::AbstractContract
        }
        _ => ContractKind::Contract,
    }
}

fn base_contract_names(contract_ast: &Value) -> Vec<String> {
    let mut bases = Vec::new();

    for base in contract_ast
        .get("baseContracts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) = base
            .get("baseName")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .or_else(|| {
                base.get("baseName")
                    .and_then(|value| value.get("namePath"))
                    .and_then(Value::as_str)
            })
        {
            bases.push(name.to_string());
        }
    }

    bases.sort();
    bases.dedup();
    bases
}

fn contract_child_nodes<'a>(contract_ast: &'a Value, node_type: &str) -> Vec<&'a Value> {
    contract_ast
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|node| node.get("nodeType").and_then(Value::as_str) == Some(node_type))
        .collect()
}

fn entrypoint_kind(function_node: &Value) -> EntrypointKind {
    match function_node
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("function")
    {
        "constructor" => EntrypointKind::Constructor,
        "receive" => EntrypointKind::Receive,
        "fallback" => EntrypointKind::Fallback,
        _ => EntrypointKind::Normal,
    }
}

fn function_name(function_node: &Value, entrypoint_kind: EntrypointKind) -> String {
    match entrypoint_kind {
        EntrypointKind::Constructor => "constructor".to_string(),
        EntrypointKind::Receive => "receive".to_string(),
        EntrypointKind::Fallback => "fallback".to_string(),
        EntrypointKind::Normal => function_node
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<anonymous>")
            .to_string(),
    }
}

fn visibility(function_node: &Value) -> Visibility {
    match function_node
        .get("visibility")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "external" => Visibility::External,
        "public" => Visibility::Public,
        "internal" => Visibility::Internal,
        "private" => Visibility::Private,
        _ => Visibility::Unknown,
    }
}

fn state_mutability(function_node: &Value) -> StateMutability {
    match function_node
        .get("stateMutability")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "pure" => StateMutability::Pure,
        "view" => StateMutability::View,
        "payable" => StateMutability::Payable,
        "nonpayable" => StateMutability::Nonpayable,
        _ => StateMutability::Unknown,
    }
}

fn ast_signature(function_node: &Value) -> Option<String> {
    let name = function_node.get("name").and_then(Value::as_str)?;
    let params = function_node
        .get("parameters")
        .and_then(|value| value.get("parameters"))
        .and_then(Value::as_array)
        .map(|params| {
            params
                .iter()
                .map(ast_param_type)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Some(format!("{name}({params})"))
}

fn ast_param_type(param: &Value) -> String {
    param
        .get("typeDescriptions")
        .and_then(|value| value.get("typeString"))
        .and_then(Value::as_str)
        .or_else(|| {
            param
                .get("typeName")
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
        })
        .unwrap_or("unknown")
        .replace(" storage pointer", "")
        .replace(" memory", "")
        .replace(" storage", "")
        .replace(" calldata", "")
}

#[derive(Debug, Clone)]
struct ModifierInvocation {
    name: String,
    role_argument: Option<String>,
}

fn modifier_invocations(function_node: &Value) -> Vec<ModifierInvocation> {
    let mut invocations = Vec::new();

    for modifier in function_node
        .get("modifiers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(name) = modifier
            .get("modifierName")
            .map(render_expression)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };

        let role_argument = modifier
            .get("arguments")
            .and_then(Value::as_array)
            .and_then(|arguments| arguments.first())
            .and_then(|arg| canonical_role_label(&render_expression(arg)));

        invocations.push(ModifierInvocation {
            name,
            role_argument,
        });
    }

    invocations
}

fn auth_signals_from_modifier_invocation(invocation: &ModifierInvocation) -> Vec<AuthSignal> {
    named_modifier_auth_signal(
        &invocation.name,
        invocation.role_argument.as_deref(),
        AuthSignalSource::ModifierInvocation,
    )
}

fn named_modifier_auth_signal(
    modifier_name: &str,
    role_argument: Option<&str>,
    source: AuthSignalSource,
) -> Vec<AuthSignal> {
    let mut signals = Vec::new();

    if modifier_name == "onlyOwner" {
        signals.push(AuthSignal {
            kind: AuthSignalKind::OnlyOwnerModifier,
            source,
            role: Some("owner".to_string()),
            evidence: format!("modifier {modifier_name}"),
            confidence: 0.99,
        });
        return signals;
    }

    if modifier_name == "onlyRole" {
        signals.push(AuthSignal {
            kind: AuthSignalKind::OnlyRoleModifier,
            source,
            role: role_argument.map(ToOwned::to_owned),
            evidence: match role_argument {
                Some(role) => format!("modifier {modifier_name}({role})"),
                None => format!("modifier {modifier_name}"),
            },
            confidence: if role_argument.is_some() { 0.98 } else { 0.9 },
        });
        return signals;
    }

    if is_named_role_modifier(modifier_name) {
        signals.push(AuthSignal {
            kind: AuthSignalKind::NamedModifier,
            source,
            role: canonical_role_label(modifier_name),
            evidence: format!("modifier {modifier_name}"),
            confidence: 0.86,
        });
    }

    signals
}

fn is_named_role_modifier(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let mentions_role = ["owner", "admin", "pauser", "upgrader"]
        .into_iter()
        .any(|needle| lower.contains(needle));
    let looks_like_gate =
        lower.contains("only") || lower.ends_with("guard") || lower.ends_with("auth");
    mentions_role && looks_like_gate
}

fn detect_auth_signals(node: &Value, source: AuthSignalSource) -> Vec<AuthSignal> {
    let mut signals = Vec::new();
    walk_nodes(node, &mut |candidate| {
        let Some(node_type) = candidate.get("nodeType").and_then(Value::as_str) else {
            return;
        };

        match node_type {
            "FunctionCall" => {
                if let Some(expression) = candidate.get("expression") {
                    let callee = render_expression(expression);
                    let base_name = callee.rsplit('.').next().unwrap_or(&callee);
                    if matches!(base_name, "hasRole" | "_checkRole") {
                        let role = candidate
                            .get("arguments")
                            .and_then(Value::as_array)
                            .and_then(|arguments| arguments.first())
                            .and_then(|arg| canonical_role_label(&render_expression(arg)));
                        signals.push(AuthSignal {
                            kind: AuthSignalKind::RoleCheck,
                            source: source.clone(),
                            role,
                            evidence: render_expression(candidate),
                            confidence: 0.97,
                        });
                    }
                }
            }
            "BinaryOperation" => {
                if let Some(operator) = candidate.get("operator").and_then(Value::as_str)
                    && matches!(operator, "==" | "!=")
                {
                    let left = candidate.get("leftExpression");
                    let right = candidate.get("rightExpression");
                    if let (Some(left), Some(right)) = (left, right) {
                        let owner_side = if is_msg_sender(left) {
                            ownerish_role(right)
                        } else if is_msg_sender(right) {
                            ownerish_role(left)
                        } else {
                            None
                        };

                        if let Some(role) = owner_side {
                            signals.push(AuthSignal {
                                kind: AuthSignalKind::OwnerCheck,
                                source: source.clone(),
                                role: Some(role),
                                evidence: render_expression(candidate),
                                confidence: 0.95,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    });

    signals
}

fn detect_call_targets(node: &Value) -> Vec<CallTarget> {
    let mut calls = Vec::new();

    walk_nodes(node, &mut |candidate| {
        if candidate.get("nodeType").and_then(Value::as_str) != Some("FunctionCall") {
            return;
        }

        let Some(expression) = candidate.get("expression") else {
            return;
        };
        let callable = match expression.get("nodeType").and_then(Value::as_str) {
            Some("FunctionCallOptions") => expression.get("expression").unwrap_or(expression),
            _ => expression,
        };
        let Some(member_name) = callable.get("memberName").and_then(Value::as_str) else {
            return;
        };

        let kind = match member_name {
            "call" => Some(CallKind::Call),
            "delegatecall" => Some(CallKind::DelegateCall),
            "staticcall" => Some(CallKind::StaticCall),
            "transfer" => Some(CallKind::Transfer),
            "send" => Some(CallKind::Send),
            _ => None,
        };

        if let Some(kind) = kind {
            let target = callable.get("expression").map(render_expression);
            calls.push(CallTarget {
                kind,
                target: target.filter(|value| !value.is_empty()),
                evidence: render_expression(candidate),
            });
        }
    });

    calls
}

fn walk_nodes<'a, F>(value: &'a Value, visit: &mut F)
where
    F: FnMut(&'a Value),
{
    match value {
        Value::Object(map) => {
            if map.contains_key("nodeType") {
                visit(value);
            }
            for child in map.values() {
                walk_nodes(child, visit);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_nodes(item, visit);
            }
        }
        _ => {}
    }
}

fn render_expression(value: &Value) -> String {
    match value.get("nodeType").and_then(Value::as_str) {
        Some("Identifier") => value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        Some("IdentifierPath") => value
            .get("name")
            .and_then(Value::as_str)
            .or_else(|| value.get("namePath").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string(),
        Some("MemberAccess") => {
            let base = value
                .get("expression")
                .map(render_expression)
                .unwrap_or_default();
            let member = value
                .get("memberName")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if base.is_empty() {
                member.to_string()
            } else {
                format!("{base}.{member}")
            }
        }
        Some("FunctionCall") => {
            let expression = value
                .get("expression")
                .map(render_expression)
                .unwrap_or_default();
            let args = value
                .get("arguments")
                .and_then(Value::as_array)
                .map(|arguments| {
                    arguments
                        .iter()
                        .map(render_expression)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            format!("{expression}({args})")
        }
        Some("Literal") => value
            .get("value")
            .and_then(Value::as_str)
            .or_else(|| value.get("hexValue").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string(),
        Some("BinaryOperation") => {
            let left = value
                .get("leftExpression")
                .map(render_expression)
                .unwrap_or_default();
            let operator = value
                .get("operator")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let right = value
                .get("rightExpression")
                .map(render_expression)
                .unwrap_or_default();
            format!("{left} {operator} {right}")
        }
        Some("TupleExpression") => value
            .get("components")
            .and_then(Value::as_array)
            .map(|components| {
                components
                    .iter()
                    .map(render_expression)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .map(|inner| format!("({inner})"))
            .unwrap_or_default(),
        Some("IndexAccess") => {
            let base = value
                .get("baseExpression")
                .map(render_expression)
                .unwrap_or_default();
            let index = value
                .get("indexExpression")
                .map(render_expression)
                .unwrap_or_default();
            format!("{base}[{index}]")
        }
        _ => value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

fn is_msg_sender(value: &Value) -> bool {
    match value.get("nodeType").and_then(Value::as_str) {
        Some("MemberAccess") => {
            value.get("memberName").and_then(Value::as_str) == Some("sender")
                && value
                    .get("expression")
                    .and_then(|expr| expr.get("name"))
                    .and_then(Value::as_str)
                    == Some("msg")
        }
        Some("FunctionCall") => value
            .get("expression")
            .and_then(|expr| expr.get("name"))
            .and_then(Value::as_str)
            .is_some_and(|name| matches!(name, "_msgSender" | "msgSender")),
        _ => false,
    }
}

fn ownerish_role(value: &Value) -> Option<String> {
    let rendered = render_expression(value);
    canonical_role_label(&rendered).filter(|role| {
        matches!(
            role.as_str(),
            "owner" | "admin" | "default_admin" | "pauser" | "upgrader"
        )
    })
}

fn canonical_role_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let stripped = trimmed
        .trim_end_matches("()")
        .trim_end_matches("_ROLE")
        .trim_start_matches("only");
    let mut out = String::new();
    let mut previous_was_sep = true;
    let chars = stripped.chars().collect::<Vec<_>>();

    for (index, ch) in chars.iter().copied().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !previous_was_sep {
                out.push('_');
            }
            previous_was_sep = true;
            continue;
        }

        let previous = index.checked_sub(1).and_then(|idx| chars.get(idx)).copied();
        let next = chars.get(index + 1).copied();
        let should_insert_sep = ch.is_ascii_uppercase()
            && !previous_was_sep
            && previous.is_some_and(|prev| prev.is_ascii_lowercase())
            && next.is_some_and(|next| next.is_ascii_lowercase());

        if should_insert_sep {
            out.push('_');
        }

        out.push(ch.to_ascii_lowercase());
        previous_was_sep = false;
    }

    let canonical = out.trim_matches('_').to_string();
    if canonical.is_empty() {
        return None;
    }

    if canonical.contains("owner") {
        return Some("owner".to_string());
    }
    if canonical == "default_admin_role" || canonical == "default_admin" {
        return Some("default_admin".to_string());
    }
    if canonical.contains("admin") {
        return Some("admin".to_string());
    }
    if canonical.contains("pauser") {
        return Some("pauser".to_string());
    }
    if canonical.contains("upgrader") {
        return Some("upgrader".to_string());
    }

    Some(canonical)
}

fn sort_and_dedup_auth_signals(signals: &mut Vec<AuthSignal>) {
    let mut seen = BTreeSet::new();
    signals.retain(|signal| {
        let key = (
            signal.kind.clone(),
            signal.source.clone(),
            signal.role.clone(),
            signal.evidence.clone(),
            format!("{:.4}", signal.confidence),
        );
        seen.insert(key)
    });
    signals.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.source.cmp(&right.source))
            .then(left.role.cmp(&right.role))
            .then(left.evidence.cmp(&right.evidence))
    });
}

fn sort_and_dedup_calls(calls: &mut Vec<CallTarget>) {
    let mut seen = BTreeSet::new();
    calls.retain(|call| {
        let key = (
            call.kind.clone(),
            call.target.clone(),
            call.evidence.clone(),
        );
        seen.insert(key)
    });
    calls.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.target.cmp(&right.target))
            .then(left.evidence.cmp(&right.evidence))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{aderyn::parse_report_str, artifacts::load_artifacts, project::FoundryProject};
    use std::{fs, path::PathBuf};

    fn fixture_project() -> FoundryProject {
        let repo_root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/foundry-simple-vault");
        FoundryProject {
            repo_root: repo_root.clone(),
            foundry_config_path: repo_root.join("foundry.toml"),
            src_dir: "src".to_string(),
            test_dir: "test".to_string(),
            script_dir: "script".to_string(),
            libs: vec!["lib".to_string()],
            artifact_dir: repo_root.join("out"),
            artifact_dir_relative: "out".to_string(),
        }
    }

    #[test]
    fn canonicalizes_role_labels_without_touching_path_case_rules() {
        assert_eq!(
            canonical_role_label("PAUSER_ROLE").as_deref(),
            Some("pauser")
        );
        assert_eq!(canonical_role_label("onlyOwner").as_deref(), Some("owner"));
        assert_eq!(
            canonical_role_label("DEFAULT_ADMIN_ROLE").as_deref(),
            Some("default_admin")
        );
    }

    #[test]
    fn treats_named_pause_guards_as_non_role_modifiers() {
        assert!(!is_named_role_modifier("whenNotPaused"));
        assert!(is_named_role_modifier("onlyPauser"));
    }

    #[test]
    fn builds_fixture_graph_with_detector_findings_kept_separate() {
        let project = fixture_project();
        let artifacts = load_artifacts(&project).unwrap();
        let report =
            fs::read_to_string(project.repo_root.join("testdata/aderyn-report.json")).unwrap();
        let detector_findings = parse_report_str(&report).unwrap();

        let graph = build_analysis_graph(&project, &artifacts, detector_findings).unwrap();

        assert_eq!(graph.contracts.len(), 1);
        assert_eq!(graph.detector_findings.len(), 3);
        assert!(
            graph
                .functions
                .iter()
                .any(
                    |function| function.signature.as_deref() == Some("upgradeTo(address)")
                        && !function.auth_signals.is_empty()
                )
        );
        assert!(
            graph
                .functions
                .iter()
                .any(
                    |function| function.signature.as_deref() == Some("withdrawFees(uint256)")
                        && !function.calls.is_empty()
                )
        );
    }
}
