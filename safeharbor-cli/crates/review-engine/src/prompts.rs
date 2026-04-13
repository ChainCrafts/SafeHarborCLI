use crate::{
    types::{
        ReviewAction, ReviewDecision, ReviewEdits, ReviewItemKind, ReviewedAccessClassification,
    },
    view::ReviewItemView,
};
use anyhow::{Context, Result, bail};
use manifest::{AccessKind, EvidenceType, Severity};
use std::io::{self, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSummary {
    pub total_items: usize,
    pub approved_count: usize,
    pub rejected_count: usize,
    pub edited_count: usize,
    pub unresolved_count: usize,
}

pub trait ReviewPrompter {
    fn should_discard_stale_state(&mut self) -> Result<bool>;
    fn review_item(&mut self, item: &ReviewItemView) -> Result<ReviewDecision>;
    fn confirm_final(&mut self, summary: &ReviewSummary) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct ApproveDefaultsPrompter {
    reject_low_confidence_semantic_templates: bool,
    low_confidence_threshold: f64,
}

impl ApproveDefaultsPrompter {
    pub fn new() -> Self {
        Self {
            reject_low_confidence_semantic_templates: false,
            low_confidence_threshold: 0.75,
        }
    }

    pub fn reject_low_confidence_semantic_templates(mut self, threshold: u32) -> Self {
        self.reject_low_confidence_semantic_templates = true;
        self.low_confidence_threshold = f64::from(threshold) / 100.0;
        self
    }
}

impl Default for ApproveDefaultsPrompter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReviewPrompter for ApproveDefaultsPrompter {
    fn should_discard_stale_state(&mut self) -> Result<bool> {
        Ok(true)
    }

    fn review_item(&mut self, item: &ReviewItemView) -> Result<ReviewDecision> {
        if self.reject_low_confidence_semantic_templates
            && item.item_kind == ReviewItemKind::SemanticTemplate
            && item
                .source_confidence
                .is_some_and(|confidence| confidence < self.low_confidence_threshold)
        {
            return Ok(ReviewDecision {
                item_id: item.item_id.clone(),
                item_kind: item.item_kind.clone(),
                action: ReviewAction::Rejected,
                edits: None,
                reviewer_note: None,
                rejection_reason: Some(format!(
                    "rejected by low-confidence batch action below {:.2}",
                    self.low_confidence_threshold
                )),
            });
        }

        Ok(ReviewDecision {
            item_id: item.item_id.clone(),
            item_kind: item.item_kind.clone(),
            action: ReviewAction::Approved,
            edits: None,
            reviewer_note: None,
            rejection_reason: None,
        })
    }

    fn confirm_final(&mut self, summary: &ReviewSummary) -> Result<bool> {
        Ok(summary.unresolved_count == 0)
    }
}

#[derive(Debug, Default)]
pub struct TerminalReviewPrompter;

impl TerminalReviewPrompter {
    pub fn new() -> Self {
        Self
    }
}

impl ReviewPrompter for TerminalReviewPrompter {
    fn should_discard_stale_state(&mut self) -> Result<bool> {
        prompt_bool(
            "Existing review state does not match current inputs. Discard it?",
            false,
        )
    }

    fn review_item(&mut self, item: &ReviewItemView) -> Result<ReviewDecision> {
        print_item(item);
        loop {
            let action = prompt_line("Action [a]pprove, [r]eject, [e]dit")?;
            match action.trim().to_ascii_lowercase().as_str() {
                "a" | "approve" => {
                    let note = prompt_optional("Reviewer note")?;
                    return Ok(ReviewDecision {
                        item_id: item.item_id.clone(),
                        item_kind: item.item_kind.clone(),
                        action: ReviewAction::Approved,
                        edits: None,
                        reviewer_note: note,
                        rejection_reason: None,
                    });
                }
                "r" | "reject" => {
                    let reason = prompt_optional("Rejection reason")?;
                    return Ok(ReviewDecision {
                        item_id: item.item_id.clone(),
                        item_kind: item.item_kind.clone(),
                        action: ReviewAction::Rejected,
                        edits: None,
                        reviewer_note: None,
                        rejection_reason: reason,
                    });
                }
                "e" | "edit" => {
                    let edits = edit_item(item)?;
                    let note = prompt_optional("Reviewer note")?;
                    return Ok(ReviewDecision {
                        item_id: item.item_id.clone(),
                        item_kind: item.item_kind.clone(),
                        action: ReviewAction::Edited,
                        edits: Some(edits),
                        reviewer_note: note,
                        rejection_reason: None,
                    });
                }
                _ => println!("Enter approve, reject, or edit."),
            }
        }
    }

    fn confirm_final(&mut self, summary: &ReviewSummary) -> Result<bool> {
        println!();
        println!("Review summary");
        println!("  total     : {}", summary.total_items);
        println!("  approved  : {}", summary.approved_count);
        println!("  rejected  : {}", summary.rejected_count);
        println!("  edited    : {}", summary.edited_count);
        println!("  unresolved: {}", summary.unresolved_count);
        if summary.unresolved_count != 0 {
            return Ok(false);
        }
        prompt_bool("Write reviewed input?", true)
    }
}

fn print_item(item: &ReviewItemView) {
    println!();
    println!("{} ({:?})", item.title, item.item_kind);
    println!("  id: {}", item.item_id);
    if let Some(contract_id) = &item.manifest_contract_id {
        println!("  manifest contract: {contract_id}");
    }
    if let Some(source_id) = &item.source_contract_id {
        println!("  source contract  : {source_id}");
    }
    if let Some(confidence) = item.source_confidence {
        println!("  confidence       : {confidence:.2}");
    }
    if !item.description.is_empty() {
        println!("  description      : {}", item.description);
    }
    if let Some(rationale) = &item.source_rationale {
        println!("  rationale        : {rationale}");
    }
    if let Some(severity) = &item.default_severity {
        println!("  default severity : {:?}", severity);
    }
    if !item.default_evidence.is_empty() {
        println!(
            "  default evidence : {}",
            render_evidence(&item.default_evidence)
        );
    }
}

fn edit_item(item: &ReviewItemView) -> Result<ReviewEdits> {
    let mut edits = ReviewEdits::default();
    if item.editable_fields.scope {
        edits.in_scope = Some(prompt_bool(
            "Mark in scope?",
            item.default_in_scope.unwrap_or(true),
        )?);
        if edits.in_scope == Some(false) {
            edits.out_of_scope_reason = prompt_optional("Out-of-scope reason")?;
        }
    }
    if item.editable_fields.access {
        edits.reviewed_access_classification = Some(prompt_access(item.default_access.as_ref())?);
    }
    if item.editable_fields.role_id {
        let default = item.default_role_id.clone().unwrap_or_default();
        let value = prompt_line_with_default("Reviewed role id", &default)?;
        if !value.trim().is_empty() {
            edits.reviewed_role_id = Some(value.trim().to_string());
        }
    }
    if item.editable_fields.severity {
        edits.severity = Some(prompt_severity(item.default_severity.as_ref())?);
    }
    if item.editable_fields.evidence {
        edits.evidence_types = prompt_evidence(&item.default_evidence)?;
    }
    if item.editable_fields.label {
        edits.reviewed_label = prompt_optional("Reviewed label")?;
    }
    if item.editable_fields.summary {
        edits.reviewed_summary = prompt_optional("Reviewed summary")?;
    }
    Ok(edits)
}

fn prompt_access(
    default: Option<&ReviewedAccessClassification>,
) -> Result<ReviewedAccessClassification> {
    let default_kind = default
        .map(|access| format!("{:?}", access.kind).to_ascii_lowercase())
        .unwrap_or_else(|| "permissionless".to_string());
    let kind = loop {
        let raw = prompt_line_with_default(
            "Access kind [permissionless|role_gated|unknown]",
            &default_kind,
        )?;
        match raw.trim() {
            "permissionless" => break AccessKind::Permissionless,
            "role_gated" => break AccessKind::RoleGated,
            "unknown" => break AccessKind::Unknown,
            _ => println!("Use permissionless, role_gated, or unknown."),
        }
    };
    let required_role_ids = if kind == AccessKind::RoleGated {
        let default_roles = default
            .map(|access| access.required_role_ids.join(","))
            .unwrap_or_default();
        prompt_line_with_default("Required role ids (comma-separated)", &default_roles)?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect()
    } else {
        Vec::new()
    };
    Ok(ReviewedAccessClassification {
        kind,
        required_role_ids,
    })
}

fn prompt_severity(default: Option<&Severity>) -> Result<Severity> {
    let default = default
        .map(|severity| format!("{:?}", severity).to_ascii_lowercase())
        .unwrap_or_else(|| "medium".to_string());
    loop {
        let raw = prompt_line_with_default("Severity [low|medium|high|critical]", &default)?;
        match raw.trim() {
            "low" => return Ok(Severity::Low),
            "medium" => return Ok(Severity::Medium),
            "high" => return Ok(Severity::High),
            "critical" => return Ok(Severity::Critical),
            _ => println!("Use low, medium, high, or critical."),
        }
    }
}

fn prompt_evidence(default: &[EvidenceType]) -> Result<Vec<EvidenceType>> {
    let default = render_evidence(default);
    loop {
        let raw = prompt_line_with_default(
            "Evidence types (comma-separated)",
            if default.is_empty() {
                "trace"
            } else {
                &default
            },
        )?;
        let mut parsed = Vec::new();
        let mut failed = None;
        for part in raw
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            match parse_evidence(part) {
                Ok(evidence) => parsed.push(evidence),
                Err(_) => {
                    failed = Some(part.to_string());
                    break;
                }
            }
        }
        if let Some(failed) = failed {
            println!("Unknown evidence type: {failed}");
            continue;
        }
        if parsed.is_empty() {
            println!("Choose at least one evidence type.");
            continue;
        }
        return Ok(parsed);
    }
}

fn parse_evidence(value: &str) -> Result<EvidenceType> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .with_context(|| format!("failed to parse evidence type: {value}"))
}

fn render_evidence(values: &[EvidenceType]) -> String {
    values
        .iter()
        .map(|value| {
            serde_json::to_value(value)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn prompt_bool(prompt: &str, default: bool) -> Result<bool> {
    loop {
        let suffix = if default { "Y/n" } else { "y/N" };
        let raw = prompt_line(&format!("{prompt} [{suffix}]"))?;
        let value = raw.trim().to_ascii_lowercase();
        if value.is_empty() {
            return Ok(default);
        }
        match value.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Enter yes or no."),
        }
    }
}

fn prompt_optional(prompt: &str) -> Result<Option<String>> {
    let raw = prompt_line(&format!("{prompt} (blank to skip)"))?;
    let trimmed = raw.trim();
    Ok(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    })
}

fn prompt_line_with_default(prompt: &str, default: &str) -> Result<String> {
    let raw = prompt_line(&format!("{prompt} [{default}]"))?;
    if raw.trim().is_empty() {
        Ok(default.to_string())
    } else {
        Ok(raw)
    }
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}: ");
    io::stdout().flush()?;
    let mut input = String::new();
    let read = io::stdin().read_line(&mut input)?;
    if read == 0 {
        bail!("interactive review input ended unexpectedly");
    }
    Ok(input.trim_end().to_string())
}
