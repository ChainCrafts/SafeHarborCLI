use manifest::{EvidenceType, InvariantKind, Severity};
use standards_recognizer::types::{SuggestionSeverity, TemplateEvidenceType};
use structural_extractor::StructuralInvariantKind;

#[derive(Debug, Clone, PartialEq)]
pub struct StructuralDefault {
    pub kind: InvariantKind,
    pub severity: Severity,
    pub evidence_types: Vec<EvidenceType>,
}

pub fn structural_default(kind: &StructuralInvariantKind) -> StructuralDefault {
    match kind {
        StructuralInvariantKind::AccessControlSurface => StructuralDefault {
            kind: InvariantKind::AccessControl,
            severity: Severity::Critical,
            evidence_types: vec![
                EvidenceType::SelectorAccessBreach,
                EvidenceType::Trace,
                EvidenceType::StateDiff,
            ],
        },
        StructuralInvariantKind::PauseControl => StructuralDefault {
            kind: InvariantKind::PauseControl,
            severity: Severity::High,
            evidence_types: vec![
                EvidenceType::Trace,
                EvidenceType::StateDiff,
                EvidenceType::ReproductionScript,
            ],
        },
        StructuralInvariantKind::UpgradeControl => StructuralDefault {
            kind: InvariantKind::UpgradeControl,
            severity: Severity::Critical,
            evidence_types: vec![
                EvidenceType::SelectorAccessBreach,
                EvidenceType::Trace,
                EvidenceType::StateDiff,
            ],
        },
        StructuralInvariantKind::FeeWithdrawalSurface => StructuralDefault {
            kind: InvariantKind::FeeBoundary,
            severity: Severity::Critical,
            evidence_types: vec![
                EvidenceType::Trace,
                EvidenceType::StateDiff,
                EvidenceType::BalanceDelta,
                EvidenceType::ReproductionScript,
            ],
        },
        StructuralInvariantKind::PayableEntrypoint => StructuralDefault {
            kind: InvariantKind::SelectorScope,
            severity: Severity::High,
            evidence_types: vec![
                EvidenceType::Trace,
                EvidenceType::StateDiff,
                EvidenceType::BalanceDelta,
            ],
        },
        StructuralInvariantKind::EmergencyStopSurface => StructuralDefault {
            kind: InvariantKind::PauseControl,
            severity: Severity::High,
            evidence_types: vec![EvidenceType::Trace, EvidenceType::StateDiff],
        },
        StructuralInvariantKind::ExternalCallSurface => StructuralDefault {
            kind: InvariantKind::ExternalDependency,
            severity: Severity::High,
            evidence_types: vec![EvidenceType::Trace, EvidenceType::StateDiff],
        },
    }
}

pub fn semantic_severity(severity: &SuggestionSeverity) -> Severity {
    match severity {
        SuggestionSeverity::Low => Severity::Low,
        SuggestionSeverity::Medium => Severity::Medium,
        SuggestionSeverity::High => Severity::High,
        SuggestionSeverity::Critical => Severity::Critical,
    }
}

pub fn semantic_evidence(evidence: &TemplateEvidenceType) -> EvidenceType {
    match evidence {
        TemplateEvidenceType::Trace => EvidenceType::Trace,
        TemplateEvidenceType::StateDiff => EvidenceType::StateDiff,
        TemplateEvidenceType::BalanceDelta => EvidenceType::BalanceDelta,
        TemplateEvidenceType::SelectorAccessBreach => EvidenceType::SelectorAccessBreach,
        TemplateEvidenceType::MultiTxSequence => EvidenceType::MultiTxSequence,
        TemplateEvidenceType::ReproductionScript => EvidenceType::ReproductionScript,
    }
}

pub fn semantic_kind(kind: &standards_recognizer::types::SemanticTemplateKind) -> InvariantKind {
    match kind {
        standards_recognizer::types::SemanticTemplateKind::AccessControl => {
            InvariantKind::AccessControl
        }
        standards_recognizer::types::SemanticTemplateKind::PauseControl => {
            InvariantKind::PauseControl
        }
        standards_recognizer::types::SemanticTemplateKind::UpgradeControl => {
            InvariantKind::UpgradeControl
        }
        standards_recognizer::types::SemanticTemplateKind::AssetAccounting => {
            InvariantKind::AssetAccounting
        }
        standards_recognizer::types::SemanticTemplateKind::Solvency => InvariantKind::Solvency,
        standards_recognizer::types::SemanticTemplateKind::MintBurnIntegrity => {
            InvariantKind::MintBurnIntegrity
        }
    }
}
