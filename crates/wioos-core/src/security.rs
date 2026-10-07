//! Security architecture: permission policy, package security gate and the
//! Security Center status report.
//!
//! This module only reports checks it actually performs. There is no malware
//! scanning engine in WIOOS yet, so threat scanning is always reported as
//! `not_implemented` and no threat counts are ever displayed.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    fsutil,
    permission::{Permission, analyze},
    status::ComponentStatus,
};

/// Where a package comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageSource {
    /// Official WIOOS store registry.
    Registry,
    /// A local `.wio` file chosen by the user.
    LocalFile,
    /// An external/unmanaged source.
    External,
}

impl PackageSource {
    /// Stable id.
    pub fn id(self) -> &'static str {
        match self {
            PackageSource::Registry => "registry",
            PackageSource::LocalFile => "local_file",
            PackageSource::External => "external",
        }
    }
}

/// Outcome of the integrity (checksum) check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum IntegrityCheck {
    Valid { algorithm: String, digest: String },
    Mismatch { expected: String, actual: String },
    Missing,
}

/// Outcome of the signature check. WIOOS has no signature scheme yet, so in
/// this phase every package is `absent`; the variants document the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum SignatureCheck {
    Valid { signer: String },
    Absent,
    Invalid { reason: String },
}

/// Classification of a package after analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Trusted,
    Unverified,
    Dangerous,
}

/// The gate decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    RequireConfirmation,
    Block,
}
/// Everything the gate knows about one installation attempt.
#[derive(Clone, Debug)]
pub struct GateInput {
    pub source: PackageSource,
    pub manifest_valid: bool,
    pub integrity: IntegrityCheck,
    pub signature: SignatureCheck,
    pub permissions: Vec<Permission>,
    /// The user explicitly confirmed the install (e.g. `--yes`).
    pub user_confirmed: bool,
    /// Developer/Advanced mode allows dangerous permissions with a warning.
    pub developer_mode: bool,
    /// Always false in this phase: no engine exists.
    pub threat_scanner_available: bool,
    /// Always false in this phase: no sandbox runner exists.
    pub sandbox_available: bool,
}

impl Default for GateInput {
    fn default() -> Self {
        Self {
            source: PackageSource::LocalFile,
            manifest_valid: false,
            integrity: IntegrityCheck::Missing,
            signature: SignatureCheck::Absent,
            permissions: Vec::new(),
            user_confirmed: false,
            developer_mode: false,
            threat_scanner_available: false,
            sandbox_available: false,
        }
    }
}

/// Status of one pipeline stage.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StageStatus {
    Completed { outcome: String },
    /// The stage could not be evaluated; never reported as a pass.
    NotEvaluated { reason: String },
}

/// One stage of the external-app security pipeline.
#[derive(Clone, Debug, Serialize)]
pub struct StageResult {
    pub stage: String,
    #[serde(flatten)]
    pub status: StageStatus,
}

/// Result of the security gate.
#[derive(Clone, Debug, Serialize)]
pub struct GateReport {
    pub classification: Classification,
    pub decision: Decision,
    pub stages: Vec<StageResult>,
    pub reasons: Vec<String>,
    pub permission_analysis: crate::permission::PermissionAnalysis,
    pub warnings: Vec<String>,
}
/// Run the external package security gate.
///
/// Pipeline: manifest validation, integrity, signature, source, permission
/// analysis, threat scan, sandbox test, user confirmation. Stages without a
/// backend are reported `not_evaluated` — never as a pass.
pub fn evaluate(input: &GateInput) -> GateReport {
    let analysis = analyze(&input.permissions);
    let mut block_reasons: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut stages: Vec<StageResult> = Vec::new();

    // 1. Manifest validation.
    stages.push(StageResult {
        stage: "manifest_validation".to_owned(),
        status: if input.manifest_valid {
            StageStatus::Completed {
                outcome: "manifest parsed and validated".to_owned(),
            }
        } else {
            block_reasons.push("manifest validation failed".to_owned());
            StageStatus::Completed {
                outcome: "manifest invalid".to_owned(),
            }
        },
    });

    // 2. Integrity (checksum) check.
    let integrity_stage = match &input.integrity {
        IntegrityCheck::Valid { algorithm, digest } => StageStatus::Completed {
            outcome: format!("{algorithm} checksum verified ({digest})"),
        },
        IntegrityCheck::Mismatch { expected, actual } => {
            block_reasons
                .push("payload checksum mismatch (package tampered or corrupted)".to_owned());
            StageStatus::Completed {
                outcome: format!("mismatch: expected {expected}, got {actual}"),
            }
        }
        IntegrityCheck::Missing => {
            block_reasons.push("package has no integrity metadata".to_owned());
            StageStatus::Completed {
                outcome: "missing checksums".to_owned(),
            }
        }
    };
    stages.push(StageResult {
        stage: "integrity_check".to_owned(),
        status: integrity_stage,
    });

    // 3. Signature check.
    let signature_valid = matches!(input.signature, SignatureCheck::Valid { .. });
    let signature_stage = match &input.signature {
        SignatureCheck::Valid { signer } => StageStatus::Completed {
            outcome: format!("signed by {signer}"),
        },
        SignatureCheck::Absent => StageStatus::Completed {
            outcome: "unsigned package".to_owned(),
        },
        SignatureCheck::Invalid { reason } => {
            block_reasons.push(format!("signature invalid: {reason}"));
            StageStatus::Completed {
                outcome: "invalid signature".to_owned(),
            }
        }
    };
    stages.push(StageResult {
        stage: "signature_check".to_owned(),
        status: signature_stage,
    });

    // 4. Source check.
    stages.push(StageResult {
        stage: "source_check".to_owned(),
        status: StageStatus::Completed {
            outcome: format!("source: {}", input.source.id()),
        },
    });

    // 5. Permission analysis.
    let dangerous = !analysis.dangerous.is_empty();
    let dangerous_labels = analysis
        .dangerous
        .iter()
        .map(|permission| permission.label())
        .collect::<Vec<_>>()
        .join(", ");
    if dangerous {
        if input.developer_mode {
            warnings.push(format!(
                "Developer mode override accepted dangerous permissions: {dangerous_labels}"
            ));
        } else {
            block_reasons
                .push(format!("dangerous permissions blocked by default: {dangerous_labels}"));
        }
    }
    stages.push(StageResult {
        stage: "permission_analysis".to_owned(),
        status: StageStatus::Completed {
            outcome: format!(
                "risk {:?}, {} permission(s) requested",
                analysis.risk,
                analysis.requested.len()
            ),
        },
    });
    // 6. Threat scan (no engine exists).
    stages.push(StageResult {
        stage: "threat_scan".to_owned(),
        status: if input.threat_scanner_available {
            StageStatus::Completed {
                outcome: "scanned".to_owned(),
            }
        } else {
            StageStatus::NotEvaluated {
                reason: "no malware scanning engine is implemented in WIOOS; \
                         no threat count is reported"
                    .to_owned(),
            }
        },
    });

    // 7. Sandbox test (no runner exists).
    stages.push(StageResult {
        stage: "sandbox_test".to_owned(),
        status: if input.sandbox_available {
            StageStatus::Completed {
                outcome: "sandboxed".to_owned(),
            }
        } else {
            StageStatus::NotEvaluated {
                reason: "no sandbox runner is implemented in WIOOS yet".to_owned(),
            }
        },
    });

    // 8. User confirmation.
    let needs_confirmation = !input.user_confirmed && (!signature_valid || dangerous);
    stages.push(StageResult {
        stage: "user_confirmation".to_owned(),
        status: StageStatus::Completed {
            outcome: if input.user_confirmed {
                "confirmed by user".to_owned()
            } else if needs_confirmation {
                "confirmation required".to_owned()
            } else {
                "not required".to_owned()
            },
        },
    });

    let decision = if !block_reasons.is_empty() {
        Decision::Block
    } else if needs_confirmation {
        Decision::RequireConfirmation
    } else {
        Decision::Allow
    };

    let classification = if dangerous
        || matches!(input.integrity, IntegrityCheck::Mismatch { .. })
    {
        Classification::Dangerous
    } else if signature_valid && input.source == PackageSource::Registry {
        Classification::Trusted
    } else {
        Classification::Unverified
    };

    GateReport {
        classification,
        decision,
        stages,
        reasons: block_reasons,
        permission_analysis: analysis,
        warnings,
    }
}
/// One security-relevant event written to the security log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// RFC3339 timestamp.
    pub time: String,
    /// Event kind, e.g. `package_gate`, `permission_denied`.
    pub kind: String,
    /// What the event is about (package name, permission id, ...).
    pub subject: String,
    /// Outcome string, e.g. `blocked`, `allowed`.
    pub outcome: String,
    pub detail: String,
}

impl SecurityEvent {
    /// Build an event with the current UTC timestamp.
    pub fn now(
        kind: impl Into<String>,
        subject: impl Into<String>,
        outcome: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        use time::{OffsetDateTime, format_description::well_known::Rfc3339};
        Self {
            time: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unavailable".to_owned()),
            kind: kind.into(),
            subject: subject.into(),
            outcome: outcome.into(),
            detail: detail.into(),
        }
    }
}

/// JSONL-backed security log (append + read).
#[derive(Clone, Debug)]
pub struct SecurityLog {
    path: std::path::PathBuf,
}

impl SecurityLog {
    /// Open the log at `path`.
    pub fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }

    /// Append an event.
    pub fn append(&self, event: &SecurityEvent) -> Result<(), String> {
        fsutil::append_json_line(&self.path, event)
            .map_err(|error| format!("could not write security log: {error}"))
    }

    /// Read the most recent events (newest last), capped at `limit`.
    pub fn recent(&self, limit: usize) -> Vec<SecurityEvent> {
        let Ok(contents) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let events: Vec<SecurityEvent> = contents
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let limit = limit.clamp(1, 500);
        let start = events.len().saturating_sub(limit);
        events[start..].to_vec()
    }

    /// The log path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Security Center component report: only real backends are operational.
pub fn center_report() -> Vec<ComponentStatus> {
    vec![
        ComponentStatus::operational("security-logs", "Security Logs")
            .with_note("package gate decisions and permission events are recorded"),
        ComponentStatus::operational("permission-manager", "Permission Manager")
            .with_note("manifest permissions are parsed, classified and enforced at install time"),
        ComponentStatus::operational("package-integrity", "Package Integrity")
            .with_note("sha256 payload checksums are verified before installation"),
        ComponentStatus::not_implemented(
            "threat-scanner",
            "Threat Scanner",
            "no malware scanning engine exists; WIOOS never displays threat counts",
        ),
        ComponentStatus::not_implemented(
            "sandbox",
            "App Sandbox",
            "no sandbox runner exists yet; installed apps run unsandboxed",
        ),
        ComponentStatus::not_implemented(
            "firewall",
            "Firewall",
            "no packet filtering backend exists in this runtime",
        ),
        ComponentStatus::not_implemented(
            "network-protection",
            "Network Protection",
            "requires the firewall and DNS filtering backends, neither implemented",
        ),
        ComponentStatus::not_implemented(
            "system-integrity",
            "System Integrity",
            "no measured boot or file integrity baseline exists in this phase",
        ),
        ComponentStatus::planned(
            "secure-storage",
            "Secure Storage",
            "encrypted credential storage is planned; no keystore backend exists yet",
        ),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;

    fn base_input() -> GateInput {
        GateInput {
            source: PackageSource::LocalFile,
            manifest_valid: true,
            integrity: IntegrityCheck::Valid {
                algorithm: "sha256".to_owned(),
                digest: "ab12".to_owned(),
            },
            signature: SignatureCheck::Absent,
            permissions: vec![Permission::Network],
            ..GateInput::default()
        }
    }

    #[test]
    fn unsigned_package_requires_confirmation_then_allows() {
        let report = evaluate(&base_input());
        assert_eq!(report.classification, Classification::Unverified);
        assert_eq!(report.decision, Decision::RequireConfirmation);

        let confirmed = evaluate(&GateInput {
            user_confirmed: true,
            ..base_input()
        });
        assert_eq!(confirmed.decision, Decision::Allow);

        let threat_stage = confirmed
            .stages
            .iter()
            .find(|stage| stage.stage == "threat_scan")
            .expect("threat stage");
        assert!(matches!(
            threat_stage.status,
            StageStatus::NotEvaluated { .. }
        ));
    }

    #[test]
    fn trusted_requires_signature_and_registry_source() {
        let report = evaluate(&GateInput {
            source: PackageSource::Registry,
            signature: SignatureCheck::Valid {
                signer: "wioos-official".to_owned(),
            },
            ..base_input()
        });
        assert_eq!(report.classification, Classification::Trusted);
        assert_eq!(report.decision, Decision::Allow);
    }

    #[test]
    fn dangerous_permissions_block_without_developer_mode() {
        let input = GateInput {
            permissions: vec![Permission::Network, Permission::RawDisk],
            ..base_input()
        };
        let blocked = evaluate(&input);
        assert_eq!(blocked.decision, Decision::Block);
        assert_eq!(blocked.classification, Classification::Dangerous);
        assert!(!blocked.reasons.is_empty());

        // Developer mode downgrades to confirmation with a clear warning.
        let override_report = evaluate(&GateInput {
            developer_mode: true,
            user_confirmed: true,
            ..input.clone()
        });
        assert_eq!(override_report.decision, Decision::Allow);
        assert!(
            override_report
                .warnings
                .iter()
                .any(|warning| warning.contains("Developer mode"))
        );

        // Without developer mode, confirmation never overrides the block.
        let still_blocked = evaluate(&GateInput {
            user_confirmed: true,
            ..input
        });
        assert_eq!(still_blocked.decision, Decision::Block);
    }

    #[test]
    fn integrity_failures_block() {
        let report = evaluate(&GateInput {
            integrity: IntegrityCheck::Mismatch {
                expected: "aa".to_owned(),
                actual: "bb".to_owned(),
            },
            user_confirmed: true,
            ..base_input()
        });
        assert_eq!(report.decision, Decision::Block);
        assert_eq!(report.classification, Classification::Dangerous);

        let missing = evaluate(&GateInput {
            integrity: IntegrityCheck::Missing,
            user_confirmed: true,
            ..base_input()
        });
        assert_eq!(missing.decision, Decision::Block);
    }

    #[test]
    fn invalid_manifest_blocks() {
        let report = evaluate(&GateInput {
            manifest_valid: false,
            user_confirmed: true,
            ..base_input()
        });
        assert_eq!(report.decision, Decision::Block);
        assert!(report
            .stages
            .iter()
            .any(|stage| stage.stage == "manifest_validation"));
    }

    #[test]
    fn center_report_never_claims_scanning() {
        let report = center_report();
        let threat = report
            .iter()
            .find(|component| component.id == "threat-scanner")
            .expect("threat scanner entry");
        assert!(!threat.is_operational());
        assert_eq!(threat.state.id(), "not_implemented");
        assert!(report.iter().any(|component| component.id == "firewall"));
        assert!(report.iter().any(|component| component.id == "security-logs"));
    }

    #[test]
    fn security_log_appends_and_reads_recent_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = SecurityLog::new(dir.path().join("security-log.jsonl"));
        for index in 0..3 {
            log.append(&SecurityEvent::now(
                "package_gate",
                format!("app-{index}"),
                "allowed",
                "test event",
            ))
            .expect("append");
        }
        let recent = log.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[1].subject, "app-2");
        assert!(recent[0].time.contains('T'));
    }
}
