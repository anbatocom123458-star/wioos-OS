//! Update Center, Backup & Recovery and Driver Manager architecture.
//!
//! All three subsystems are interface-only in this phase: they report their
//! real state (`not_implemented` / `planned`) and list no fake content.

use std::path::Path;

use serde::Serialize;

use crate::status::{ComponentState, ComponentStatus};

/// Update categories the Update Center will manage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCategory {
    Os,
    Drivers,
    Apps,
    Packages,
}

impl UpdateCategory {
    /// Stable id.
    pub fn id(self) -> &'static str {
        match self {
            UpdateCategory::Os => "os",
            UpdateCategory::Drivers => "drivers",
            UpdateCategory::Apps => "apps",
            UpdateCategory::Packages => "packages",
        }
    }
}

/// Status of one update category.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateCategoryStatus {
    pub category: UpdateCategory,
    /// No update channel is configured in this phase.
    pub channel: Option<String>,
    pub last_checked: Option<String>,
    pub status: ComponentStatus,
}

/// Update Center report.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateCenterReport {
    pub categories: Vec<UpdateCategoryStatus>,
    pub staged_rollout: ComponentStatus,
    pub rollback: ComponentStatus,
    pub failed_update_recovery: ComponentStatus,
    pub signature_verification: ComponentStatus,
}

/// Build the Update Center report.
pub fn update_report() -> UpdateCenterReport {
    let categories = [
        UpdateCategory::Os,
        UpdateCategory::Drivers,
        UpdateCategory::Apps,
        UpdateCategory::Packages,
    ]
    .into_iter()
    .map(|category| UpdateCategoryStatus {
        category,
        channel: None,
        last_checked: None,
        status: ComponentStatus::not_implemented(
            format!("update-{}", category.id()),
            format!("{} updates", category.id()),
            "no update service or channel is configured in this phase",
        ),
    })
    .collect();
    UpdateCenterReport {
        categories,
        staged_rollout: ComponentStatus::planned(
            "staged-rollout",
            "Staged updates",
            "staged update delivery is planned with the update service",
        ),
        rollback: ComponentStatus::planned(
            "update-rollback",
            "Update rollback",
            "rollback needs snapshot support from Backup & Recovery",
        ),
        failed_update_recovery: ComponentStatus::planned(
            "update-recovery",
            "Failed update recovery",
            "recovery mode requires boot-level control that does not exist yet",
        ),
        signature_verification: ComponentStatus::not_implemented(
            "update-signature",
            "Update signature verification",
            "no signature scheme exists yet; packages only carry sha256 checksums",
        ),
    }
}

/// One existing snapshot on disk.
#[derive(Clone, Debug, Serialize)]
pub struct SnapshotInfo {
    pub id: String,
    pub size_bytes: u64,
    pub created_unix: Option<u64>,
}

/// Backup & Recovery report. Snapshots are listed from disk (honestly empty
/// when none exist); restore/reset stay unimplemented.
#[derive(Clone, Debug, Serialize)]
pub struct BackupReport {
    pub snapshots: Vec<SnapshotInfo>,
    pub restore: ComponentStatus,
    pub system_repair: ComponentStatus,
    pub safe_mode: ComponentStatus,
    pub reset: ComponentStatus,
}

/// Build the Backup & Recovery report for a state directory.
pub fn backup_report(state_dir: &Path) -> BackupReport {
    let snapshots_dir = state_dir.join("snapshots");
    let mut snapshots = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&snapshots_dir) {
        for entry in entries.flatten() {
            let metadata = entry.metadata().ok();
            snapshots.push(SnapshotInfo {
                id: entry.file_name().to_string_lossy().into_owned(),
                size_bytes: metadata.as_ref().map(|data| data.len()).unwrap_or(0),
                created_unix: metadata
                    .and_then(|data| data.modified().ok())
                    .and_then(|time| {
                        time.duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|duration| duration.as_secs())
                    }),
            });
        }
    }
    snapshots.sort_by(|a, b| a.id.cmp(&b.id));
    BackupReport {
        snapshots,
        restore: ComponentStatus::not_implemented(
            "backup-restore",
            "Restore",
            "snapshot creation and restore are not implemented yet",
        ),
        system_repair: ComponentStatus::planned(
            "system-repair",
            "System repair",
            "repair needs boot-level control that does not exist yet",
        ),
        safe_mode: ComponentStatus::planned(
            "safe-mode",
            "Safe mode",
            "safe mode requires a boot environment, planned with native boot",
        ),
        reset: ComponentStatus::not_implemented(
            "factory-reset",
            "Reset",
            "destructive reset is intentionally unimplemented until a real \
             safety confirmation flow and backend exist",
        ),
    }
}
/// One driver category the Driver Manager will cover.
#[derive(Clone, Debug, Serialize)]
pub struct DriverCategory {
    pub name: String,
    pub required: bool,
    pub status: ComponentState,
}

/// Driver Manager report (architecture only; no hardware detection or driver
/// packages exist in this phase).
#[derive(Clone, Debug, Serialize)]
pub struct DriverReport {
    pub detection: ComponentStatus,
    pub categories: Vec<DriverCategory>,
    pub install_pipeline: Vec<String>,
    pub note: String,
}

/// Build the Driver Manager report.
pub fn driver_report() -> DriverReport {
    let category = |name: &str, required: bool| DriverCategory {
        name: name.to_owned(),
        required,
        status: ComponentState::Planned {
            reason: "hardware detection and the official driver package source \
                     are not configured in this phase"
                .to_owned(),
        },
    };
    DriverReport {
        detection: ComponentStatus::not_implemented(
            "hardware-detection",
            "Hardware detection",
            "no hardware enumeration backend exists in this runtime",
        ),
        categories: vec![
            category("Wi-Fi", true),
            category("Ethernet", true),
            category("Storage", true),
            category("USB", true),
            category("Display", true),
            category("Keyboard", true),
            category("Touchscreen", false),
            category("Audio", false),
            category("Bluetooth", false),
            category("Camera", false),
            category("GPU", false),
        ],
        install_pipeline: vec![
            "detect hardware".to_owned(),
            "find compatible driver".to_owned(),
            "download official driver".to_owned(),
            "verify signature and checksum".to_owned(),
            "install".to_owned(),
            "load".to_owned(),
            "report status".to_owned(),
        ],
        note: "Drivers will only come from the official WIOOS driver package \
               source with licence, copyright and provenance metadata preserved. \
               Random drivers from the internet are never fetched."
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_report_lists_all_categories_without_fake_channels() {
        let report = update_report();
        assert_eq!(report.categories.len(), 4);
        for category in &report.categories {
            assert!(category.channel.is_none());
            assert!(category.last_checked.is_none());
            assert!(!category.status.is_operational());
        }
        assert!(matches!(
            report.rollback.state,
            ComponentState::Planned { .. }
        ));
        assert!(!report.signature_verification.is_operational());
    }

    #[test]
    fn backup_report_lists_real_snapshots_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = backup_report(dir.path());
        assert!(report.snapshots.is_empty());
        assert!(!report.restore.is_operational());
        assert!(!report.reset.is_operational());

        std::fs::create_dir_all(dir.path().join("snapshots/one")).expect("mkdir");
        let report = backup_report(dir.path());
        assert_eq!(report.snapshots.len(), 1);
        assert_eq!(report.snapshots[0].id, "one");
    }

    #[test]
    fn driver_report_is_architecture_only() {
        let report = driver_report();
        assert!(!report.detection.is_operational());
        assert_eq!(report.categories.len(), 11);
        assert!(report.categories.iter().all(|category| matches!(
            category.status,
            ComponentState::Planned { .. }
        )));
        assert_eq!(report.install_pipeline.len(), 7);
        assert!(!report.note.is_empty());
    }
}
