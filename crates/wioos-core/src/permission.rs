//! The WIOOS permission model.
//!
//! Permissions are declared in app manifests, analysed by the security gate
//! and shown by the App Manager. Dangerous permissions are blocked by default
//! for externally sourced packages.

use serde::{Deserialize, Serialize};

/// A permission an application can request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Open outbound network connections.
    Network,
    /// Read files inside the app sandbox / shared storage areas.
    StorageRead,
    /// Write files inside the app sandbox / shared storage areas.
    StorageWrite,
    /// Post notifications through the WIO notification service.
    Notifications,
    /// Access device location (no location backend exists yet).
    Location,
    /// Capture camera video/images (no camera backend exists yet).
    Camera,
    /// Capture microphone audio (no audio backend exists yet).
    Microphone,
    /// Spawn child processes.
    ProcessSpawn,
    /// Stop/restart other processes.
    ProcessControl,
    /// Talk to other WIO applications.
    InterAppCommunication,
    /// Raw block-device access. Dangerous.
    RawDisk,
    /// Kernel-level access. Dangerous.
    KernelAccess,
    /// Install or load drivers. Dangerous.
    DriverInstall,
    /// Modify system files or OS configuration. Dangerous.
    SystemModification,
}

impl Permission {
    /// Every permission, for documentation and UI tables.
    pub const ALL: [Permission; 14] = [
        Permission::Network,
        Permission::StorageRead,
        Permission::StorageWrite,
        Permission::Notifications,
        Permission::Location,
        Permission::Camera,
        Permission::Microphone,
        Permission::ProcessSpawn,
        Permission::ProcessControl,
        Permission::InterAppCommunication,
        Permission::RawDisk,
        Permission::KernelAccess,
        Permission::DriverInstall,
        Permission::SystemModification,
    ];

    /// Permissions that are blocked by default for external packages.
    pub const DANGEROUS: [Permission; 4] = [
        Permission::RawDisk,
        Permission::KernelAccess,
        Permission::DriverInstall,
        Permission::SystemModification,
    ];

    /// Dangerous permissions require Developer/Advanced mode to override.
    pub fn is_dangerous(self) -> bool {
        Self::DANGEROUS.contains(&self)
    }

    /// Stable id used in manifests and UI.
    pub fn id(self) -> &'static str {
        match self {
            Permission::Network => "network",
            Permission::StorageRead => "storage_read",
            Permission::StorageWrite => "storage_write",
            Permission::Notifications => "notifications",
            Permission::Location => "location",
            Permission::Camera => "camera",
            Permission::Microphone => "microphone",
            Permission::ProcessSpawn => "process_spawn",
            Permission::ProcessControl => "process_control",
            Permission::InterAppCommunication => "inter_app_communication",
            Permission::RawDisk => "raw_disk",
            Permission::KernelAccess => "kernel_access",
            Permission::DriverInstall => "driver_install",
            Permission::SystemModification => "system_modification",
        }
    }

    /// Human readable label (English, no icons).
    pub fn label(self) -> &'static str {
        match self {
            Permission::Network => "Network access",
            Permission::StorageRead => "Read storage",
            Permission::StorageWrite => "Write storage",
            Permission::Notifications => "Notifications",
            Permission::Location => "Location",
            Permission::Camera => "Camera",
            Permission::Microphone => "Microphone",
            Permission::ProcessSpawn => "Spawn processes",
            Permission::ProcessControl => "Control processes",
            Permission::InterAppCommunication => "Talk to other apps",
            Permission::RawDisk => "Raw disk access",
            Permission::KernelAccess => "Kernel-level access",
            Permission::DriverInstall => "Driver installation",
            Permission::SystemModification => "System modification",
        }
    }
}
/// Overall risk level of a permission set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Result of analysing a manifest's permission list.
#[derive(Clone, Debug, Serialize)]
pub struct PermissionAnalysis {
    pub requested: Vec<Permission>,
    pub dangerous: Vec<Permission>,
    pub risk: RiskLevel,
    /// True when dangerous permissions are present; installation then needs
    /// Developer/Advanced mode plus explicit user confirmation.
    pub requires_developer_mode: bool,
}

/// Analyse a requested permission list.
pub fn analyze(requested: &[Permission]) -> PermissionAnalysis {
    let mut dangerous: Vec<Permission> = requested
        .iter()
        .copied()
        .filter(|permission| permission.is_dangerous())
        .collect();
    dangerous.dedup();
    let medium_markers = [
        Permission::ProcessSpawn,
        Permission::ProcessControl,
        Permission::Location,
        Permission::Camera,
        Permission::Microphone,
        Permission::StorageWrite,
    ];
    let risk = if !dangerous.is_empty() {
        RiskLevel::High
    } else if requested.iter().any(|p| medium_markers.contains(p)) {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };
    let mut requested: Vec<Permission> = requested.to_vec();
    requested.sort_by_key(|permission| permission.id());
    PermissionAnalysis {
        requires_developer_mode: !dangerous.is_empty(),
        requested,
        dangerous,
        risk,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_permissions_are_blocked_by_default() {
        for permission in Permission::DANGEROUS {
            assert!(permission.is_dangerous());
        }
        let analysis = analyze(&[Permission::Network, Permission::RawDisk]);
        assert_eq!(analysis.risk, RiskLevel::High);
        assert!(analysis.requires_developer_mode);
        assert_eq!(analysis.dangerous, vec![Permission::RawDisk]);
    }

    #[test]
    fn harmless_permissions_are_low_risk() {
        let analysis = analyze(&[Permission::Network, Permission::Notifications]);
        assert_eq!(analysis.risk, RiskLevel::Low);
        assert!(!analysis.requires_developer_mode);
        assert!(analysis.dangerous.is_empty());
    }

    #[test]
    fn sensitive_but_not_dangerous_permissions_are_medium_risk() {
        let analysis = analyze(&[Permission::StorageWrite]);
        assert_eq!(analysis.risk, RiskLevel::Medium);
        assert!(!analysis.requires_developer_mode);
    }

    #[test]
    fn permission_serialisation_is_stable() {
        let json = serde_json::to_string(&Permission::RawDisk).expect("serialize");
        assert_eq!(json, "\"raw_disk\"");
        let back: Permission = serde_json::from_str("\"network\"").expect("deserialize");
        assert_eq!(back, Permission::Network);
        assert!(serde_json::from_str::<Permission>("\"root_access\"").is_err());
    }
}
