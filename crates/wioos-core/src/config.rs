//! Core configuration and environment facts.
//!
//! Configuration never contains secrets. Environment facts are detected, not
//! assumed: WIOOS states what the host actually provides.

use std::{
    env,
    error::Error,
    fmt::{Display, Formatter},
    path::PathBuf,
};

use serde::Serialize;

use crate::profile::Profile;

/// Configuration error raised by [`CoreConfig::from_env`].
#[derive(Debug)]
pub struct ConfigError(pub String);

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ConfigError {}

/// Paths and profile shared by every WIOOS service.
#[derive(Clone, Debug)]
pub struct CoreConfig {
    pub profile: Profile,
    /// Root for all runtime state (settings, installed apps, home, logs).
    pub state_dir: PathBuf,
}

impl CoreConfig {
    /// Build a configuration from explicit values (used by tests and the CLI).
    pub fn new(profile: Profile, state_dir: PathBuf) -> Self {
        Self {
            profile,
            state_dir,
        }
    }

    /// `WIOOS_PROFILE` (default `desktop`) and `WIOOS_STATE_DIR` (default `data`).
    pub fn from_env() -> Result<Self, ConfigError> {
        let raw_profile = env::var("WIOOS_PROFILE").unwrap_or_else(|_| "desktop".to_owned());
        let profile = Profile::parse(&raw_profile).ok_or_else(|| {
            ConfigError(format!(
                "invalid WIOOS_PROFILE '{raw_profile}': expected one of {}",
                Profile::ALL
                    .iter()
                    .map(|profile| profile.id())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        let state_dir = env::var_os("WIOOS_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data"));
        Ok(Self::new(profile, state_dir))
    }

    /// `settings.json` inside the state directory.
    pub fn settings_path(&self) -> PathBuf {
        self.state_dir.join("settings.json")
    }

    /// Installed applications root.
    pub fn apps_dir(&self) -> PathBuf {
        self.state_dir.join("apps")
    }

    /// App registry file.
    pub fn registry_path(&self) -> PathBuf {
        self.apps_dir().join("registry.json")
    }

    /// Sandboxed user home used by WIO Files.
    pub fn home_dir(&self) -> PathBuf {
        self.state_dir.join("home")
    }

    /// Trash directory inside the sandboxed home.
    pub fn trash_dir(&self) -> PathBuf {
        self.home_dir().join(".trash")
    }

    /// JSONL security event log.
    pub fn security_log_path(&self) -> PathBuf {
        self.state_dir.join("security-log.jsonl")
    }

    /// Snapshot directory for the (planned) backup subsystem.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.state_dir.join("snapshots")
    }
}
/// Detected facts about the environment WIOOS runs in.
///
/// WIOOS never claims kernel, driver or hardware control just because it
/// reports a profile.
#[derive(Clone, Debug, Serialize)]
pub struct EnvironmentInfo {
    /// Host OS family (`linux`, `macos`, ...).
    pub os: String,
    /// Target architecture (`x86_64`, `aarch64`, ...).
    pub arch: String,
    /// How the runtime is deployed, detected from the host.
    pub runtime_kind: String,
    /// True only when WIOOS actually has kernel/driver control. Always false
    /// for the current userspace runtime.
    pub hardware_access: bool,
    /// True when WIOOS controls the kernel. False in this phase.
    pub kernel_control: bool,
    /// Honest limitation note surfaced by the UI.
    pub note: String,
}

impl EnvironmentInfo {
    /// Detect environment facts from the current process' host.
    pub fn detect() -> Self {
        Self {
            os: env::consts::OS.to_owned(),
            arch: env::consts::ARCH.to_owned(),
            runtime_kind: detect_runtime_kind(),
            hardware_access: false,
            kernel_control: false,
            note: "WIOOS currently runs as a userspace runtime. It has no kernel, \
                   driver or physical device control on this host."
                .to_owned(),
        }
    }
}

fn detect_runtime_kind() -> String {
    if std::path::Path::new("/.dockerenv").exists() {
        return "linux-container".to_owned();
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        for marker in ["docker", "containerd", "kubepods", "lxc"] {
            if cgroup.contains(marker) {
                return "linux-container".to_owned();
            }
        }
    }
    "userspace-process".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_from_explicit_values() {
        let config = CoreConfig::new(Profile::Server, PathBuf::from("/tmp/wio"));
        assert_eq!(config.profile, Profile::Server);
        assert_eq!(config.settings_path(), PathBuf::from("/tmp/wio/settings.json"));
        assert_eq!(
            config.registry_path(),
            PathBuf::from("/tmp/wio/apps/registry.json")
        );
        assert_eq!(config.trash_dir(), PathBuf::from("/tmp/wio/home/.trash"));
        assert_eq!(
            config.security_log_path(),
            PathBuf::from("/tmp/wio/security-log.jsonl")
        );
    }

    #[test]
    fn environment_facts_never_claim_hardware_control() {
        let info = EnvironmentInfo::detect();
        assert!(!info.hardware_access);
        assert!(!info.kernel_control);
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
        assert!(!info.runtime_kind.is_empty());
        assert!(info.note.contains("userspace runtime"));
    }

    #[test]
    fn profile_gate_used_by_from_env_rejects_unknown_values() {
        assert!(Profile::parse("no-such-profile").is_none());
        assert_eq!(Profile::parse("desktop"), Some(Profile::Desktop));
        assert_eq!(Profile::parse("RAILWAY"), Some(Profile::Railway));
    }
}
