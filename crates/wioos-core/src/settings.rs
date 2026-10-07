//! Personalization settings: validated, file-backed, shared by GUI and CLI.
//!
//! Settings are stored per *usage profile* (General, Mobile, Developer,
//! Gaming, Server, Custom) so different usage modes can keep independent
//! personalization without forking the OS.

use std::{collections::BTreeMap, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    desktop::{DockConfig, HomeConfig},
    fsutil,
    profile::Profile,
    time_service::TimePreferences,
};

/// Light / dark theme selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Light,
    #[default]
    Dark,
    /// Follow the environment once a system theme signal exists.
    System,
}

/// User usage profiles for personalization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageProfile {
    /// Neutral defaults, no specialised behaviour.
    #[default]
    General,
    Mobile,
    Developer,
    Gaming,
    Server,
    /// User-defined profile; label stored in [`SettingsDocument::custom_label`].
    Custom,
}

impl UsageProfile {
    /// All usage profiles in stable order.
    pub const ALL: [UsageProfile; 6] = [
        UsageProfile::General,
        UsageProfile::Mobile,
        UsageProfile::Developer,
        UsageProfile::Gaming,
        UsageProfile::Server,
        UsageProfile::Custom,
    ];

    /// Stable identifier.
    pub fn id(self) -> &'static str {
        match self {
            UsageProfile::General => "general",
            UsageProfile::Mobile => "mobile",
            UsageProfile::Developer => "developer",
            UsageProfile::Gaming => "gaming",
            UsageProfile::Server => "server",
            UsageProfile::Custom => "custom",
        }
    }
}

/// Startup behaviour.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StartupSettings {
    /// Show Home instead of restoring last windows on start.
    pub show_home: bool,
}

impl Default for StartupSettings {
    fn default() -> Self {
        Self { show_home: true }
    }
}

/// The personalization set for one usage profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: Theme,
    pub dock: DockConfig,
    pub home: HomeConfig,
    pub time: TimePreferences,
    /// Master switch for shell animations.
    pub animations: bool,
    pub startup: StartupSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            dock: DockConfig::default(),
            home: HomeConfig::default(),
            time: TimePreferences::default(),
            animations: true,
            startup: StartupSettings::default(),
        }
    }
}
impl Settings {
    /// Validate one profile's settings; returns a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        self.dock.validate()?;
        self.home.validate()?;
        self.time.validate()?;
        Ok(())
    }
}

/// Settings error surfaced by the API and CLI.
#[derive(Debug)]
pub struct SettingsError(pub String);

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SettingsError {}

/// The persisted settings document: one settings set per usage profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SettingsDocument {
    pub schema_version: u32,
    pub active_usage_profile: UsageProfile,
    /// Label for the `custom` usage profile.
    pub custom_label: Option<String>,
    /// Settings keyed by [`UsageProfile::id`].
    pub profiles: BTreeMap<String, Settings>,
}

impl Default for SettingsDocument {
    fn default() -> Self {
        Self {
            schema_version: 1,
            active_usage_profile: UsageProfile::General,
            custom_label: None,
            profiles: BTreeMap::new(),
        }
    }
}

impl SettingsDocument {
    /// Validate the whole document.
    pub fn validate(&self) -> Result<(), SettingsError> {
        if self.schema_version != 1 {
            return Err(SettingsError(format!(
                "unsupported settings schema_version {}",
                self.schema_version
            )));
        }
        let known: Vec<&str> = UsageProfile::ALL.iter().map(|p| p.id()).collect();
        for key in self.profiles.keys() {
            if !known.contains(&key.as_str()) {
                return Err(SettingsError(format!("unknown usage profile '{key}'")));
            }
        }
        if let Some(label) = &self.custom_label {
            if label.len() > 48 {
                return Err(SettingsError("custom_label longer than 48 characters".to_owned()));
            }
        }
        for (key, settings) in &self.profiles {
            settings
                .validate()
                .map_err(|error| SettingsError(format!("profile '{key}': {error}")))?;
        }
        Ok(())
    }

    /// Effective settings for the active usage profile (defaults when unset).
    pub fn effective(&self) -> Settings {
        self.profiles
            .get(self.active_usage_profile.id())
            .cloned()
            .unwrap_or_default()
    }

    /// Mutable access to the active profile's settings, creating the entry
    /// when it does not exist yet.
    pub fn effective_entry(&mut self) -> &mut Settings {
        let key = self.active_usage_profile.id().to_owned();
        self.profiles.entry(key).or_default()
    }
}
/// File-backed settings service shared by the shell API and the CLI.
#[derive(Clone, Debug)]
pub struct SettingsService {
    path: PathBuf,
}

impl SettingsService {
    /// Open (or prepare) a settings file.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The settings file path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Load the document; a missing file yields defaults.
    pub fn load(&self) -> Result<SettingsDocument, SettingsError> {
        fsutil::read_json_or_default::<SettingsDocument>(&self.path)
            .map_err(|error| SettingsError(format!("could not read settings: {error}")))
    }

    /// Load, apply `update`, validate, and persist atomically.
    pub fn update(
        &self,
        update: impl FnOnce(&mut SettingsDocument) -> Result<(), SettingsError>,
    ) -> Result<SettingsDocument, SettingsError> {
        let path = self.path.clone();
        fsutil::update_json::<SettingsDocument, _>(&path, |document| {
            update(document).map_err(|error| std::io::Error::other(error.0))?;
            document
                .validate()
                .map_err(|error| std::io::Error::other(error.0))?;
            Ok(())
        })
        .map_err(|error| SettingsError(format!("could not save settings: {error}")))?;
        self.load()
    }

    /// Effective settings for the active usage profile.
    pub fn effective(&self) -> Result<Settings, SettingsError> {
        Ok(self.load()?.effective())
    }

    /// Ensure profile-specific defaults exist for a WIOOS edition.
    ///
    /// Called at boot so e.g. a Mobile edition starts with the compact Dock
    /// the first time, without overwriting user changes on later boots.
    pub fn seed_for_edition(&self, edition: Profile) -> Result<(), SettingsError> {
        let target = match edition {
            Profile::Mobile => UsageProfile::Mobile,
            Profile::Server => UsageProfile::Server,
            _ => return Ok(()),
        };
        let key = target.id().to_owned();
        self.update(|document| {
            let fresh = document.profiles.is_empty();
            if !document.profiles.contains_key(&key) {
                let mut settings = Settings::default();
                if target == UsageProfile::Mobile {
                    settings.dock = DockConfig::default_for(Profile::Mobile);
                }
                document.profiles.insert(key.clone(), settings);
            }
            if fresh {
                document.active_usage_profile = target;
            }
            Ok(())
        })?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::DockPosition;

    fn service(dir: &tempfile::TempDir) -> SettingsService {
        SettingsService::new(dir.path().join("settings.json"))
    }

    #[test]
    fn missing_file_yields_valid_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        let document = service.load().expect("load defaults");
        assert_eq!(document.schema_version, 1);
        assert_eq!(document.active_usage_profile, UsageProfile::General);
        let effective = document.effective();
        assert_eq!(effective.theme, Theme::Dark);
        assert!(effective.validate().is_ok());
    }

    #[test]
    fn updates_persist_and_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        let document = service
            .update(|doc| {
                doc.effective_entry().dock.position = DockPosition::Right;
                Ok(())
            })
            .expect("update");
        assert_eq!(document.effective().dock.position, DockPosition::Right);
        let reloaded = service.effective().expect("reload");
        assert_eq!(reloaded.dock.position, DockPosition::Right);
    }

    #[test]
    fn invalid_updates_are_rejected_and_not_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        let result = service.update(|doc| {
            doc.profiles.insert(
                UsageProfile::General.id().to_owned(),
                Settings {
                    dock: DockConfig {
                        size_px: 5,
                        ..DockConfig::default()
                    },
                    ..Settings::default()
                },
            );
            Ok(())
        });
        assert!(result.is_err());
        assert!(service.load().expect("load").profiles.is_empty());
    }

    #[test]
    fn usage_profiles_keep_independent_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        service
            .update(|doc| {
                let mut mobile = Settings::default();
                mobile.dock = DockConfig::default_for(Profile::Mobile);
                doc.profiles.insert(UsageProfile::Mobile.id().to_owned(), mobile);
                doc.active_usage_profile = UsageProfile::Mobile;
                Ok(())
            })
            .expect("seed mobile");
        assert!(service.effective().expect("eff").dock.size_px < 64);

        service
            .update(|doc| {
                doc.active_usage_profile = UsageProfile::General;
                Ok(())
            })
            .expect("switch");
        assert_eq!(service.effective().expect("eff").dock.size_px, 64);
    }

    #[test]
    fn edition_seeding_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        service.seed_for_edition(Profile::Mobile).expect("seed");
        let first = service.load().expect("load");
        assert_eq!(first.active_usage_profile, UsageProfile::Mobile);
        assert!(first.profiles.contains_key("mobile"));

        service
            .update(|doc| {
                doc.active_usage_profile = UsageProfile::General;
                Ok(())
            })
            .expect("switch");
        service.seed_for_edition(Profile::Mobile).expect("seed again");
        let second = service.load().expect("load");
        assert_eq!(second.active_usage_profile, UsageProfile::General);
    }

    #[test]
    fn rejects_unknown_usage_profile_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = service(&dir);
        let mut document = SettingsDocument::default();
        document
            .profiles
            .insert("not-a-profile".to_owned(), Settings::default());
        assert!(document.validate().is_err());

        let mut bad_version = SettingsDocument::default();
        bad_version.schema_version = 99;
        assert!(bad_version.validate().is_err());
        let _ = service;
    }
}
