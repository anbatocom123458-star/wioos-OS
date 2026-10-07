//! Desktop / Home abstraction: Dock configuration and Home layout models.
//!
//! The Dock is a system component: the shell renders it from this
//! configuration through the desktop API instead of hardcoding a widget.
//! Profiles select defaults; users override them through Settings.

use serde::{Deserialize, Serialize};

use crate::profile::Profile;

/// Where the Dock sits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DockPosition {
    #[default]
    Bottom,
    Left,
    Right,
}

/// User-configurable Dock behaviour.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockConfig {
    pub position: DockPosition,
    /// Dock thickness in pixels (40..=112).
    pub size_px: u8,
    /// Background opacity in percent (30..=100).
    pub opacity_percent: u8,
    /// Corner radius in pixels (0..=40).
    pub corner_radius_px: u8,
    /// Slide the Dock out of view when idle.
    pub auto_hide: bool,
    /// Keep the Dock on screen at all times.
    pub always_visible: bool,
    /// Enable Dock animations (respects reduced-motion settings too).
    pub animation: bool,
    /// Gap between Dock items in pixels (0..=24).
    pub spacing_px: u8,
    /// App ids pinned to the Dock, in order.
    pub pinned: Vec<String>,
    /// Show an indicator for running apps.
    pub show_running_indicators: bool,
}

impl Default for DockConfig {
    fn default() -> Self {
        Self {
            position: DockPosition::Bottom,
            size_px: 64,
            opacity_percent: 92,
            corner_radius_px: 16,
            auto_hide: false,
            always_visible: true,
            animation: true,
            spacing_px: 8,
            pinned: vec![
                "files".to_owned(),
                "web".to_owned(),
                "store".to_owned(),
                "settings".to_owned(),
            ],
            show_running_indicators: true,
        }
    }
}
impl DockConfig {
    /// Profile-specific defaults (Mobile gets a compact touch Dock).
    pub fn default_for(profile: Profile) -> Self {
        match profile {
            Profile::Mobile => Self {
                size_px: 56,
                opacity_percent: 96,
                corner_radius_px: 20,
                spacing_px: 6,
                pinned: vec!["files".to_owned(), "store".to_owned(), "settings".to_owned()],
                ..Self::default()
            },
            Profile::Minimal => Self {
                animation: false,
                pinned: vec!["settings".to_owned()],
                ..Self::default()
            },
            _ => Self::default(),
        }
    }

    /// Validate the configuration; returns a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if !(40..=112).contains(&self.size_px) {
            return Err(format!("dock size_px {} out of range 40..=112", self.size_px));
        }
        if !(30..=100).contains(&self.opacity_percent) {
            return Err(format!(
                "dock opacity_percent {} out of range 30..=100",
                self.opacity_percent
            ));
        }
        if self.corner_radius_px > 40 {
            return Err(format!(
                "dock corner_radius_px {} out of range 0..=40",
                self.corner_radius_px
            ));
        }
        if self.spacing_px > 24 {
            return Err(format!("dock spacing_px {} out of range 0..=24", self.spacing_px));
        }
        if self.auto_hide && self.always_visible {
            return Err("dock cannot be auto_hide and always_visible at the same time".to_owned());
        }
        if self.pinned.len() > 16 {
            return Err(format!("dock pinned list too long ({}/16)", self.pinned.len()));
        }
        for app_id in &self.pinned {
            if !is_app_id(app_id) {
                return Err(format!("invalid pinned app id '{app_id}'"));
            }
        }
        let mut unique = self.pinned.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != self.pinned.len() {
            return Err("dock pinned list contains duplicates".to_owned());
        }
        Ok(())
    }
}

/// App ids are lowercase slugs.
pub fn is_app_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Wallpaper presets shipped with the shell (rendered as CSS gradients; no
/// bitmap or SVG assets are claimed).
pub const WALLPAPERS: [(&str, &str); 4] = [
    ("aurora", "Aurora"),
    ("graphite", "Graphite"),
    ("paper", "Paper"),
    ("deep", "Deep"),
];

/// True when `id` names a shipped wallpaper preset.
pub fn is_wallpaper_preset(id: &str) -> bool {
    WALLPAPERS.iter().any(|(preset, _)| *preset == id)
}

/// Home / desktop layout preferences.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HomeConfig {
    pub wallpaper: String,
    pub show_clock_widget: bool,
    pub show_status_widget: bool,
    pub search_enabled: bool,
}

impl Default for HomeConfig {
    fn default() -> Self {
        Self {
            wallpaper: "aurora".to_owned(),
            show_clock_widget: true,
            show_status_widget: true,
            search_enabled: true,
        }
    }
}

impl HomeConfig {
    /// Validate the configuration; returns a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if !is_wallpaper_preset(&self.wallpaper) {
            return Err(format!("unknown wallpaper preset '{}'", self.wallpaper));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dock_is_valid() {
        assert!(DockConfig::default().validate().is_ok());
        for profile in Profile::ALL {
            let dock = DockConfig::default_for(profile);
            assert!(dock.validate().is_ok(), "defaults for {profile} must validate");
        }
        let mobile = DockConfig::default_for(Profile::Mobile);
        assert!(mobile.size_px < DockConfig::default().size_px);
    }

    #[test]
    fn rejects_out_of_range_and_conflicting_values() {
        let mut dock = DockConfig::default();
        dock.size_px = 10;
        assert!(dock.validate().is_err());

        let mut dock = DockConfig::default();
        dock.opacity_percent = 100;
        dock.auto_hide = true; // always_visible defaults to true
        assert!(dock.validate().is_err());

        let mut dock = DockConfig::default();
        dock.pinned = vec!["files".to_owned(), "files".to_owned()];
        assert!(dock.validate().is_err());

        let mut dock = DockConfig::default();
        dock.pinned = vec!["../escape".to_owned()];
        assert!(dock.validate().is_err());
    }

    #[test]
    fn app_ids_and_wallpapers_are_validated() {
        assert!(is_app_id("files"));
        assert!(is_app_id("app-2"));
        assert!(!is_app_id(""));
        assert!(!is_app_id("Files"));
        assert!(!is_app_id("a b"));
        assert!(is_wallpaper_preset("aurora"));
        assert!(!is_wallpaper_preset("malicious"));
    }

    #[test]
    fn home_config_validates_wallpaper() {
        let mut home = HomeConfig::default();
        assert!(home.validate().is_ok());
        home.wallpaper = "not-a-preset".to_owned();
        assert!(home.validate().is_err());
    }

    #[test]
    fn dock_config_serde_roundtrip() {
        let dock = DockConfig::default_for(Profile::Desktop);
        let json = serde_json::to_string(&dock).expect("serialize");
        let back: DockConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dock, back);
    }
}
