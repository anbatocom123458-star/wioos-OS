//! Native WIO app manifest (`wio.toml`) and validation.

use serde::{Deserialize, Serialize};
use wioos_core::permission::Permission;

/// CPU architecture a native package targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Arm64,
}

impl Architecture {
    /// Stable id (`x86_64`, `arm64`).
    pub fn id(self) -> &'static str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::Arm64 => "arm64",
        }
    }

    /// Architecture of the current host, when WIOOS supports it.
    pub fn host() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Architecture::X86_64),
            "aarch64" => Some(Architecture::Arm64),
            _ => None,
        }
    }
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// A declared app dependency.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDependency {
    pub name: String,
    pub version: String,
}

/// The native WIO app manifest stored as `wio.toml` in sources and packages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WioManifest {
    pub schema_version: u32,
    /// Lowercase slug, e.g. `calculator`.
    pub name: String,
    /// `major.minor.patch`.
    pub version: String,
    pub display_name: String,
    pub description: String,
    pub architecture: Architecture,
    /// Path of the executable inside the payload directory.
    pub entry: String,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub dependencies: Vec<AppDependency>,
    #[serde(default)]
    pub developer: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub changelog: Option<String>,
    /// System apps are protected from removal; only first-party sources may
    /// set this (enforced at installation, not by the manifest alone).
    #[serde(default)]
    pub system: bool,
}

impl WioManifest {
    /// Parse `wio.toml` content.
    pub fn from_toml(content: &str) -> Result<Self, String> {
        let manifest: Self =
            toml::from_str(content).map_err(|error| format!("invalid wio.toml: {error}"))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Render back to `wio.toml`.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("manifest serialises to toml")
    }

    /// Validate the manifest; returns a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!("unsupported schema_version {}", self.schema_version));
        }
        if !is_slug(&self.name) || self.name.len() < 2 || self.name.len() > 64 {
            return Err(format!("invalid name '{}'", self.name));
        }
        validate_version(&self.version)?;
        if self.display_name.trim().is_empty() || self.display_name.len() > 64 {
            return Err("display_name must be 1..=64 characters".to_owned());
        }
        if self.description.len() > 1024 {
            return Err("description longer than 1024 characters".to_owned());
        }
        if self.entry.is_empty()
            || self.entry.len() > 512
            || self.entry.starts_with('/')
            || self
                .entry
                .split('/')
                .any(|part| part == ".." || part.is_empty())
        {
            return Err(format!("invalid entry path '{}'", self.entry));
        }
        let mut permissions = self.permissions.clone();
        permissions.sort_by_key(|permission| permission.id());
        let before = permissions.len();
        permissions.dedup();
        if before != permissions.len() {
            return Err("duplicate permissions in manifest".to_owned());
        }
        for dependency in &self.dependencies {
            if !is_slug(&dependency.name) {
                return Err(format!("invalid dependency name '{}'", dependency.name));
            }
            if dependency.name == self.name {
                return Err("app cannot depend on itself".to_owned());
            }
            if dependency.version.is_empty() || dependency.version.len() > 32 {
                return Err(format!("invalid dependency version for '{}'", dependency.name));
            }
        }
        if let Some(developer) = &self.developer {
            if developer.len() > 128 {
                return Err("developer name longer than 128 characters".to_owned());
            }
        }
        if let Some(source) = &self.source {
            if source.len() > 256 {
                return Err("source longer than 256 characters".to_owned());
            }
        }
        Ok(())
    }
}
/// Lowercase slug: `a-z`, `0-9`, `-`.
pub fn is_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `major.minor.patch` with numeric components.
pub fn validate_version(version: &str) -> Result<(), String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("version '{version}' must be major.minor.patch"));
    }
    for part in parts {
        if part.is_empty() || part.len() > 5 || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("version '{version}' has invalid component"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> String {
        r##"
schema_version = 1
name = "calculator"
version = "1.0.0"
display_name = "Calculator"
description = "A small calculator."
architecture = "x86_64"
entry = "bin/calculator"
permissions = ["network"]
developer = "WIOOS"

[[dependencies]]
name = "libwio"
version = "1.0.0"
"##
        .to_owned()
    }

    #[test]
    fn parses_and_validates_a_real_manifest() {
        let manifest = WioManifest::from_toml(&valid_toml()).expect("valid manifest");
        assert_eq!(manifest.name, "calculator");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.architecture, Architecture::X86_64);
        assert_eq!(manifest.permissions, vec![wioos_core::permission::Permission::Network]);
        assert_eq!(manifest.dependencies.len(), 1);
        assert!(!manifest.system);
        // Roundtrip through TOML keeps validation passing.
        let roundtrip = WioManifest::from_toml(&manifest.to_toml()).expect("roundtrip");
        assert_eq!(roundtrip, manifest);
    }

    #[test]
    fn rejects_invalid_names_versions_and_entries() {
        let cases = [
            ("name = \"Calculator\"", "uppercase name"),
            ("version = \"1.0\"", "short version"),
            ("entry = \"../escape\"", "entry traversal"),
            ("entry = \"/abs/path\"", "absolute entry"),
            ("schema_version = 9", "unknown schema"),
            ("permissions = [\"raw_disk\"]", "unknown permission value"), // known but see below
        ];
        for (override_line, label) in cases {
            let toml_body = valid_toml()
                .lines()
                .filter(|line| {
                    let key = override_line.split('=').next().unwrap_or("").trim();
                    !line.trim().starts_with(key) || key.is_empty()
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
                + override_line;
            let result = WioManifest::from_toml(&toml_body);
            if label == "unknown permission value" {
                // raw_disk is a known permission; the manifest must still parse.
                assert!(result.is_ok(), "{label} should parse: {result:?}");
            } else {
                assert!(result.is_err(), "{label} must fail: {result:?}");
            }
        }
    }

    #[test]
    fn rejects_unknown_permissions_and_duplicate_entries() {
        let bad = valid_toml().replace("permissions = [\"network\"]", "permissions = [\"root\"]");
        assert!(WioManifest::from_toml(&bad).is_err());

        let duplicate = valid_toml().replace(
            "permissions = [\"network\"]",
            "permissions = [\"network\", \"network\"]",
        );
        assert!(WioManifest::from_toml(&duplicate)
            .expect_err("duplicates rejected")
            .contains("duplicate"));
    }

    #[test]
    fn rejects_self_dependency() {
        let bad = valid_toml().replace("name = \"libwio\"", "name = \"calculator\"");
        assert!(WioManifest::from_toml(&bad)
            .expect_err("self dependency")
            .contains("depend on itself"));
    }

    #[test]
    fn host_architecture_is_reported_honestly() {
        let host = Architecture::host();
        match std::env::consts::ARCH {
            "x86_64" => assert_eq!(host, Some(Architecture::X86_64)),
            "aarch64" => assert_eq!(host, Some(Architecture::Arm64)),
            _ => assert!(host.is_none()),
        }
    }
}
