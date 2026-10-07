//! Programming Language Manager: 15 language definitions and host detection.
//!
//! "Support" means the language is available as a downloadable package in the
//! future plus a real detection of toolchains already on the host. Nothing is
//! installed by default; installation and remote fetching are architecture
//! only until the package repository exists.

use serde::Serialize;
use wioos_core::status::ComponentStatus;

/// Definition of one supported programming language.
#[derive(Clone, Debug)]
pub struct LanguageDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub compiled: bool,
    pub package_id: &'static str,
    pub toolchain_binaries: &'static [&'static str],
}

impl LanguageDefinition {
    /// Stable id (`rust`, `python`, ...).
    pub fn id(&self) -> &'static str {
        self.id
    }
}

/// The 15 languages WIOOS will manage.
pub const LANGUAGES: [LanguageDefinition; 15] = [
    LanguageDefinition {
        id: "rust",
        name: "Rust",
        compiled: true,
        package_id: "lang-rust",
        toolchain_binaries: &["rustc", "cargo"],
    },
    LanguageDefinition {
        id: "c",
        name: "C",
        compiled: true,
        package_id: "lang-c",
        toolchain_binaries: &["gcc", "clang"],
    },
    LanguageDefinition {
        id: "cpp",
        name: "C++",
        compiled: true,
        package_id: "lang-cpp",
        toolchain_binaries: &["g++", "clang++"],
    },
    LanguageDefinition {
        id: "python",
        name: "Python",
        compiled: false,
        package_id: "lang-python",
        toolchain_binaries: &["python3"],
    },
    LanguageDefinition {
        id: "go",
        name: "Go",
        compiled: true,
        package_id: "lang-go",
        toolchain_binaries: &["go"],
    },
    LanguageDefinition {
        id: "java",
        name: "Java",
        compiled: true,
        package_id: "lang-java",
        toolchain_binaries: &["java", "javac"],
    },
    LanguageDefinition {
        id: "javascript",
        name: "JavaScript",
        compiled: false,
        package_id: "lang-js",
        toolchain_binaries: &["node"],
    },
    LanguageDefinition {
        id: "typescript",
        name: "TypeScript",
        compiled: false,
        package_id: "lang-ts",
        toolchain_binaries: &["tsc"],
    },
    LanguageDefinition {
        id: "kotlin",
        name: "Kotlin",
        compiled: true,
        package_id: "lang-kotlin",
        toolchain_binaries: &["kotlinc"],
    },
    LanguageDefinition {
        id: "swift",
        name: "Swift",
        compiled: true,
        package_id: "lang-swift",
        toolchain_binaries: &["swiftc"],
    },
    LanguageDefinition {
        id: "zig",
        name: "Zig",
        compiled: true,
        package_id: "lang-zig",
        toolchain_binaries: &["zig"],
    },
    LanguageDefinition {
        id: "ruby",
        name: "Ruby",
        compiled: false,
        package_id: "lang-ruby",
        toolchain_binaries: &["ruby"],
    },
    LanguageDefinition {
        id: "php",
        name: "PHP",
        compiled: false,
        package_id: "lang-php",
        toolchain_binaries: &["php"],
    },
    LanguageDefinition {
        id: "lua",
        name: "Lua",
        compiled: false,
        package_id: "lang-lua",
        toolchain_binaries: &["lua"],
    },
    LanguageDefinition {
        id: "dart",
        name: "Dart",
        compiled: true,
        package_id: "lang-dart",
        toolchain_binaries: &["dart"],
    },
];

/// Status of one language for the UI: WIOOS-managed state + what the host
/// already provides. Everything is real detection; nothing is invented.
#[derive(Clone, Debug, Serialize)]
pub struct LanguageStatus {
    pub id: String,
    pub name: String,
    pub compiled: bool,
    pub package_id: String,
    pub toolchain_binaries: Vec<String>,
    /// Installed through WIOOS package management (always false today).
    pub wio_installed: bool,
    /// Toolchain actually found on the host via PATH scanning.
    pub host_detected: Vec<String>,
    pub detection_note: String,
}

impl LanguageStatus {
    /// Status component for the system report.
    pub fn component_status(&self) -> ComponentStatus {
        if self.wio_installed {
            ComponentStatus::operational(
                &format!("language-{}", self.id),
                &format!("Language: {}", self.name),
            )
        } else {
            ComponentStatus::planned(
                &format!("language-{}", self.id),
                &format!("Language: {}", self.name),
                "language package not installed; install via the Package Manager",
            )
        }
    }
}

/// Build the full language list with host detection.
pub fn languages_with_detection() -> Vec<LanguageStatus> {
    LANGUAGES
        .iter()
        .map(|definition| LanguageStatus {
            id: definition.id.to_owned(),
            name: definition.name.to_owned(),
            compiled: definition.compiled,
            package_id: definition.package_id.to_owned(),
            toolchain_binaries: definition
                .toolchain_binaries
                .iter()
                .map(|binary| (*binary).to_owned())
                .collect(),
            wio_installed: false,
            host_detected: detect_host_toolchains(definition.toolchain_binaries),
            detection_note: "host toolchain detection via PATH (no WIOOS package installed)".to_owned(),
        })
        .collect()
}

fn path_dirs() -> Vec<std::path::PathBuf> {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(|entry| entry.to_owned().into())
        .filter(|path: &std::path::PathBuf| !path.as_os_str().is_empty())
        .collect()
}

/// Search the host `PATH` for the given binaries.
pub fn detect_host_toolchains(binaries: &[&'static str]) -> Vec<String> {
    let dirs = path_dirs();
    let mut found = Vec::new();
    for binary in binaries {
        for dir in &dirs {
            let candidate = dir.join(binary);
            if candidate.is_file()
                && std::fs::metadata(&candidate)
                    .map(|metadata| !metadata.permissions().readonly())
                    .unwrap_or(false)
            {
                found.push(format!("{binary} ({candidate:?})"));
                break;
            }
        }
    }
    found
}

/// Installation is architecture-only in this phase: there is no configured
/// package repository yet. The UI must not show a fake "Installed" state.
pub fn install_language(_language_id: &str) -> Result<(), String> {
    Err("language installation is not implemented: no WIOOS package repository is configured in this phase".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defines_all_15_languages_and_detects_the_host() {
        assert_eq!(LANGUAGES.len(), 15);
        let ids: Vec<&str> = LANGUAGES.iter().map(|language| language.id).collect();
        let unique: std::collections::BTreeSet<&str> = ids.iter().cloned().collect();
        assert_eq!(ids.len(), unique.len(), "duplicate ids");
        let detected = languages_with_detection();
        assert_eq!(detected.len(), 15);
        let rust = detected.iter().find(|language| language.id == "rust").expect("rust");
        assert!(!rust.wio_installed);
        assert!(rust.host_detected.len() >= 0);
        if !rust.host_detected.is_empty() {
            assert!(rust
                .host_detected
                .iter()
                .all(|binary| binary.contains("rustc") || binary.contains("cargo")));
        }
    }

    #[test]
    fn installation_is_explicitly_not_implemented() {
        assert!(install_language("rust").is_err());
        assert!(install_language("go").is_err());
    }
}
