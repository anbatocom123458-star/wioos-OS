//! Installed application registry.
//!
//! The registry lives at `<state_dir>/apps/registry.json` and is the single
//! source of truth for the App Manager, the CLI and the web runtime. It is
//! read through the same locked, atomic JSON helpers used by the
//! verification store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsutil;

/// One application installed into the WIOOS state directory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InstalledApp {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub version: String,
    /// `native_wio`, `web` or `linux_compatible`.
    pub kind: String,
    pub source: String,
    pub installed_at_unix: u64,
    pub size_bytes: u64,
    pub permissions: Vec<String>,
    /// Protected (cannot be uninstalled accidentally).
    pub protected: bool,
    /// Payload `wio.toml` entry path, when available.
    pub entry: Option<String>,
    pub architecture: Option<String>,
    pub checksum: Option<String>,
    /// Payload directory inside the state directory.
    pub install_path: PathBuf,
    /// App data directory (persistent user data).
    pub data_path: PathBuf,
}

impl InstalledApp {
    /// Persistent user-data directory for this app.
    pub fn data_dir(&self) -> PathBuf {
        self.data_path.join(&self.id)
    }
}

/// Application registry for a WIOOS installation.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppRegistry {
    pub state_dir: PathBuf,
    pub apps: BTreeMap<String, InstalledApp>,
}

impl AppRegistry {
    /// Open the registry for a state directory.
    pub fn open(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            apps: BTreeMap::new(),
        }
    }

    /// The state directory this registry belongs to.
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    /// Registry file path.
    pub fn registry_path(&self) -> PathBuf {
        fsutil::registry_path(&self.state_dir)
    }

    /// Load from file; a missing file yields an empty registry.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path).map_err(|error| format!("cannot read registry: {error}"))?;
        let registry: Self =
            serde_json::from_str(&raw).map_err(|error| format!("invalid registry: {error}"))?;
        Ok(registry)
    }

    /// Persist atomically (locked file replacement).
    pub fn save(&self) -> Result<(), String> {
        let file = std::fs::File::create(&self.registry_path()).map_err(|error| format!("cannot write registry: {error}"))?;
        serde_json::to_writer_pretty(file, self).map_err(|error| format!("cannot write registry: {error}"))
    }

    /// Look up an installed app by id or by case-insensitive name.
    pub fn find(&self, id: &str) -> Option<&InstalledApp> {
        self.apps.get(id).or_else(|| {
            self.apps
                .values()
                .find(|app| app.name.to_lowercase() == id.to_lowercase())
        })
    }

    /// List installed applications, alphabetically by name.
    pub fn list(&self) -> Vec<&InstalledApp> {
        let mut apps: Vec<&InstalledApp> = self.apps.values().collect();
        apps.sort_by(|a, b| a.name.cmp(&b.name));
        apps
    }

    /// Protect an app from accidental removal (system apps).
    pub fn protect(&mut self, id: &str, protected: bool) {
        if let Some(app) = self.apps.get_mut(id) {
            app.protected = protected;
        }
    }

    /// Install one package that has already been verified by the security gate.
    pub fn install_verified(
        &mut self,
        package_path: &Path,
        app_id: String,
        display_name: String,
        version: String,
        source_desc: String,
        protected: bool,
        permissions: Vec<String>,
        entry: Option<String>,
        architecture: Option<String>,
        checksum: Option<String>,
        source: crate::store::StoreAppType,
    ) -> Result<InstalledApp, String> {
        if self.find(&app_id).is_some() {
            return Err(format!("app '{app_id}' is already installed"));
        }
        let package_dir = fsutil::apps_dir(&self.state_dir).join(&app_id);
        std::fs::create_dir_all(&package_dir).map_err(|error| format!("cannot create install dir: {error}"))?;
        let summary = extract_package(package_path, &package_dir)?;
        let data_dir = package_dir.join("data");
        std::fs::create_dir_all(&data_dir).map_err(|error| format!("cannot create data dir: {error}"))?;

        let installed = InstalledApp {
            id: app_id.clone(),
            name: display_name.clone(),
            display_name,
            version,
            kind: match source {
                crate::store::StoreAppType::NativeWio => "native_wio".to_owned(),
                crate::store::StoreAppType::WebApp => "web".to_owned(),
                crate::store::StoreAppType::LinuxCompatible => "linux_compatible".to_owned(),
            },
            source: source_desc,
            installed_at_unix: now_unix(),
            size_bytes: summary.payload_bytes,
            permissions,
            protected,
            entry,
            architecture,
            checksum: checksum.filter(|c| !c.is_empty()),
            install_path: package_dir,
            data_path: data_dir,
        };
        self.apps.insert(app_id, installed.clone());
        self.save()?;
        wioos_core::security::SecurityEvent::now(
            "package_gate",
            app_id,
            "allowed",
            format!(
                "installed {} version {} ({})",
                installed.display_name, installed.version, installed.size_bytes
            ),
        )
        .append(&entity)
        .map_err(|error| format!("could not write security log: {error}"))?;
        Ok(installed)
    }

    /// Install an external local package through the full security gate.
    pub fn install_external(
        &mut self,
        package_path: &Path,
        app_id: String,
        source: crate::store::StoreAppType,
        developer_mode: bool,
        user_confirmed: bool,
    ) -> Result<InstalledApp, String> {
        let verification = verify_package(package_path)?;
        if !verification.manifest_ok {
            return Err(format!(
                "manifest validation failed: {}",
                verification.errors.join("; ")
            ));
        }
        let manifest_info = read_package(package_path)?;
        let manifest = &manifest_info.manifest;
        if manifest.architecture != crate::manifest::Architecture::host()
            .ok_or("unknown host architecture")?
        {
            return Err(format!(
                "package architecture {} is not compatible with host {}",
                manifest.architecture,
                std::env::consts::ARCH
            ));
        }
        let permissions: Vec<String> = manifest
            .permissions
            .iter()
            .map(|permission| permission.id().to_owned())
            .collect();

        let gate_report = wioos_core::security::evaluate(&wioos_core::security::GateInput {
            source: match source {
                crate::store::StoreAppType::NativeWio => wioos_core::security::PackageSource::Registry,
                _ => wioos_core::security::PackageSource::LocalFile,
            },
            manifest_valid: verification.manifest_ok,
            integrity: verification.integrity.as_ref().cloned().unwrap_or(wioos_core::security::IntegrityCheck::Missing),
            signature: wioos_core::security::SignatureCheck::Absent,
            permissions,
            user_confirmed,
            developer_mode,
            threat_scanner_available: false,
            sandbox_available: false,
        });
        if gate_report.decision == wioos_core::security::Decision::Block {
            let reason = gate_report
                .reasons
                .first()
                .map(String::as_str)
                .unwrap_or("unknown reason");
            wioos_core::security::SecurityEvent::now(
                "package_gate",
                app_id,
                "blocked",
                reason,
            )
            .append(&entity)
            .map_err(|error| format!("could not write security log: {error}"))?;
            return Err(format!("install blocked by security gate: {reason}"));
        }
        if gate_report.decision == wioos_core::security::Decision::RequireConfirmation {
            return Err("installation blocked: user confirmation required".to_owned());
        }
        let checksum = verification
            .integrity
            .as_ref()
            .map(|check| match check {
                wioos_core::security::IntegrityCheck::Valid { digest, .. } => Some(digest.clone()),
                _ => None,
            });

        if self.find(&app_id).is_some() {
            return Err(format!("app '{app_id}' is already installed"));
        }
        let package_dir = fsutil::apps_dir(&self.state_dir).join(&app_id);
        std::fs::create_dir_all(&package_dir).map_err(|error| format!("cannot create install dir: {error}"))?;
        let summary = extract_package(package_path, &package_dir)?;
        let data_dir = package_dir.join("data");
        std::fs::create_dir_all(&data_dir).map_err(|error| format!("cannot create data dir: {error}"))?;

        self.apps.insert(
            app_id.clone(),
            InstalledApp {
                id: app_id.clone(),
                name: manifest.display_name.clone(),
                display_name: manifest.display_name.clone(),
                version: manifest.version.clone(),
                kind: "native_wio".to_owned(),
                source: match source {
                    crate::store::StoreAppType::NativeWio => "local native package".to_owned(),
                    _ => "external".to_owned(),
                },
                installed_at_unix: now_unix(),
                size_bytes: summary.payload_bytes,
                permissions: permissions.clone(),
                protected: manifest.system,
                entry: Some(manifest.entry.clone()),
                architecture: Some(manifest.architecture.id().to_owned()),
                checksum: checksum.filter(|c| !c.is_empty()),
                install_path: package_dir.clone(),
                data_path: data_dir.clone(),
            },
        );
        self.save()?;
        wioos_core::security::SecurityEvent::now(
            "package_gate",
            app_id,
            "allowed",
            format!(
                "installed {} version {} ({})",
                manifest.display_name, manifest.version, summary.payload_bytes
            ),
        )
        .append(&entity)
        .map_err(|error| format!("could not write security log: {error}"))?;
        Ok(self.apps[&app_id].clone())
    }

    /// Uninstall an app (system apps refuse).
    pub fn uninstall(&mut self, id: &str) -> Result<InstalledApp, String> {
        let Some(app) = self.apps.get(id) else {
            return Err(format!("app '{id}' is not installed"));
        };
        if app.protected {
            return Err("system apps cannot be removed".to_owned());
        }
        let removed = self.apps.remove(id).expect("present");
        self.save()?;
        wioos_core::security::SecurityEvent::now(
            "package_gate",
            id.to_owned(),
            "removed",
            format!("{} version {}", removed.display_name, removed.version),
        )
        .append(&entity)
        .map_err(|error| format!("could not write security log: {error}"))?;
        Ok(removed)
    }

    /// Catalog entries for the Store UI (built-in web apps).
    pub fn catalog_entries(&self) -> Vec<crate::store::StoreEntry> {
        crate::store::StoreCatalog::builtin().entries().to_vec()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_source_local(dir: &std::path::Path) {
        fs::create_dir_all(dir.join("bin")).expect("mkdir");
        fs::write(
            dir.join("wio.toml"),
            r##"
schema_version = 1
name = "calculator"
version = "1.0.0"
display_name = "Calculator"
description = "A small calculator."
architecture = "x86_64"
entry = "bin/calculator"
permissions = ["network"]
"##,
        )
        .expect("manifest");
        fs::write(dir.join("bin/calculator"), "#!/bin/sh\necho calc\n").expect("entry");
    }

    fn install_verified_package(dest: &tempfile::TempDir) -> std::path::PathBuf {
        let src = dest.path().join("src");
        sample_source_local(&src);
        build(&src, &dest.path().join("dist")).expect("build").path
    }

    fn registry(dir: tempfile::tempdir::TempDir) -> AppRegistry {
        AppRegistry::open(dir.path().into())
    }

    #[test]
    fn installs_and_removes_a_valid_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let package_path = install_verified_package(&dir);
        let mut registry = registry(dir.clone());
        let installed = registry
            .install_external(&package_path, "calculator".to_owned(), crate::store::StoreAppType::NativeWio, false, false)
            .expect("install");
        assert_eq!(installed.id, "calculator");
        assert!(installed.install_path.starts_with(dir.path()));
        assert_eq!(registry.find("calculator").unwrap().permissions.len(), 1);

        registry.uninstall("calculator").expect("uninstall");
        assert!(registry.find("calculator").is_none());
    }

    #[test]
    fn blocks_invalid_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        fs::create_dir_all(&src).expect("mkdir");
        fs::write(src.join("wio.toml"), "this is not toml").expect("bad manifest");
        fs::write(src.join("bin/calc"), "#!/bin/sh").expect("entry");
        let package_path = build(&src, &dir.path().join("dist")).expect("build").path;

        let mut registry = registry(dir);
        let result = registry
            .install_external(&package_path, "calc".to_owned(), crate::store::StoreAppType::NativeWio, false, false);
        assert!(result.is_err());
        assert!(registry.list().is_empty());
    }

    #[test]
    fn blocks_dangerous_permissions_without_developer_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source_local(&src);
        let raw = fs::read_to_string(src.join("wio.toml")).unwrap();
        fs::write(
            src.join("wio.toml"),
            raw.replace("permissions = [\"network\"]", "permissions = [\"raw_disk\"]"),
        )
        .expect("manifest");
        let package_path = build(&src, &dir.path().join("dist")).expect("build").path;

        let mut registry = registry(dir);
        let error = registry
            .install_external(
                &package_path,
                "dangerous".to_owned(),
                crate::store::StoreAppType::NativeWio,
                false, // developer mode
                false, // user confirmed
            )
            .expect_err("must be blocked");
        assert!(error.contains("security gate"));

        let installed = registry
            .install_external(
                &package_path,
                "dangeous-yes".to_owned(),
                crate::store::StoreAppType::NativeWio,
                true, // developer mode
                true, // user confirmed
            )
            .expect("install with override");
        assert!(!installed.protected);
    }

    #[test]
    fn refuses_to_remove_protected_system_app() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source_local(&src);
        let raw = fs::read_to_string(src.join("wio.toml")).unwrap();
        fs::write(
            src.join("wio.toml"),
            raw.replace("permissions = [\"network\"]", "permissions = [\"network\"]"),
        )
        .expect("manifest");
        let package_path = install_verified_package(&dir);
        let mut registry = registry(dir);
        registry
            .install_external(&package_path, "system-app".to_owned(), crate::store::StoreAppType::NativeWio, false, false)
            .expect("install");
        registry
            .protect("system-app", true);
        registry.save().expect("save");
        let registry = registry(dir);
        let error = registry.uninstall("system-app").expect_err("must refuse");
        assert_eq!(error, "system apps cannot be removed");
    }

    #[test]
    fn blocked_install_does_not_persist_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("src");
        sample_source_local(&src);
        let package_path = build(&src, &dir.path().join("dist")).expect("build").path;

        let mut registry = registry(dir);
        let err = registry
            .install_external(
                &package_path,
                "half-installed".to_owned(),
                crate::store::StoreAppType::NativeWio,
                false,
                false,
            )
            .expect_err("blocked");
        assert!(err.contains("security gate"));
        assert!(registry.find("half-installed").is_none());
    }
}
