//! WIO Store: the official catalog. Entries are explicitly typed so a web
//! app can never be mistaken for a native `.wio` package.

use serde::Serialize;

use crate::webapp::{WebAppEntry, validate_url};
use wioos_core::permission::Permission;

/// What kind of application a catalog entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreAppType {
    /// Native package built with `wio build` (`.wio` archive).
    NativeWio,
    /// URL entry opened by the WIO Web Runtime.
    WebApp,
    /// Future Linux compatibility layer (architecture only).
    LinuxCompatible,
}

impl StoreAppType {
    /// Label shown in the store UI.
    pub fn label(self) -> &'static str {
        match self {
            StoreAppType::NativeWio => "NATIVE WIO APP",
            StoreAppType::WebApp => "WEB APP",
            StoreAppType::LinuxCompatible => "LINUX COMPATIBLE",
        }
    }
}

/// One store entry.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StoreEntry {
    Web { app: WebAppEntry },
    Native { package: NativeCatalogItem },
}

/// A native package offered by the catalog.
///
/// The catalog ships no remote native packages in this phase; local `.wio`
/// files are surfaced through [`StoreCatalog::with_local_packages`].
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NativeCatalogItem {
    pub name: String,
    pub version: String,
    pub display_name: String,
    pub description: String,
    pub architecture: String,
    pub size_bytes: Option<u64>,
    pub developer: Option<String>,
    pub source: String,
    pub checksum: Option<String>,
    pub local_path: String,
}

impl StoreEntry {
    /// The entry type.
    pub fn app_type(&self) -> StoreAppType {
        match self {
            StoreEntry::Web { .. } => StoreAppType::WebApp,
            StoreEntry::Native { .. } => StoreAppType::NativeWio,
        }
    }

    /// Stable id used by install/uninstall.
    pub fn id(&self) -> &str {
        match self {
            StoreEntry::Web { app } => &app.id,
            StoreEntry::Native { package } => &package.name,
        }
    }

    /// Display name.
    pub fn name(&self) -> &str {
        match self {
            StoreEntry::Web { app } => &app.name,
            StoreEntry::Native { package } => &package.display_name,
        }
    }

    /// Description.
    pub fn description(&self) -> &str {
        match self {
            StoreEntry::Web { app } => &app.description,
            StoreEntry::Native { package } => &package.description,
        }
    }
}
/// The WIO Store catalog.
#[derive(Clone, Debug)]
pub struct StoreCatalog {
    entries: Vec<StoreEntry>,
}

impl StoreCatalog {
    /// Built-in catalog: the web app bridge plus (optionally) local native
    /// packages discovered in a directory.
    pub fn builtin() -> Self {
        let web = |id: &str, name: &str, url: &str, description: &str, developer: &str| {
            StoreEntry::Web {
                app: WebAppEntry {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    url: url.to_owned(),
                    description: description.to_owned(),
                    developer: Some(developer.to_owned()),
                    permissions: vec![Permission::Network],
                    requires_internet: true,
                },
            }
        };
        Self {
            entries: vec![
                web("youtube", "YouTube", "https://www.youtube.com", "Video streaming.", "Google"),
                web("github", "GitHub", "https://github.com", "Code hosting and collaboration.", "GitHub"),
                web("discord", "Discord", "https://discord.com", "Voice, video and text chat.", "Discord"),
                web("chatgpt", "ChatGPT", "https://chatgpt.com", "AI assistant chat.", "OpenAI"),
                web("wikipedia", "Wikipedia", "https://www.wikipedia.org", "The free encyclopedia.", "Wikimedia Foundation"),
                web("reddit", "Reddit", "https://www.reddit.com", "Communities and discussion.", "Reddit"),
                web("notion", "Notion", "https://www.notion.so", "Notes and workspace docs.", "Notion Labs"),
                web("figma", "Figma", "https://www.figma.com", "Collaborative interface design.", "Figma"),
            ],
        }
    }

    /// The catalog without local packages.
    pub fn entries(&self) -> &[StoreEntry] {
        &self.entries
    }

    /// Append local `.wio` packages found in `dist`-style directories so
    /// developers can install what they just built.
    pub fn with_local_packages(mut self, items: Vec<NativeCatalogItem>) -> Self {
        for item in items {
            self.entries.push(StoreEntry::Native { package: item });
        }
        self
    }

    /// Case-insensitive search over id, name and description.
    pub fn search(&self, query: &str) -> Vec<&StoreEntry> {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return self.entries.iter().collect();
        }
        self.entries
            .iter()
            .filter(|entry| {
                let (id, name, description) = match entry {
                    StoreEntry::Web { app } => {
                        (app.id.as_str(), app.name.as_str(), app.description.as_str())
                    }
                    StoreEntry::Native { package } => (
                        package.name.as_str(),
                        package.display_name.as_str(),
                        package.description.as_str(),
                    ),
                };
                id.to_lowercase().contains(&query)
                    || name.to_lowercase().contains(&query)
                    || description.to_lowercase().contains(&query)
            })
            .collect()
    }

    /// Look up one entry by id.
    pub fn get(&self, id: &str) -> Option<&StoreEntry> {
        self.entries.iter().find(|entry| entry.id() == id)
    }

    /// Validate every built-in entry (used by tests and boot checks).
    pub fn validate(&self) -> Result<(), String> {
        for entry in &self.entries {
            if let StoreEntry::Web { app } = entry {
                app.validate()?;
                validate_url(&app.url)?;
            }
        }
        let mut ids: Vec<&str> = self.entries.iter().map(|entry| entry.id()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        if before != ids.len() {
            return Err("duplicate store ids".to_owned());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_is_valid_and_labelled_honestly() {
        let catalog = StoreCatalog::builtin();
        catalog.validate().expect("valid builtin catalog");
        assert!(catalog.entries().len() >= 8);
        for entry in catalog.entries() {
            match entry {
                StoreEntry::Web { app } => {
                    assert_eq!(entry.app_type(), StoreAppType::WebApp);
                    assert_eq!(StoreAppType::WebApp.label(), "WEB APP");
                    assert!(app.url.starts_with("https://"));
                }
                StoreEntry::Native { .. } => panic!("builtin catalog ships no native packages"),
            }
        }
    }

    #[test]
    fn search_matches_name_id_and_description() {
        let catalog = StoreCatalog::builtin();
        assert_eq!(catalog.search("youTube").len(), 1);
        assert_eq!(catalog.search("github")[0].id(), "github");
        assert_eq!(catalog.search("encyclopedia")[0].id(), "wikipedia");
        assert_eq!(catalog.search("no-such-app").len(), 0);
        assert_eq!(catalog.search("").len(), catalog.entries().len());
    }

    #[test]
    fn native_catalog_items_are_typed_as_native() {
        let item = NativeCatalogItem {
            name: "calculator".to_owned(),
            version: "1.0.0".to_owned(),
            display_name: "Calculator".to_owned(),
            description: "A calculator.".to_owned(),
            architecture: "x86_64".to_owned(),
            size_bytes: Some(2048),
            developer: Some("WIOOS".to_owned()),
            source: "local file".to_owned(),
            checksum: Some("sha256:ab".to_owned()),
            local_path: "dist/calculator-1.0.0.wio".to_owned(),
        };
        let catalog = StoreCatalog::builtin().with_local_packages(vec![item]);
        let entry = catalog.get("calculator").expect("native entry");
        assert_eq!(entry.app_type(), StoreAppType::NativeWio);
        assert_eq!(StoreAppType::NativeWio.label(), "NATIVE WIO APP");
        catalog.validate().expect("still valid");
    }
}
