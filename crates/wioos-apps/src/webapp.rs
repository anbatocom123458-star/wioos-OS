//! Web App model: clearly labelled URL applications opened by the WIO Web
//! Runtime. Web apps are never presented as native `.wio` packages.

use serde::{Deserialize, Serialize};
use wioos_core::{desktop::is_app_id, permission::Permission};

/// A catalog entry for a web application.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WebAppEntry {
    /// Stable slug id (also used as the installed-app id).
    pub id: String,
    pub name: String,
    /// `https://` URL only.
    pub url: String,
    pub description: String,
    #[serde(default)]
    pub developer: Option<String>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// Web apps always require internet access.
    pub requires_internet: bool,
}

impl WebAppEntry {
    /// Validate catalog metadata; returns a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if !is_app_id(&self.id) {
            return Err(format!("invalid web app id '{}'", self.id));
        }
        if self.name.trim().is_empty() || self.name.len() > 64 {
            return Err("name must be 1..=64 characters".to_owned());
        }
        if self.description.len() > 1024 {
            return Err("description longer than 1024 characters".to_owned());
        }
        validate_url(&self.url)?;
        if !self.requires_internet {
            return Err("web apps require internet access".to_owned());
        }
        if self.permissions != [Permission::Network] && !self.permissions.is_empty() {
            // Web apps may only request network access in this phase.
            if self.permissions.iter().any(|permission| *permission != Permission::Network) {
                return Err("web apps may only request the network permission".to_owned());
            }
        }
        Ok(())
    }
}

/// Strict URL validation without extra dependencies: `https://`, no
/// credentials, no whitespace, non-empty host.
pub fn validate_url(url: &str) -> Result<(), String> {
    if url.len() > 2048 {
        return Err("url longer than 2048 characters".to_owned());
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("web app urls must use https://".to_owned());
    };
    if rest.is_empty() {
        return Err("url has no host".to_owned());
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("url contains whitespace or control characters".to_owned());
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("url has no host".to_owned());
    }
    if authority.contains('@') {
        return Err("url must not embed credentials".to_owned());
    }
    let host = authority.split(':').next().unwrap_or("");
    if host.is_empty() {
        return Err("url has no host".to_owned());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str) -> WebAppEntry {
        WebAppEntry {
            id: "youtube".to_owned(),
            name: "YouTube".to_owned(),
            url: url.to_owned(),
            description: "Video streaming.".to_owned(),
            developer: Some("Google".to_owned()),
            permissions: vec![Permission::Network],
            requires_internet: true,
        }
    }

    #[test]
    fn accepts_valid_https_entries() {
        assert!(entry("https://www.youtube.com").validate().is_ok());
        assert!(entry("https://github.com/login").validate().is_ok());
        assert!(validate_url("https://example.com:8443/path?q=1").is_ok());
    }

    #[test]
    fn rejects_insecure_or_malformed_urls() {
        for url in [
            "http://example.com",
            "javascript:alert(1)",
            "ftp://example.com",
            "https://",
            "https://user:pass@example.com",
            "https://exa mple.com",
            "file:///etc/passwd",
            "",
        ] {
            assert!(validate_url(url).is_err(), "url '{url}' must be rejected");
        }
    }

    #[test]
    fn rejects_non_network_permissions_and_missing_internet() {
        let mut app = entry("https://example.com");
        app.permissions = vec![Permission::RawDisk];
        assert!(app.validate().is_err());

        let mut app = entry("https://example.com");
        app.requires_internet = false;
        assert!(app.validate().is_err());

        let mut app = entry("https://example.com");
        app.id = "Not A Slug".to_owned();
        assert!(app.validate().is_err());
    }

    #[test]
    fn web_app_metadata_round_trips_json() {
        let app = entry("https://www.youtube.com");
        let json = serde_json::to_string(&app).expect("serialize");
        let back: WebAppEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, app);
        assert!(json.contains("https://www.youtube.com"));
    }
}
