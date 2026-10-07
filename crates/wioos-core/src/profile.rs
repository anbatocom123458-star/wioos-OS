//! WIOOS Profiles / Editions.
//!
//! One Core, many targets. A profile selects capabilities; it never forks the
//! codebase. The running environment (container, host, hardware) is described
//! separately by [`crate::config::EnvironmentInfo`] and is never inferred from
//! the profile name.

use serde::{Deserialize, Serialize};

/// The supported WIOOS editions / deployment profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Full GUI edition for PC/laptop targets.
    Desktop,
    /// CLI/API-first edition: services, networking, storage, logs.
    Server,
    /// Edition oriented towards rendering / compute workloads.
    Render,
    /// Touch-first edition for phones via an external emulator/runtime.
    Mobile,
    /// The current deployment target: WIOOS Runtime inside a Linux container.
    Railway,
    /// Core plus the minimum needed to boot/runtime.
    Minimal,
}

/// Feature switches selected by a [`Profile`].
///
/// These are configuration switches, not claims about what the underlying
/// host can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileCapabilities {
    /// Serves the desktop shell (Home, windows, launcher).
    pub desktop_shell: bool,
    /// Shell includes a Dock.
    pub dock: bool,
    /// Dock uses the compact touch layout.
    pub compact_dock: bool,
    /// Input/layout tuned for touch.
    pub touch_first: bool,
    /// Home supports widgets.
    pub widgets: bool,
    /// Developer surfaces (language manager, package build) enabled.
    pub developer_tools: bool,
    /// Optimised for GPU/render workloads (planned; no GPU backend exists yet).
    pub gpu_workloads: bool,
    /// Minimal image: no optional components installed by default.
    pub minimal_image: bool,
    /// Profile prioritises services over interactive use.
    pub services_focus: bool,
}

impl Profile {
    /// All profiles in stable order.
    pub const ALL: [Profile; 6] = [
        Profile::Desktop,
        Profile::Server,
        Profile::Render,
        Profile::Mobile,
        Profile::Railway,
        Profile::Minimal,
    ];

    /// Parse a profile identifier (the serde lowercase form).
    pub fn parse(value: &str) -> Option<Self> {
        Profile::ALL
            .into_iter()
            .find(|profile| profile.id() == value.trim().to_ascii_lowercase())
    }

    /// Stable identifier, e.g. `railway`.
    pub fn id(self) -> &'static str {
        match self {
            Profile::Desktop => "desktop",
            Profile::Server => "server",
            Profile::Render => "render",
            Profile::Mobile => "mobile",
            Profile::Railway => "railway",
            Profile::Minimal => "minimal",
        }
    }

    /// Human readable edition name.
    pub fn display_name(self) -> &'static str {
        match self {
            Profile::Desktop => "WIOOS Desktop",
            Profile::Server => "WIOOS Server",
            Profile::Render => "WIOOS Render",
            Profile::Mobile => "WIOOS Mobile",
            Profile::Railway => "WIOOS Railway Runtime",
            Profile::Minimal => "WIOOS Minimal",
        }
    }

    /// Short, honest description of the edition.
    pub fn description(self) -> &'static str {
        match self {
            Profile::Desktop => "Full desktop shell for PC and laptops: Home, Dock, windows, Files, Store, Settings.",
            Profile::Server => "CLI/API-first edition with service, network, storage and log management; no GUI by default.",
            Profile::Render => "Edition oriented at rendering, GPU and compute workloads. No GPU backend exists yet.",
            Profile::Mobile => "Touch-first edition for phones running WIOOS inside an external emulator or runtime.",
            Profile::Railway => "WIOOS Runtime deployed as a userspace process inside a Linux container (current deployment target). Not a bare-metal OS.",
            Profile::Minimal => "Core plus minimal runtime: small image, fast start, no optional components by default.",
        }
    }
    /// Capability switches for this profile.
    pub fn capabilities(self) -> ProfileCapabilities {
        let caps = ProfileCapabilities {
            desktop_shell: false,
            dock: false,
            compact_dock: false,
            touch_first: false,
            widgets: false,
            developer_tools: false,
            gpu_workloads: false,
            minimal_image: false,
            services_focus: false,
        };
        match self {
            Profile::Desktop => ProfileCapabilities {
                desktop_shell: true,
                dock: true,
                widgets: true,
                developer_tools: true,
                ..caps
            },
            Profile::Server => ProfileCapabilities {
                developer_tools: true,
                services_focus: true,
                ..caps
            },
            Profile::Render => ProfileCapabilities {
                developer_tools: true,
                gpu_workloads: true,
                services_focus: true,
                ..caps
            },
            Profile::Mobile => ProfileCapabilities {
                desktop_shell: true,
                dock: true,
                compact_dock: true,
                touch_first: true,
                widgets: true,
                ..caps
            },
            Profile::Railway => ProfileCapabilities {
                desktop_shell: true,
                dock: true,
                widgets: true,
                developer_tools: true,
                ..caps
            },
            Profile::Minimal => ProfileCapabilities {
                minimal_image: true,
                services_focus: true,
                ..caps
            },
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_profile_id() {
        for profile in Profile::ALL {
            assert_eq!(Profile::parse(profile.id()), Some(profile));
            assert_eq!(Profile::parse(&format!("  {}  ", profile.id())), Some(profile));
        }
        assert_eq!(Profile::parse("unknown"), None);
        assert_eq!(Profile::parse(""), None);
    }

    #[test]
    fn serde_roundtrip_uses_stable_ids() {
        for profile in Profile::ALL {
            let json = serde_json::to_string(&profile).expect("serialize");
            assert_eq!(json, format!("\"{}\"", profile.id()));
            let back: Profile = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, profile);
        }
    }

    #[test]
    fn ids_and_display_names_are_unique() {
        let mut ids: Vec<&str> = Profile::ALL.iter().map(|p| p.id()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());

        let mut names: Vec<&str> = Profile::ALL.iter().map(|p| p.display_name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }

    #[test]
    fn only_shell_profiles_offer_the_shell_and_dock() {
        for profile in Profile::ALL {
            let caps = profile.capabilities();
            if caps.desktop_shell {
                assert!(caps.dock, "shell profiles must define a dock policy");
            }
            match profile {
                Profile::Minimal => {
                    assert!(caps.minimal_image);
                    assert!(!caps.desktop_shell);
                }
                Profile::Mobile => assert!(caps.touch_first && caps.compact_dock),
                Profile::Server => assert!(caps.services_focus && !caps.desktop_shell),
                Profile::Render => assert!(caps.gpu_workloads),
                _ => {}
            }
        }
    }

    #[test]
    fn descriptions_are_honest_about_railway() {
        let railway = Profile::Railway.description().to_ascii_lowercase();
        assert!(railway.contains("userspace"));
        assert!(railway.contains("not a bare-metal os"));
    }
}
