//! WIO Display API.
//!
//! Orientation, brightness, resolution and refresh-rate changes must go
//! through this API rather than being faked with CSS/layout tricks. In the
//! current userspace runtime no display hardware or compositor API exists, so
//! every capability is reported as unavailable with a concrete reason.

use serde::Serialize;

use crate::status::ComponentStatus;

/// Physical/display orientation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Orientation {
    Portrait,
    Landscape,
}

impl Orientation {
    /// Stable id.
    pub fn id(self) -> &'static str {
        match self {
            Orientation::Portrait => "portrait",
            Orientation::Landscape => "landscape",
        }
    }
}

/// What the display backend can actually do right now.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct DisplayCapabilities {
    pub orientation_control: bool,
    pub auto_rotate: bool,
    pub brightness_control: bool,
    pub resolution_control: bool,
    pub refresh_rate_control: bool,
}

impl DisplayCapabilities {
    /// No display backend exists in this runtime, so nothing is supported.
    fn unsupported() -> Self {
        Self {
            orientation_control: false,
            auto_rotate: false,
            brightness_control: false,
            resolution_control: false,
            refresh_rate_control: false,
        }
    }
}

/// Honest report from the Display API.
#[derive(Clone, Debug, Serialize)]
pub struct DisplayReport {
    pub capabilities: DisplayCapabilities,
    /// Current orientation, `None` because no display backend reports one.
    pub orientation: Option<Orientation>,
    pub status: ComponentStatus,
    pub notes: Vec<String>,
}
/// Query the display backend.
pub fn report() -> DisplayReport {
    DisplayReport {
        capabilities: DisplayCapabilities::unsupported(),
        orientation: None,
        status: ComponentStatus::unavailable(
            "display",
            "Display API",
            "no display service or compositor API is available to this userspace runtime",
        ),
        notes: vec![
            "Orientation, brightness, resolution and refresh rate changes require \
             the future WIO display/input service."
                .to_owned(),
            "The shell must not rotate or resize itself through layout tricks and \
             present that as a display change."
                .to_owned(),
        ],
    }
}

/// Error returned when a display action is requested without a backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayError(pub String);

impl std::fmt::Display for DisplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DisplayError {}

/// Request an orientation change through the Display API.
///
/// Always fails while no display backend exists; the UI must surface the
/// error instead of silently rotating.
pub fn set_orientation(_orientation: Orientation) -> Result<(), DisplayError> {
    Err(DisplayError(
        "orientation control is not available: WIOOS has no display backend in \
         this runtime"
            .to_owned(),
    ))
}

/// Status entry for the component report.
pub fn component_status() -> ComponentStatus {
    report().status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_never_claims_display_capabilities() {
        let report = report();
        assert!(!report.capabilities.orientation_control);
        assert!(!report.capabilities.auto_rotate);
        assert!(!report.capabilities.brightness_control);
        assert!(!report.capabilities.resolution_control);
        assert!(!report.capabilities.refresh_rate_control);
        assert!(report.orientation.is_none());
        assert!(!report.status.is_operational());
        assert_eq!(report.status.state.id(), "unavailable");
    }

    #[test]
    fn orientation_requests_fail_honestly_without_backend() {
        let result = set_orientation(Orientation::Portrait);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no display backend"));
    }

    #[test]
    fn orientation_serialises_stably() {
        assert_eq!(
            serde_json::to_string(&Orientation::Landscape).unwrap(),
            "\"landscape\""
        );
    }
}
