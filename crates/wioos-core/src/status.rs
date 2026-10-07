//! Honest component status reporting.
//!
//! Every WIOOS subsystem reports its real state through this module. The
//! allowed states are intentionally narrow so the UI and CLI can never claim
//! a capability that does not exist.

use serde::Serialize;

/// The real state of a WIOOS component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ComponentState {
    /// The component works and its backend exists.
    Operational,
    /// The component exists but is partially limited.
    Degraded { reason: String },
    /// The component cannot run in this environment (e.g. no hardware access).
    Unavailable { reason: String },
    /// The backend has not been implemented yet; only the interface exists.
    NotImplemented { reason: String },
    /// Scheduled for a later phase.
    Planned { reason: String },
    /// Explicitly a simulation; never shown as real functionality.
    SimulatedOnly { reason: String },
}

impl ComponentState {
    /// The human-readable reason attached to non-operational states.
    pub fn reason(&self) -> Option<&str> {
        match self {
            ComponentState::Operational => None,
            ComponentState::Degraded { reason }
            | ComponentState::Unavailable { reason }
            | ComponentState::NotImplemented { reason }
            | ComponentState::Planned { reason }
            | ComponentState::SimulatedOnly { reason } => Some(reason),
        }
    }

    /// Stable machine-readable state id.
    pub fn id(&self) -> &'static str {
        match self {
            ComponentState::Operational => "operational",
            ComponentState::Degraded { .. } => "degraded",
            ComponentState::Unavailable { .. } => "unavailable",
            ComponentState::NotImplemented { .. } => "not_implemented",
            ComponentState::Planned { .. } => "planned",
            ComponentState::SimulatedOnly { .. } => "simulated_only",
        }
    }
}

/// Status of a single WIOOS component.
#[derive(Clone, Debug, Serialize)]
pub struct ComponentStatus {
    pub id: String,
    pub name: String,
    pub state: ComponentState,
    pub notes: Vec<String>,
}

impl ComponentStatus {
    /// Create a status with an explicit state.
    pub fn new(id: impl Into<String>, name: impl Into<String>, state: ComponentState) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            state,
            notes: Vec::new(),
        }
    }

    /// Convenience: the component works.
    pub fn operational(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name, ComponentState::Operational)
    }

    /// Convenience: backend not implemented.
    pub fn not_implemented(
        id: impl Into<String>,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(id, name, ComponentState::NotImplemented { reason: reason.into() })
    }

    /// Convenience: cannot run in this environment.
    pub fn unavailable(
        id: impl Into<String>,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(id, name, ComponentState::Unavailable { reason: reason.into() })
    }

    /// Convenience: planned for a later phase.
    pub fn planned(
        id: impl Into<String>,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(id, name, ComponentState::Planned { reason: reason.into() })
    }

    /// Convenience: partially limited.
    pub fn degraded(
        id: impl Into<String>,
        name: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(id, name, ComponentState::Degraded { reason: reason.into() })
    }

    /// Attach an additional note.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// True when the backend genuinely exists and works here.
    pub fn is_operational(&self) -> bool {
        matches!(self.state, ComponentState::Operational)
    }
}
/// Counts used by dashboards and CLI summaries.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct StatusCounts {
    pub operational: usize,
    pub degraded: usize,
    pub unavailable: usize,
    pub not_implemented: usize,
    pub planned: usize,
    pub simulated_only: usize,
}

/// A full status report for the system.
#[derive(Clone, Debug, Serialize)]
pub struct StatusReport {
    pub components: Vec<ComponentStatus>,
    pub counts: StatusCounts,
}

impl StatusReport {
    /// Build a report and compute counts.
    pub fn new(components: Vec<ComponentStatus>) -> Self {
        let mut counts = StatusCounts::default();
        for component in &components {
            match component.state {
                ComponentState::Operational => counts.operational += 1,
                ComponentState::Degraded { .. } => counts.degraded += 1,
                ComponentState::Unavailable { .. } => counts.unavailable += 1,
                ComponentState::NotImplemented { .. } => counts.not_implemented += 1,
                ComponentState::Planned { .. } => counts.planned += 1,
                ComponentState::SimulatedOnly { .. } => counts.simulated_only += 1,
            }
        }
        Self {
            components,
            counts,
        }
    }

    /// Look up a component by id.
    pub fn get(&self, id: &str) -> Option<&ComponentStatus> {
        self.components.iter().find(|component| component.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_serialise_with_stable_tags() {
        let status = ComponentStatus::not_implemented("firewall", "Firewall", "no backend");
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(json.contains("\"state\":\"not_implemented\""));
        assert!(json.contains("\"reason\":\"no backend\""));
    }

    #[test]
    fn counts_aggregate_all_states() {
        let report = StatusReport::new(vec![
            ComponentStatus::operational("a", "A"),
            ComponentStatus::not_implemented("b", "B", "x"),
            ComponentStatus::unavailable("c", "C", "y"),
            ComponentStatus::planned("d", "D", "z"),
            ComponentStatus::degraded("e", "E", "f"),
        ]);
        assert_eq!(report.counts.operational, 1);
        assert_eq!(report.counts.not_implemented, 1);
        assert_eq!(report.counts.unavailable, 1);
        assert_eq!(report.counts.planned, 1);
        assert_eq!(report.counts.degraded, 1);
        assert!(report.get("b").is_some());
        assert!(report.get("missing").is_none());
    }

    #[test]
    fn operational_states_have_no_reason() {
        let ok = ComponentStatus::operational("x", "X");
        assert!(ok.state.reason().is_none());
        assert!(ok.is_operational());
        let bad = ComponentStatus::planned("y", "Y", "later");
        assert_eq!(bad.state.reason(), Some("later"));
        assert_eq!(bad.state.id(), "planned");
        assert!(!bad.is_operational());
    }
}
