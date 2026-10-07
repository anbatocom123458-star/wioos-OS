//! Central Time Service.
//!
//! Apps and the shell read the clock through this service instead of keeping
//! their own. Timezone database support is *not* available in this phase:
//! the service supports UTC plus a manual fixed offset, and reports automatic
//! timezone detection as planned.

use serde::{Deserialize, Serialize};
use time::{Month, OffsetDateTime, Weekday, UtcOffset, format_description::well_known::Rfc3339};

use crate::status::{ComponentState, ComponentStatus};

/// Date rendering preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateFormat {
    /// `2026-10-07`
    #[default]
    Iso,
    /// `07-10-2026`
    DayMonthYear,
    /// `10-07-2026`
    MonthDayYear,
}

/// User preferences for the Time Service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TimePreferences {
    /// Fixed UTC offset in minutes, range -840..=840.
    pub offset_minutes: i32,
    /// 24-hour clock when true, 12-hour when false.
    pub clock_24h: bool,
    pub date_format: DateFormat,
}

impl Default for TimePreferences {
    fn default() -> Self {
        Self {
            offset_minutes: 0,
            clock_24h: true,
            date_format: DateFormat::Iso,
        }
    }
}

impl TimePreferences {
    /// Validate the preferences; returns a human-readable error.
    pub fn validate(&self) -> Result<(), String> {
        if !(-840..=840).contains(&self.offset_minutes) {
            return Err(format!(
                "offset_minutes {} out of range (-840..=840)",
                self.offset_minutes
            ));
        }
        Ok(())
    }

    /// Timezone label: `UTC` or a fixed offset like `+07:00`.
    pub fn timezone_label(&self) -> String {
        if self.offset_minutes == 0 {
            return "UTC".to_owned();
        }
        let sign = if self.offset_minutes < 0 { '-' } else { '+' };
        let abs = self.offset_minutes.abs();
        format!("{sign}{:02}:{:02}", abs / 60, abs % 60)
    }
}

/// Broken-down local time, letting clients render per their own layout rules.
#[derive(Clone, Debug, Serialize)]
pub struct TimeParts {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Lowercase weekday name, e.g. `wednesday`.
    pub weekday: String,
}

/// A snapshot from the Time Service.
#[derive(Clone, Debug, Serialize)]
pub struct TimeSnapshot {
    pub utc_rfc3339: String,
    pub parts: TimeParts,
    pub offset_minutes: i32,
    pub timezone_label: String,
    pub clock_24h: bool,
    pub date_format: DateFormat,
    /// Status of automatic timezone detection (never faked).
    pub automatic_timezone: ComponentState,
}
/// Read the current time through the Time Service.
pub fn snapshot(prefs: &TimePreferences) -> TimeSnapshot {
    let prefs_valid = prefs.validate().is_ok();
    let offset = if prefs_valid {
        prefs.offset_minutes
    } else {
        0
    };
    let now = OffsetDateTime::now_utc()
        .to_offset(UtcOffset::from_whole_seconds(offset * 60).unwrap_or(UtcOffset::UTC));
    TimeSnapshot {
        utc_rfc3339: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unavailable".to_owned()),
        parts: TimeParts {
            year: now.year(),
            month: month_number(now.month()),
            day: now.day(),
            hour: now.hour(),
            minute: now.minute(),
            second: now.second(),
            weekday: weekday_name(now.weekday()).to_owned(),
        },
        offset_minutes: offset,
        timezone_label: prefs.timezone_label(),
        clock_24h: prefs.clock_24h,
        date_format: prefs.date_format,
        automatic_timezone: ComponentState::Planned {
            reason: "timezone database is not bundled with this runtime; only \
                     UTC and a manual fixed offset are supported"
                .to_owned(),
        },
    }
}

/// Status entry for the Time Service component report.
pub fn component_status() -> ComponentStatus {
    ComponentStatus::operational("time-service", "Time Service").with_note(
        "UTC and manual fixed offsets supported; automatic timezone detection is planned",
    )
}

fn month_number(month: Month) -> u8 {
    match month {
        Month::January => 1,
        Month::February => 2,
        Month::March => 3,
        Month::April => 4,
        Month::May => 5,
        Month::June => 6,
        Month::July => 7,
        Month::August => 8,
        Month::September => 9,
        Month::October => 10,
        Month::November => 11,
        Month::December => 12,
    }
}

fn weekday_name(weekday: Weekday) -> &'static str {
    match weekday {
        Weekday::Monday => "monday",
        Weekday::Tuesday => "tuesday",
        Weekday::Wednesday => "wednesday",
        Weekday::Thursday => "thursday",
        Weekday::Friday => "friday",
        Weekday::Saturday => "saturday",
        Weekday::Sunday => "sunday",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preferences_are_utc_24h_iso() {
        let prefs = TimePreferences::default();
        assert_eq!(prefs.offset_minutes, 0);
        assert!(prefs.clock_24h);
        assert_eq!(prefs.date_format, DateFormat::Iso);
        assert_eq!(prefs.timezone_label(), "UTC");
        assert!(prefs.validate().is_ok());
    }

    #[test]
    fn offset_labels_and_validation() {
        let mut prefs = TimePreferences {
            offset_minutes: 420,
            ..Default::default()
        };
        assert_eq!(prefs.timezone_label(), "+07:00");
        prefs.offset_minutes = -330;
        assert_eq!(prefs.timezone_label(), "-05:30");
        prefs.offset_minutes = 900;
        assert!(prefs.validate().is_err());
    }

    #[test]
    fn snapshot_reports_honest_timezone_state() {
        let snapshot = snapshot(&TimePreferences::default());
        assert!(snapshot.utc_rfc3339.contains('T'));
        assert!(snapshot.parts.year >= 2024);
        assert!((1..=12).contains(&snapshot.parts.month));
        assert!((1..=31).contains(&snapshot.parts.day));
        assert!(snapshot.parts.hour <= 23);
        assert!(!snapshot.parts.weekday.is_empty());
        assert!(matches!(
            snapshot.automatic_timezone,
            ComponentState::Planned { .. }
        ));
    }

    #[test]
    fn invalid_offset_falls_back_to_utc_in_snapshot() {
        let prefs = TimePreferences {
            offset_minutes: 5000,
            ..Default::default()
        };
        let snapshot = snapshot(&prefs);
        assert_eq!(snapshot.offset_minutes, 0);
    }
}
