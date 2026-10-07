//! System monitor: CPU, memory, optional sensors and process listing.
//!
//! All numbers are read from the host (`/proc`, `/sys`). Missing sensors are
//! reported as unavailable — never simulated.

use std::{
    collections::HashMap,
    time::Instant,
};

use serde::Serialize;

use crate::status::ComponentStatus;

/// CPU usage since the previous sample.
#[derive(Clone, Debug, Serialize)]
pub struct CpuInfo {
    /// Percent since the last sample; `None` until a baseline exists or when
    /// `/proc/stat` is unreadable.
    pub usage_percent: Option<f64>,
    pub core_count: Option<usize>,
    pub note: Option<String>,
}

/// Memory figures straight from `/proc/meminfo`.
#[derive(Clone, Debug, Serialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

/// Battery status read from `/sys/class/power_supply`.
#[derive(Clone, Debug, Serialize)]
pub struct BatteryReport {
    /// Charge percent when a battery device exists.
    pub percent: Option<u8>,
    pub status: ComponentStatus,
}

/// Thermal status read from `/sys/class/thermal`.
#[derive(Clone, Debug, Serialize)]
pub struct TemperatureReport {
    /// Temperature in millidegrees Celsius when a sensor exists.
    pub millidegrees: Option<i64>,
    pub status: ComponentStatus,
}

/// One sampled view of the system.
#[derive(Clone, Debug, Serialize)]
pub struct MonitorSnapshot {
    pub cpu: CpuInfo,
    pub memory: Option<MemoryInfo>,
    pub battery: BatteryReport,
    pub temperature: TemperatureReport,
    pub sampled_at: String,
    /// False until the second sample makes a delta computable.
    pub baseline_ready: bool,
}

/// One process read from `/proc`.
#[derive(Clone, Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    /// Process state letter from `/proc/<pid>/stat` (`R`, `S`, `Z`, ...).
    pub state: Option<String>,
    /// Percent since the previous process sample; `None` on first sample.
    pub cpu_percent: Option<f64>,
    pub memory_rss_bytes: Option<u64>,
    pub uptime_seconds: Option<u64>,
    /// Open file descriptors when readable; `None` when permission is denied.
    pub open_files: Option<usize>,
}
/// Parse the aggregate `cpu` line from `/proc/stat`.
pub fn parse_cpu_counters(line: &str) -> Option<(u64, u64)> {
    let mut fields = line.split_whitespace();
    if fields.next() != Some("cpu") {
        return None;
    }
    let values: Vec<u64> = fields
        .map(|field| field.parse::<u64>().unwrap_or(0))
        .collect();
    if values.len() < 4 {
        return None;
    }
    let total: u64 = values.iter().sum();
    let iowait = values.get(4).copied().unwrap_or(0);
    let idle = values[3] + iowait;
    Some((total, idle))
}

/// Parse `/proc/meminfo` into [`MemoryInfo`].
pub fn parse_meminfo(text: &str) -> Option<MemoryInfo> {
    let mut total = None;
    let mut available = None;
    let mut swap_total = None;
    let mut swap_free = None;
    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value = rest
            .split_whitespace()
            .next()
            .and_then(|raw| raw.parse::<u64>().ok());
        let Some(value) = value else { continue };
        match key {
            "MemTotal" => total = Some(value),
            "MemAvailable" => available = Some(value),
            "SwapTotal" => swap_total = Some(value),
            "SwapFree" => swap_free = Some(value),
            _ => {}
        }
    }
    let total_kb = total?;
    let available_kb = available.unwrap_or(0);
    let swap_total_kb = swap_total.unwrap_or(0);
    let swap_free_kb = swap_free.unwrap_or(0);
    Some(MemoryInfo {
        total_bytes: total_kb * 1024,
        available_bytes: available_kb * 1024,
        used_bytes: (total_kb.saturating_sub(available_kb)) * 1024,
        swap_total_bytes: swap_total_kb * 1024,
        swap_used_bytes: (swap_total_kb.saturating_sub(swap_free_kb)) * 1024,
    })
}

/// CPU percent from two counter samples.
pub fn cpu_percent(previous: (u64, u64), current: (u64, u64)) -> Option<f64> {
    let total_delta = current.0.saturating_sub(previous.0);
    let idle_delta = current.1.saturating_sub(previous.1);
    if total_delta == 0 {
        return None;
    }
    let busy = total_delta.saturating_sub(idle_delta);
    Some((busy as f64 / total_delta as f64) * 100.0)
}
/// Selected fields parsed from `/proc/<pid>/stat`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStat {
    pub pid: u32,
    pub comm: String,
    pub state: String,
    pub parent_pid: Option<u32>,
    pub utime: u64,
    pub stime: u64,
    pub starttime: u64,
    pub rss_pages: u64,
}

/// Parse `/proc/<pid>/stat`, tolerating process names with spaces/parens.
pub fn parse_process_stat(text: &str) -> Option<ProcessStat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = text[..open].trim().parse::<u32>().ok()?;
    let comm = text[open + 1..close].to_owned();
    let rest: Vec<&str> = text[close + 1..].split_whitespace().collect();
    // rest[0] is field 3 (state); field N lives at rest index N - 3.
    let state = rest.first().copied()?.to_owned();
    let field = |index: usize| -> Option<u64> { rest.get(index - 3)?.parse::<u64>().ok() };
    Some(ProcessStat {
        pid,
        comm,
        state,
        parent_pid: field(4).map(|value| value as u32),
        utime: field(14)?,
        stime: field(15)?,
        starttime: field(22)?,
        rss_pages: field(24)?,
    })
}

/// System clock ticks per second (usually 100).
pub fn clock_ticks_per_sec() -> f64 {
    static HZ: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *HZ.get_or_init(|| {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz > 0 {
            hz as f64
        } else {
            100.0
        }
    })
}

/// Memory page size in bytes.
pub fn page_size() -> u64 {
    static PAGE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size > 0 {
            size as u64
        } else {
            4096
        }
    })
}

fn read_uptime_seconds() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    text.split_whitespace().next()?.parse::<f64>().ok()
}

/// Battery charge read from `/sys/class/power_supply`.
pub fn read_battery() -> BatteryReport {
    if let Ok(entries) = std::fs::read_dir("/sys/class/power_supply") {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.file_name().is_some_and(|name| {
                name.to_string_lossy().starts_with("BAT")
            }) {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(path.join("capacity")) {
                if let Ok(percent) = raw.trim().parse::<u8>() {
                    if percent <= 100 {
                        return BatteryReport {
                            percent: Some(percent),
                            status: ComponentStatus::operational("battery", "Battery"),
                        };
                    }
                }
            }
        }
    }
    BatteryReport {
        percent: None,
        status: ComponentStatus::unavailable(
            "battery",
            "Battery",
            "no battery device exposed under /sys/class/power_supply",
        ),
    }
}

/// Thermal reading from `/sys/class/thermal`.
pub fn read_temperature() -> TemperatureReport {
    if let Ok(raw) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
        if let Ok(millidegrees) = raw.trim().parse::<i64>() {
            return TemperatureReport {
                millidegrees: Some(millidegrees),
                status: ComponentStatus::operational("temperature", "Temperature sensor"),
            };
        }
    }
    TemperatureReport {
        millidegrees: None,
        status: ComponentStatus::unavailable(
            "temperature",
            "Temperature sensor",
            "no thermal sensor exposed under /sys/class/thermal",
        ),
    }
}
/// Stateful sampler: keeps previous counters so deltas are real measurements.
#[derive(Default)]
pub struct Sampler {
    previous_total: Option<(u64, u64)>,
    previous_processes: HashMap<u32, (u64, Instant)>,
    last: Option<MonitorSnapshot>,
}

fn rfc3339_now() -> String {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unavailable".to_owned())
}

fn read_cpu_counters() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().find(|line| line.starts_with("cpu "))?;
    parse_cpu_counters(line)
}

fn read_core_count() -> Option<usize> {
    std::thread::available_parallelism()
        .ok()
        .map(|count| count.get())
}

impl Sampler {
    /// Create a sampler without a baseline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a system sample (CPU, memory, sensors).
    pub fn sample(&mut self) -> MonitorSnapshot {
        let cpu = match read_cpu_counters() {
            Some(current) => {
                let usage = self
                    .previous_total
                    .and_then(|previous| cpu_percent(previous, current));
                self.previous_total = Some(current);
                let note = if usage.is_none() {
                    Some("collecting baseline sample; usage appears after the next tick".to_owned())
                } else {
                    None
                };
                CpuInfo {
                    usage_percent: usage,
                    core_count: read_core_count(),
                    note,
                }
            }
            None => CpuInfo {
                usage_percent: None,
                core_count: None,
                note: Some("/proc/stat is not readable on this host".to_owned()),
            },
        };
        let memory = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| parse_meminfo(&text));
        let snapshot = MonitorSnapshot {
            baseline_ready: cpu.usage_percent.is_some(),
            cpu,
            memory,
            battery: read_battery(),
            temperature: read_temperature(),
            sampled_at: rfc3339_now(),
        };
        self.last = Some(snapshot.clone());
        snapshot
    }

    /// The most recent snapshot without sampling again.
    pub fn last_snapshot(&self) -> Option<&MonitorSnapshot> {
        self.last.as_ref()
    }

    /// List processes; CPU percent comes from deltas between calls.
    pub fn processes(&mut self) -> Vec<ProcessInfo> {
        let hz = clock_ticks_per_sec();
        let page = page_size();
        let uptime = read_uptime_seconds();
        let now = Instant::now();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut out: Vec<ProcessInfo> = Vec::new();
        let mut seen: Vec<u32> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else { continue };
            let Ok(stat_text) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(stat) = parse_process_stat(&stat_text) else {
                continue;
            };
            let ticks = stat.utime.saturating_add(stat.stime);
            let cpu_percent = self
                .previous_processes
                .get(&pid)
                .and_then(|(previous_ticks, previous_at)| {
                    let elapsed = now.duration_since(*previous_at).as_secs_f64();
                    if elapsed <= 0.0 || hz <= 0.0 {
                        return None;
                    }
                    let delta = ticks.saturating_sub(*previous_ticks) as f64;
                    Some(delta / hz / elapsed * 100.0)
                });
            self.previous_processes.insert(pid, (ticks, now));
            seen.push(pid);
            out.push(ProcessInfo {
                pid,
                name: stat.comm,
                parent_pid: stat.parent_pid,
                state: Some(stat.state),
                cpu_percent,
                memory_rss_bytes: Some(stat.rss_pages.saturating_mul(page)),
                uptime_seconds: uptime.map(|seconds| {
                    (seconds - stat.starttime as f64 / hz).max(0.0) as u64
                }),
                open_files: std::fs::read_dir(entry.path().join("fd"))
                    .map(|fds| fds.count())
                    .ok(),
            });
        }
        self.previous_processes
            .retain(|pid, _| seen.contains(pid));
        out.sort_by_key(|process| process.pid);
        out
    }
}

/// Component status for the system monitor.
pub fn component_status() -> ComponentStatus {
    ComponentStatus::operational("system-monitor", "System Monitor")
        .with_note("CPU and memory are read from /proc; optional sensors report unavailable when absent")
}

/// GPU monitoring has no backend in this phase.
pub fn gpu_component() -> ComponentStatus {
    ComponentStatus::unavailable(
        "gpu",
        "GPU monitoring",
        "no GPU backend or telemetry interface exists in this runtime",
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aggregate_cpu_counters() {
        let (total, idle) =
            parse_cpu_counters("cpu  100 0 100 800 10 0 0 0 0 0").expect("parse");
        assert_eq!(total, 1010);
        assert_eq!(idle, 810);
        assert!(parse_cpu_counters("cpu0 1 2 3 4").is_none());
        assert!(parse_cpu_counters("not cpu").is_none());
    }

    #[test]
    fn computes_cpu_percent_from_deltas() {
        let previous = (1000, 800);
        let current = (1200, 900);
        let percent = cpu_percent(previous, current).expect("percent");
        assert!((percent - 50.0).abs() < f64::EPSILON);
        assert_eq!(cpu_percent((1000, 800), (1000, 800)), None);
    }

    #[test]
    fn parses_meminfo() {
        let text = "MemTotal:       16384000 kB\nMemAvailable:   8192000 kB\nSwapTotal: 2048000 kB\nSwapFree: 1024000 kB\n";
        let info = parse_meminfo(text).expect("parse");
        assert_eq!(info.total_bytes, 16384000 * 1024);
        assert_eq!(info.available_bytes, 8192000 * 1024);
        assert_eq!(info.used_bytes, (16384000 - 8192000) * 1024);
        assert_eq!(info.swap_used_bytes, (2048000 - 1024000) * 1024);
        assert!(parse_meminfo("garbage").is_none());
    }

    #[test]
    fn parses_process_stat_with_awkward_comm() {
        let line = "1234 (Web Content) R 1000 1234 1234 0 -1 4194304 100 0 0 0 15 7 0 0 20 0 3 0 123456 1048576 500";
        let stat = parse_process_stat(line).expect("parse");
        assert_eq!(stat.pid, 1234);
        assert_eq!(stat.comm, "Web Content");
        assert_eq!(stat.state, "R");
        assert_eq!(stat.parent_pid, Some(1000));
        assert_eq!(stat.utime, 15);
        assert_eq!(stat.stime, 7);
        assert_eq!(stat.starttime, 123456);
        assert_eq!(stat.rss_pages, 500);
        assert!(parse_process_stat("no parens here 1 2 3").is_none());
    }

    #[test]
    fn sampler_and_process_list_read_real_host_data() {
        let mut sampler = Sampler::new();
        let first = sampler.sample();
        assert!(first.sampled_at.contains('T'));
        assert!(sampler.last_snapshot().is_some());
        // Memory is reported when /proc/meminfo exists (Linux); otherwise None.
        if std::path::Path::new("/proc/meminfo").exists() {
            assert!(first.memory.is_some());
            assert!(first.cpu.core_count.unwrap_or(1) >= 1);
        }
        let processes = sampler.processes();
        if std::path::Path::new("/proc").exists() {
            assert!(!processes.is_empty());
            assert!(processes.iter().any(|process| process.pid > 0));
        }
        // A second sample may compute a CPU delta or stay None (too little
        // elapsed time); both outcomes are honest, never fabricated.
        let second = sampler.sample();
        if let Some(percent) = second.cpu.usage_percent {
            assert!((0.0..=100.0).contains(&percent));
        }
    }

    #[test]
    fn sensors_report_unavailable_or_real_values() {
        let battery = read_battery();
        match battery.percent {
            Some(percent) => assert!(percent <= 100 && battery.status.is_operational()),
            None => assert!(!battery.status.is_operational()),
        }
        let temperature = read_temperature();
        match temperature.millidegrees {
            Some(value) => assert!(value.abs() < 200_000),
            None => assert!(!temperature.status.is_operational()),
        }
        assert!(!gpu_component().is_operational());
    }
}
