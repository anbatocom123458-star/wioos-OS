//! Network Center: read-only monitoring plus an explicit action interface.
//!
//! Interface statistics, addresses and DNS servers are read from the host.
//! Management actions (scan, connect, static IP, proxy) have no backend in
//! this runtime and always report `not_implemented`.

use std::{
    collections::BTreeMap,
    net::IpAddr,
};

use serde::Serialize;

use crate::status::{ComponentState, ComponentStatus};

/// One network interface with real counters and addresses.
#[derive(Clone, Debug, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    /// `None` when interface flags could not be read.
    pub up: Option<bool>,
    pub running: Option<bool>,
    /// Receive bytes from `/proc/net/dev`; `None` when unreadable.
    pub rx_bytes: Option<u64>,
    /// Transmit bytes from `/proc/net/dev`; `None` when unreadable.
    pub tx_bytes: Option<u64>,
    pub addresses: Vec<IpAddr>,
}

/// DNS servers read from `/etc/resolv.conf`.
#[derive(Clone, Debug, Serialize)]
pub struct DnsReport {
    pub servers: Vec<IpAddr>,
    pub source: String,
}

/// Wi-Fi state read from `/proc/net/wireless`.
#[derive(Clone, Debug, Serialize)]
pub struct WifiReport {
    /// True when a wireless interface is visible to the kernel.
    pub present: bool,
    pub interface: Option<String>,
    /// Signal level in dBm as reported by the kernel.
    pub signal_dbm: Option<i64>,
    pub status: ComponentStatus,
}

/// What the Network Center can actually do right now.
#[derive(Clone, Debug, Serialize)]
pub struct NetworkCapabilities {
    /// Reading interfaces/addresses/DNS works.
    pub read_status: bool,
    pub wifi_scan: ComponentState,
    pub wifi_connect: ComponentState,
    pub wifi_forget: ComponentState,
    pub interface_enable_disable: ComponentState,
    pub static_ip: ComponentState,
    pub dhcp_control: ComponentState,
    pub proxy_config: ComponentState,
    pub dns_config: ComponentState,
    pub latency_probe: ComponentState,
    pub driver_status: ComponentState,
    pub firmware_status: ComponentState,
}

/// Full Network Center report.
#[derive(Clone, Debug, Serialize)]
pub struct NetworkReport {
    pub interfaces: Vec<InterfaceInfo>,
    pub dns: Option<DnsReport>,
    pub wifi: WifiReport,
    pub capabilities: NetworkCapabilities,
    pub has_ipv4: bool,
    pub has_ipv6: bool,
    pub status: ComponentStatus,
}

/// Error for network actions that have no backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionError {
    pub action: String,
    pub reason: String,
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network action '{}' not implemented: {}", self.action, self.reason)
    }
}

impl std::error::Error for ActionError {}
/// Parse `/proc/net/dev` into `(interface, rx_bytes, tx_bytes)` rows.
pub fn parse_proc_net_dev(text: &str) -> Vec<(String, u64, u64)> {
    let mut rows = Vec::new();
    for line in text.lines().skip(2) {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<u64> = counters
            .split_whitespace()
            .filter_map(|field| field.parse::<u64>().ok())
            .collect();
        if fields.len() < 9 {
            continue;
        }
        rows.push((name.trim().to_owned(), fields[0], fields[8]));
    }
    rows
}

/// Parse `/etc/resolv.conf` nameserver entries.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        if let Some(raw) = parts.next() {
            if let Ok(address) = raw.parse::<IpAddr>() {
                if !servers.contains(&address) {
                    servers.push(address);
                }
            }
        }
        if servers.len() >= 4 {
            break;
        }
    }
    servers
}

/// Parse `/proc/net/wireless` for the first wireless interface and its signal.
pub fn parse_proc_net_wireless(text: &str) -> Option<(String, Option<i64>)> {
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // columns: status, link quality, level (dBm), noise.
        let signal = fields
            .get(2)
            .and_then(|raw| raw.parse::<f64>().ok())
            .map(|value| value as i64);
        return Some((name.trim().to_owned(), signal));
    }
    None
}

fn read_interface_counters() -> BTreeMap<String, (u64, u64)> {
    std::fs::read_to_string("/proc/net/dev")
        .map(|text| {
            parse_proc_net_dev(&text)
                .into_iter()
                .map(|(name, rx, tx)| (name, (rx, tx)))
                .collect()
        })
        .unwrap_or_default()
}

/// Addresses and flags per interface via `getifaddrs(3)`.
fn collect_addresses() -> Result<BTreeMap<String, (Vec<IpAddr>, u32)>, String> {
    unsafe {
        let mut first: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut first) != 0 {
            return Err(format!(
                "getifaddrs failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut map: BTreeMap<String, (Vec<IpAddr>, u32)> = BTreeMap::new();
        let mut current = first;
        while !current.is_null() {
            let entry = &*current;
            let name = std::ffi::CStr::from_ptr(entry.ifa_name)
                .to_string_lossy()
                .into_owned();
            let flags = entry.ifa_flags;
            let slot = map.entry(name).or_insert_with(|| (Vec::new(), flags));
            slot.1 |= flags;
            if !entry.ifa_addr.is_null() {
                let socket_address = &*entry.ifa_addr;
                match socket_address.sa_family as i32 {
                    libc::AF_INET => {
                        let inet = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        let octets = inet.sin_addr.s_addr.to_ne_bytes();
                        slot.0.push(IpAddr::V4(std::net::Ipv4Addr::new(
                            octets[0],
                            octets[1],
                            octets[2],
                            octets[3],
                        )));
                    }
                    libc::AF_INET6 => {
                        let inet6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        slot.0
                            .push(IpAddr::V6(std::net::Ipv6Addr::from(inet6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(first);
        Ok(map)
    }
}
/// Assemble the Network Center report from real host reads.
pub fn report() -> NetworkReport {
    let counters = read_interface_counters();
    let addresses = collect_addresses().unwrap_or_default();
    let mut names: std::collections::BTreeSet<String> =
        counters.keys().cloned().collect();
    names.extend(addresses.keys().cloned());

    let interfaces: Vec<InterfaceInfo> = names
        .into_iter()
        .map(|name| {
            let (rx_bytes, tx_bytes) = match counters.get(&name) {
                Some((rx, tx)) => (Some(*rx), Some(*tx)),
                None => (None, None),
            };
            let (addresses_for_iface, flags) = addresses
                .get(&name)
                .map(|(list, flags)| (list.clone(), Some(*flags)))
                .unwrap_or_else(|| (Vec::new(), None));
            InterfaceInfo {
                name,
                up: flags.map(|flags| flags & libc::IFF_UP as u32 != 0),
                running: flags.map(|flags| flags & libc::IFF_RUNNING as u32 != 0),
                rx_bytes,
                tx_bytes,
                addresses: addresses_for_iface,
            }
        })
        .collect();

    let dns = std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .map(|text| DnsReport {
            servers: parse_resolv_conf(&text),
            source: "/etc/resolv.conf".to_owned(),
        });

    let wifi = match std::fs::read_to_string("/proc/net/wireless") {
        Ok(text) => match parse_proc_net_wireless(&text) {
            Some((interface, signal_dbm)) => WifiReport {
                present: true,
                interface: Some(interface),
                signal_dbm,
                status: ComponentStatus::operational("wifi-status", "Wi-Fi status").with_note(
                    "scan/connect/forget actions are not implemented in this runtime",
                ),
            },
            None => WifiReport {
                present: false,
                interface: None,
                signal_dbm: None,
                status: ComponentStatus::unavailable(
                    "wifi-status",
                    "Wi-Fi status",
                    "no wireless interface visible to the kernel",
                ),
            },
        },
        Err(_) => WifiReport {
            present: false,
            interface: None,
            signal_dbm: None,
            status: ComponentStatus::unavailable(
                "wifi-status",
                "Wi-Fi status",
                "/proc/net/wireless is not readable on this host",
            ),
        },
    };

    let no_backend = |action: &str, detail: &str| {
        ComponentState::NotImplemented {
            reason: format!("{action} requires host network control, which this userspace runtime does not provide{detail}"),
        }
    };

    let capabilities = NetworkCapabilities {
        read_status: true,
        wifi_scan: no_backend("Wi-Fi scan", ""),
        wifi_connect: no_backend("Wi-Fi connect", ""),
        wifi_forget: no_backend("Wi-Fi forget", ""),
        interface_enable_disable: no_backend("interface enable/disable", ""),
        static_ip: no_backend("static IP configuration", ""),
        dhcp_control: no_backend("DHCP control", ""),
        proxy_config: no_backend("proxy configuration", ""),
        dns_config: no_backend("DNS configuration", "; DNS servers are read-only here"),
        latency_probe: no_backend("latency probing", "; no probe target is configured"),
        driver_status: ComponentState::NotImplemented {
            reason: "driver inventory requires the Driver Manager, which is architecture-only in this phase"
                .to_owned(),
        },
        firmware_status: ComponentState::NotImplemented {
            reason: "firmware inventory requires the Driver Manager, which is architecture-only in this phase"
                .to_owned(),
        },
    };

    let has_ipv4 = interfaces
        .iter()
        .any(|interface| interface.addresses.iter().any(|address| address.is_ipv4()));
    let has_ipv6 = interfaces
        .iter()
        .any(|interface| interface.addresses.iter().any(|address| address.is_ipv6()));

    NetworkReport {
        interfaces,
        dns,
        wifi,
        capabilities,
        has_ipv4,
        has_ipv6,
        status: ComponentStatus::operational("network-center", "Network Center")
            .with_note("monitoring is read-only; management actions are not implemented"),
    }
}

fn not_implemented(action: &str) -> ActionError {
    ActionError {
        action: action.to_owned(),
        reason: "no network management backend exists in this WIOOS runtime; \
                 Wi-Fi/iface control needs host network privileges and drivers"
            .to_owned(),
    }
}

/// Wi-Fi scan (architecture interface; no backend yet).
pub fn wifi_scan() -> Result<Vec<String>, ActionError> {
    Err(not_implemented("wifi_scan"))
}

/// Wi-Fi connect (architecture interface; no backend yet).
/// The password parameter is accepted for interface completeness and never
/// logged or stored by this layer.
pub fn wifi_connect(_ssid: &str, _password: Option<&str>) -> Result<(), ActionError> {
    Err(not_implemented("wifi_connect"))
}

/// Wi-Fi disconnect (architecture interface; no backend yet).
pub fn wifi_disconnect(_ssid: &str) -> Result<(), ActionError> {
    Err(not_implemented("wifi_disconnect"))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_dev() {
        let text = "Inter-|   Receive                                                |  Transmit\n face |bytes    errs drop fifo frame compressed multicast|bytes    errs drop fifo colls carrier compressed\n    lo: 1000    0    0    0    0     0          0         0     2000    0    0    0     0       0          0\n  eth0: 500     1    2    3    4     5          6         7     900     8    9    10    11      12         13\n";
        let rows = parse_proc_net_dev(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("lo".to_owned(), 1000, 2000));
        assert_eq!(rows[1], ("eth0".to_owned(), 500, 900));
    }

    #[test]
    fn parses_resolv_conf_without_duplicates() {
        let text = "search example\nnameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n# nameserver 9.9.9.9\n";
        let servers = parse_resolv_conf(text);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], "1.1.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parses_wireless_status() {
        let text = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | track\n face | status | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\nwlp2s0: 0000   60.  -50.  -256        0      0     0     0     0     0        0\n";
        let parsed = parse_proc_net_wireless(text).expect("parse");
        assert_eq!(parsed.0, "wlp2s0");
        assert_eq!(parsed.1, Some(-50));
        assert!(parse_proc_net_wireless("no wireless here").is_none());
    }

    #[test]
    fn actions_report_not_implemented() {
        let scan = wifi_scan().expect_err("no backend");
        assert!(scan.to_string().contains("not implemented"));
        let connect = wifi_connect("ssid", Some("secret")).expect_err("no backend");
        // The error message must never contain the credentials.
        assert!(!connect.to_string().contains("secret"));
        assert!(wifi_disconnect("ssid").is_err());
    }

    #[test]
    fn report_never_claims_management_capabilities() {
        let report = report();
        assert!(report.capabilities.read_status);
        assert!(matches!(
            report.capabilities.wifi_scan,
            ComponentState::NotImplemented { .. }
        ));
        assert!(matches!(
            report.capabilities.static_ip,
            ComponentState::NotImplemented { .. }
        ));
        assert!(matches!(
            report.capabilities.dns_config,
            ComponentState::NotImplemented { .. }
        ));
        // Interfaces and addresses are real host data when readable.
        for interface in &report.interfaces {
            assert!(!interface.name.is_empty());
        }
        assert!(report.status.is_operational());
    }
}
