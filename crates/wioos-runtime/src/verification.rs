use std::{net::IpAddr, str::FromStr};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub fn parse_verify_command(line: &str) -> Result<IpAddr, &'static str> {
    let mut parts = line.split_whitespace();
    if parts.next() != Some("verify") {
        return Err("expected: verify <IP>");
    }
    let Some(raw_ip) = parts.next() else {
        return Err("missing IP address");
    };
    if parts.next().is_some() {
        return Err("expected exactly one IP address");
    }
    IpAddr::from_str(raw_ip).map_err(|_| "malformed IP address")
}

pub fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unavailable".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ipv4_and_ipv6_commands() {
        assert_eq!(
            parse_verify_command("verify 192.0.2.1").unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            parse_verify_command("verify 2001:db8::1").unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_malformed_or_injected_commands() {
        assert!(parse_verify_command("verify 192.0.2.1; echo bad").is_err());
        assert!(parse_verify_command("verify not-an-ip").is_err());
        assert!(parse_verify_command("verify").is_err());
    }
}
