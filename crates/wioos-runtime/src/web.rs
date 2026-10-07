use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use axum::{
    Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Html,
    routing::get,
};
use ipnet::IpNet;
use tracing::error;

use crate::{
    state::{VerificationStatus, VerificationStore},
    verification,
};

#[derive(Clone)]
struct AppState {
    verification: VerificationStore,
    trusted_proxy_cidrs: Vec<IpNet>,
}

pub fn router(verification: VerificationStore, trusted_proxy_cidrs: Vec<IpNet>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/health", get(|| async { "ok" }))
        .with_state(AppState {
            verification,
            trusted_proxy_cidrs,
        })
}

async fn index(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Html<&'static str>, StatusCode> {
    let ip = resolve_client_ip(peer.ip(), &headers, &state.trusted_proxy_cidrs);
    let status = state
        .verification
        .record_request(ip)
        .await
        .map_err(|cause| {
            error!(%cause, "Failed to persist verification request");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let (status_name, page) = match status {
        VerificationStatus::Pending => ("PENDING", WAITING_PAGE),
        VerificationStatus::Verified => ("VERIFIED", READY_PAGE),
    };
    println!(
        "WIOOS VERIFICATION REQUEST\nIP: {ip}\nTIME: {}\nSTATUS: {status_name}",
        verification::timestamp()
    );
    Ok(Html(page))
}

fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpNet]) -> IpAddr {
    if !trusted_proxies.iter().any(|range| range.contains(&peer)) {
        return peer;
    }
    let Some(header) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
    else {
        return peer;
    };
    let forwarded = header
        .split(',')
        .map(|entry| IpAddr::from_str(entry.trim()))
        .collect::<Result<Vec<_>, _>>();
    let Ok(forwarded) = forwarded else {
        return peer;
    };
    let mut current = peer;
    for candidate in forwarded.into_iter().rev() {
        if !trusted_proxies.iter().any(|range| range.contains(&current)) {
            break;
        }
        current = candidate;
    }
    current
}

const WAITING_PAGE: &str = r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>WIOOS | Waiting for verification</title><style>
:root{color-scheme:light;font-family:ui-sans-serif,system-ui,sans-serif;background:#f5f6f3;color:#192522}*{box-sizing:border-box}body{min-height:100svh;margin:0;display:grid;place-items:center;padding:24px}main{width:min(100%,520px);border-top:3px solid #287563;padding:36px 0 0;animation:arrive 380ms ease-out both}.wordmark{margin:0 0 52px;font-size:13px;font-weight:700;letter-spacing:0}.eyebrow{margin:0 0 12px;color:#287563;font-size:12px;font-weight:700}h1{margin:0;font-size:clamp(32px,8vw,48px);line-height:1.08;letter-spacing:0;font-weight:600}.copy{max-width:390px;margin:18px 0 0;color:#53615d;font-size:15px;line-height:1.6}.rule{margin-top:52px;border:0;border-top:1px solid #d9dfda}footer{margin-top:16px;color:#68746f;font-size:12px}@keyframes arrive{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important}}
</style></head><body><main><p class="wordmark">WIOOS</p><p class="eyebrow">ACCESS CONTROL</p><h1>Waiting for verification</h1><p class="copy">This request is pending operator approval. This page will become available after verification.</p><hr class="rule"><footer>WIOOS Runtime Prototype</footer></main></body></html>"##;

const READY_PAGE: &str = r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WIOOS Runtime Prototype</title><style>:root{font-family:ui-sans-serif,system-ui,sans-serif;background:#f5f6f3;color:#192522}body{min-height:100svh;margin:0;display:grid;place-items:center;padding:24px}main{width:min(100%,520px);border-top:3px solid #287563;padding-top:36px}p{color:#53615d;line-height:1.6}h1{font-size:36px;letter-spacing:0}.wordmark{color:#192522;font-size:13px;font-weight:700}</style></head><body><main><p class="wordmark">WIOOS</p><h1>Access granted</h1><p>The runtime prototype is online. The WIOOS system interface and services are not implemented yet.</p></main></body></html>"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(values: &[&str]) -> Vec<IpNet> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn ignores_forwarded_headers_from_untrusted_peers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
        let peer = "198.51.100.5".parse().unwrap();
        assert_eq!(
            resolve_client_ip(peer, &headers, &ranges(&["10.0.0.0/8"])),
            peer
        );
    }

    #[test]
    fn resolves_forwarded_chain_through_trusted_proxies() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8, 10.0.0.2".parse().unwrap());
        let peer = "10.0.0.3".parse().unwrap();
        assert_eq!(
            resolve_client_ip(peer, &headers, &ranges(&["10.0.0.0/8"])),
            "203.0.113.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn malformed_forwarded_chain_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        let peer = "10.0.0.3".parse().unwrap();
        assert_eq!(
            resolve_client_ip(peer, &headers, &ranges(&["10.0.0.0/8"])),
            peer
        );
    }
}
