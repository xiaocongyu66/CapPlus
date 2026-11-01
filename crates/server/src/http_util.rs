//! Small HTTP helpers: client IP resolution, origin checks, UA parsing and
//! path/CIDR matching. Pure functions plus a couple of config reads.

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cap_store::KeyConfig;

use crate::settings;

/// JS-compatible metric bucket: epoch seconds rounded down to the hour.
pub(crate) fn hourly_bucket(now_ms: i64) -> i64 {
    (now_ms / 1000 / 3600) * 3600
}

pub(crate) fn is_loopback_or_private(addr: &str) -> bool {
    use std::net::IpAddr;
    let ip = match addr.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            // fc00::/7 unique-local, fe80::/10 link-local
            v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

pub(crate) fn proxy_trusted(headers: &HeaderMap, peer: &str) -> bool {
    let cfg = settings();
    if !cfg.trust_proxy {
        return false;
    }
    match Some(cfg.proxy_secret.as_str()) {
        Some(secret) if !secret.is_empty() => headers
            .get("x-cap-proxy-secret")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                use sha2::{Digest, Sha256};
                // Compare fixed-size digests so the comparison time does not
                // depend on how much of the secret matched.
                let a = Sha256::digest(v.as_bytes());
                let b = Sha256::digest(secret.as_bytes());
                a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            })
            .unwrap_or(false),
        _ => is_loopback_or_private(peer),
    }
}

pub(crate) fn client_ip(headers: &HeaderMap, peer: &str) -> String {
    // Forwarded headers are client-controlled. They are only consulted when
    // the operator declares a trusted proxy (CAP_TRUST_PROXY=true); otherwise
    // the peer address wins, so a client cannot spoof an IP to dodge the
    // limiter or the blocklist.
    if !proxy_trusted(headers, peer) {
        return peer.to_string();
    }
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let configured = settings().ip_header.clone();
    if !configured.is_empty() {
        // An explicitly configured header is the only source: falling through
        // to XFF would let a client supply the address when the header is
        // absent.
        return get(configured.as_str())
            .and_then(forwarded_client)
            .unwrap_or_else(|| peer.to_string());
    }
    // Single-value headers that a proxy sets (overwrites) rather than appends.
    for h in ["cf-connecting-ip", "x-real-ip"] {
        if let Some(ip) = get(h).and_then(forwarded_client) {
            return ip;
        }
    }
    get("x-forwarded-for")
        .and_then(forwarded_client)
        .unwrap_or_else(|| peer.to_string())
}

/// Pick the client from a forwarded list. Proxies append, so everything left
/// of the last hop the operator controls is attacker-supplied: walk from the
/// right and take the first address that is not one of our (private) proxies.
fn forwarded_client(v: &str) -> Option<String> {
    let hops: Vec<&str> = v
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    hops.iter()
        .rev()
        .find(|h| !is_loopback_or_private(h))
        .or_else(|| hops.first())
        .filter(|h| h.parse::<std::net::IpAddr>().is_ok())
        .map(|h| h.to_string())
}

pub(crate) fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

pub(crate) fn cors_origins(cfg: &KeyConfig) -> Vec<String> {
    cfg.cors_origins.clone().unwrap_or_default()
}

pub(crate) fn same_origin(headers: &HeaderMap) -> bool {
    let origin = header_str(headers, "origin");
    if origin.is_empty() {
        return false;
    }
    // Only the Host the client actually addressed. `X-Forwarded-Host` is
    // client-controlled and made the check trivially spoofable together with
    // a forged `Origin`; behind a proxy `Host` is preserved by default.
    let host = header_str(headers, "host");
    if host.is_empty() {
        return false;
    }
    let Some((_, rest)) = origin.split_once("://") else {
        return false;
    };
    let Some(origin_host) = rest.split('/').next() else {
        return false;
    };
    origin_host.eq_ignore_ascii_case(&host)
}

pub(crate) fn html_response(status: StatusCode, csp: Option<&str>, body: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if let Some(csp) = csp {
        if let Ok(v) = HeaderValue::from_str(csp) {
            headers.insert("content-security-policy", v);
        }
    }
    (status, headers, body).into_response()
}

/// Platform / OS from a User-Agent string, matching `parseUA` in `cap.js`.
pub(crate) fn parse_ua(ua: &str) -> (Option<&'static str>, Option<&'static str>) {
    if ua.is_empty() {
        return (None, None);
    }
    let os = if ua.contains("iPad") {
        Some("iPadOS")
    } else if ua.contains("iPhone") {
        Some("iOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("Macintosh") || ua.contains("Mac OS X") {
        Some("macOS")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    let platform = if ua.contains("iPhone")
        || (ua.contains("Android") && ua.contains("Mobile"))
    {
        Some("Phone")
    } else if ua.contains("iPad")
        || (ua.contains("Android") && !ua.contains("Mobile"))
        || ua.contains("Tablet")
    {
        Some("Tablet")
    } else if ua.contains("Macintosh")
        || ua.contains("Windows")
        || ua.contains("Linux")
        || ua.contains("CrOS")
    {
        Some("Desktop")
    } else {
        None
    };
    (platform, os)
}

/// 判断 IPv4 或 IPv6 地址是否属于给定网段。
pub(crate) fn cidr_match(net: &str, ip: &str) -> bool {
    use std::net::IpAddr;
    let (base, prefix) = match net.split_once('/') {
        Some((base, prefix)) => (base, Some(prefix)),
        None => (net, None),
    };
    let (Ok(base), Ok(ip)) = (base.parse::<IpAddr>(), ip.parse::<IpAddr>()) else {
        return false;
    };
    let prefix = match prefix.map(str::parse::<u32>).transpose() {
        Ok(prefix) => prefix,
        Err(_) => return false,
    };
    match (base, ip) {
        (IpAddr::V4(base), IpAddr::V4(ip)) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 { return false; }
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            (u32::from(base) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(base), IpAddr::V6(ip)) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 { return false; }
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            (u128::from(base) & mask) == (u128::from(ip) & mask)
        }
        (IpAddr::V4(_), IpAddr::V6(ip)) => ip
            .to_ipv4_mapped()
            .is_some_and(|ip| cidr_match(net, &ip.to_string())),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_and_ipv6_cidrs() {
        for (net, ip) in [
            ("192.0.2.0/24", "192.0.2.42"),
            ("0.0.0.0/0", "203.0.113.1"),
            ("2001:db8::/32", "2001:db8:abcd::1"),
            ("::/0", "fd00::1"),
            ("2001:db8::1/128", "2001:0db8:0:0:0:0:0:1"),
            ("192.0.2.0/24", "::ffff:192.0.2.42"),
        ] {
            assert!(cidr_match(net, ip), "{net} {ip}");
        }
        for (net, ip) in [
            ("2001:db8::/32", "2001:db9::1"),
            ("::/129", "::1"),
            ("192.0.2.0/33", "192.0.2.1"),
            ("::/0", "192.0.2.1"),
            ("invalid/24", "192.0.2.1"),
        ] {
            assert!(!cidr_match(net, ip), "{net} {ip}");
        }
    }

    #[test]
    fn private_ranges() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.1.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(is_loopback_or_private(ip), "{ip}");
        }
        for ip in ["172.2.0.1", "172.200.1.1", "172.32.0.1", "8.8.8.8", "2001:db8::1", "fcdn.example", ""] {
            assert!(!is_loopback_or_private(ip), "{ip}");
        }
    }

    #[test]
    fn forwarded_takes_rightmost_public_hop() {
        // Client-supplied left part is ignored.
        assert_eq!(forwarded_client("1.1.1.1, 203.0.113.7").as_deref(), Some("203.0.113.7"));
        // Our own proxies on the right are skipped.
        assert_eq!(forwarded_client("6.6.6.6, 203.0.113.7, 10.0.0.2").as_deref(), Some("203.0.113.7"));
        // All-private chain: first hop.
        assert_eq!(forwarded_client("10.0.0.5, 10.0.0.2").as_deref(), Some("10.0.0.5"));
        // Garbage is rejected rather than used as a bucket key.
        assert_eq!(forwarded_client("not-an-ip"), None);
        assert_eq!(forwarded_client("  ,  "), None);
    }
}
