//! Small HTTP helpers: client IP resolution, origin checks, UA parsing and
//! path/CIDR matching. Pure functions plus a couple of config reads.

use super::*;

/// JS-compatible metric bucket: epoch seconds rounded down to the hour.
pub(crate) fn hourly_bucket(now_ms: i64) -> i64 {
    (now_ms / 1000 / 3600) * 3600
}

pub(crate) fn is_loopback_or_private(addr: &str) -> bool {
    if addr == "::1" || addr.starts_with("127.") || addr.starts_with("::ffff:127.") {
        return true;
    }
    if addr.starts_with("10.")
        || addr.starts_with("192.168.")
        || addr.starts_with("169.254.")
        || addr.starts_with("fc")
        || addr.starts_with("fd")
    {
        return true;
    }
    if let Some(rest) = addr.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                return (16..=31).contains(&n);
            }
        }
    }
    false
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
            .map(|v| v == secret)
            .unwrap_or(false),
        _ => is_loopback_or_private(peer),
    }
}

pub(crate) fn client_ip(headers: &HeaderMap, peer: &str) -> String {
    // Forwarded headers are client-controlled. Like cap.js `getClientIp`,
    // they are only trusted when the operator declares a trusted proxy
    // (CAP_TRUST_PROXY=true); otherwise the peer address wins, so a client
    // cannot spoof an IP to dodge the limiter or the blocklist.
    if !proxy_trusted(headers, peer) {
        return peer.to_string();
    }
    let configured = settings().ip_header.clone();
    if !configured.is_empty() {
        if let Some(v) = headers.get(configured.as_str()).and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    for h in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"] {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    peer.to_string()
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

/// Whether `ip` falls inside `net` (`a.b.c.d/len`, IPv4 only).
pub(crate) fn cidr_match(net: &str, ip: &str) -> bool {
    let (base, len) = match net.split_once('/') {
        Some((b, l)) => (b, l),
        None => return net == ip,
    };
    let Ok(len) = len.parse::<u32>() else {
        return false;
    };
    if len > 32 {
        return false;
    }
    let (Ok(base), Ok(ip)) = (
        base.parse::<std::net::Ipv4Addr>(),
        ip.parse::<std::net::Ipv4Addr>(),
    ) else {
        return false;
    };
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (u32::from(base) & mask) == (u32::from(ip) & mask)
}
