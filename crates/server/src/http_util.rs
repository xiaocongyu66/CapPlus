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

/// Protocol-layer fingerprint forwarded by the trusted proxy: JA3/JA4, HTTP/2
/// SETTINGS class and whether TLS was used. Unlike anything the client
/// reports, these come from the connection the proxy actually terminated, so
/// a scripted client cannot claim a browser fingerprint it does not have.
///
/// Header contract (both required, signature = hex HMAC-SHA256 of the raw
/// value with `CAP_PROXY_SECRET`):
///   x-cap-net-fp:     {"tls":true,"ja3Browser":...,"ja4Browser":...,
///                      "http2Browser":...,"uaMismatch":...}
///   x-cap-net-fp-sig: 64 hex chars
const NET_FP_HEADER: &str = "x-cap-net-fp";
const NET_FP_SIG_HEADER: &str = "x-cap-net-fp-sig";
/// Bound the value before hashing; a real fingerprint is well under this.
const NET_FP_MAX_LEN: usize = 512;

pub(crate) fn network_signals(
    headers: &HeaderMap,
    peer: &str,
) -> Option<cap_detect::NetworkSignals> {
    let cfg = settings();
    if !proxy_trusted(headers, peer) {
        return None;
    }
    // Without a shared secret there is no way to tell the proxy's headers
    // from a client's, so no network signals are derived at all.
    if cfg.proxy_secret.is_empty() {
        return None;
    }
    let mut net = parse_signed_network_fp(headers, &cfg.proxy_secret);
    // Caddy and Traefik do not compute JA3/JA4 themselves, but both set
    // `X-Forwarded-Proto`; that alone proves whether the hop the proxy
    // terminated was TLS. Explicit fields from a signed fingerprint win.
    if let Some(tls) = forwarded_tls(headers) {
        match &mut net {
            Some(n) => {
                if n.tls.is_none() {
                    n.tls = Some(tls);
                }
            }
            None => {
                net = Some(cap_detect::NetworkSignals {
                    tls: Some(tls),
                    ..Default::default()
                });
            }
        }
    }
    net
}

/// Signature + parse only; the caller decides whether the sender is trusted.
fn parse_signed_network_fp(
    headers: &HeaderMap,
    secret: &str,
) -> Option<cap_detect::NetworkSignals> {
    // A proxy that appends instead of overwriting would let a client prepend
    // an unsigned header and shadow the real one; with duplicates, trust none.
    let mut values = headers.get_all(NET_FP_HEADER).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    if raw.is_empty() || raw.len() > NET_FP_MAX_LEN || secret.is_empty() {
        return None;
    }
    let mut sigs = headers.get_all(NET_FP_SIG_HEADER).iter();
    let sig = sigs.next()?.to_str().ok()?.trim();
    if sigs.next().is_some() {
        return None;
    }
    if sig.len() != 64 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let expected = hex_hmac_sha256(secret, raw);
    // Fixed-length hex, compared without early exit.
    let ok = expected
        .as_bytes()
        .iter()
        .zip(sig.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a.to_ascii_lowercase() ^ b.to_ascii_lowercase()))
        == 0;
    if !ok {
        return None;
    }
    serde_json::from_str(raw).ok()
}

/// Transport security of the hop the proxy terminated, from the rightmost
/// `X-Forwarded-Proto` value: proxies that append put their own hop last, so
/// taking the left value would let a client prepend `https` and suppress the
/// `tls_missing` signal.
fn forwarded_tls(headers: &HeaderMap) -> Option<bool> {
    let proto = headers.get("x-forwarded-proto")?.to_str().ok()?;
    proto
        .rsplit(',')
        .map(str::trim)
        .find(|p| !p.is_empty())
        .map(|p| p.eq_ignore_ascii_case("https"))
}

fn hex_hmac_sha256(secret: &str, msg: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(msg.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(64);
    for b in out {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
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
    // X-Forwarded-For is the only default source: Caddy and Traefik set it,
    // while they neither set nor strip `CF-Connecting-IP` / `X-Real-IP`, so
    // trusting those implicitly lets any client claim an arbitrary address.
    // Operators behind Cloudflare can opt in via `RATELIMIT_IP_HEADER`.
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
    fn network_fp_requires_signature_and_shape() {
        use cap_detect::NetworkSignals;
        let secret = "proxy-secret";
        let body = r#"{"tls":true,"ja4Browser":true,"ja3Browser":false,"http2Browser":true,"uaMismatch":false}"#;
        let sig = hex_hmac_sha256(secret, body);
        let hdr = |v: &str, sig: Option<&str>| {
            let mut h = HeaderMap::new();
            h.insert(NET_FP_HEADER, HeaderValue::from_str(v).unwrap());
            if let Some(s) = sig {
                h.insert(NET_FP_SIG_HEADER, HeaderValue::from_str(s).unwrap());
            }
            h
        };
        let got = parse_signed_network_fp(&hdr(body, Some(&sig)), secret).unwrap();
        assert_eq!(
            got,
            NetworkSignals {
                tls: Some(true),
                ja4_browser: Some(true),
                ja3_browser: Some(false),
                http2_browser: Some(true),
                ua_mismatch: Some(false),
            }
        );
        // 未签名、错签名、大写 hex 均可按常量化比较判断，但篡改必须被拒。
        assert!(parse_signed_network_fp(&hdr(body, None), secret).is_none());
        assert!(parse_signed_network_fp(&hdr(body, Some("00")), secret).is_none());
        let tampered = body.replace("\"ja4Browser\":true", "\"ja4Browser\":false");
        assert!(parse_signed_network_fp(&hdr(&tampered, Some(&sig)), secret).is_none());
        // 签名正确但内容不是预期结构 → 丢弃而不是 panic。
        let bad = "not-json";
        let bad_sig = hex_hmac_sha256(secret, bad);
        assert!(parse_signed_network_fp(&hdr(bad, Some(&bad_sig)), secret).is_none());
        // 超长值在验签前被拒。
        let long = "x".repeat(NET_FP_MAX_LEN + 1);
        let long_sig = hex_hmac_sha256(secret, &long);
        assert!(parse_signed_network_fp(&hdr(&long, Some(&long_sig)), secret).is_none());
        // 大写 hex 签名同样有效（规范化比较）。
        assert!(parse_signed_network_fp(&hdr(body, Some(&sig.to_ascii_uppercase())), secret).is_some());
    }

    #[test]
    fn forwarded_proto_uses_proxy_hop() {
        // Appended client value must not win over the proxy's own hop.
        let hdr = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-proto", HeaderValue::from_str(v).unwrap());
            h
        };
        assert_eq!(forwarded_tls(&hdr("https, http")), Some(false));
        assert_eq!(forwarded_tls(&hdr("http, https")), Some(true));
        assert_eq!(forwarded_tls(&hdr(" https ")), Some(true));
        assert_eq!(forwarded_tls(&hdr(", ")), None);
        assert_eq!(forwarded_tls(&HeaderMap::new()), None);
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
