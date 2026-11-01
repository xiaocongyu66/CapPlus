//! Small HTTP helpers: client IP resolution, origin checks, UA parsing and
//! path/CIDR matching. Pure functions plus a couple of config reads.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
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
    proxy_trusted_with(headers, peer, cfg.trust_proxy, &cfg.proxy_secret)
}

fn proxy_trusted_with(headers: &HeaderMap, peer: &str, enabled: bool, secret: &str) -> bool {
    if !enabled {
        return false;
    }
    if headers.get_all("x-cap-proxy-secret").iter().count() > 1 {
        return false;
    }
    match Some(secret) {
        Some(secret) if !secret.is_empty() => headers
            .get("x-cap-proxy-secret")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                use sha2::{Digest, Sha256};
                // Compare fixed-size digests so the comparison time does not
                // depend on how much of the secret matched.
                let a = Sha256::digest(v.as_bytes());
                let b = Sha256::digest(secret.as_bytes());
                a.iter()
                    .zip(b.iter())
                    .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                    == 0
            })
            .unwrap_or(false),
        _ => is_loopback_or_private(peer),
    }
}

/// Protocol-layer fingerprint forwarded by the trusted proxy: JA3/JA4, HTTP/2
/// SETTINGS class and whether TLS was used. These are authenticated proxy
/// observations, not proof of browser identity: clients can imitate TLS stacks.
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NetworkSignalError {
    Required,
    Invalid,
}

pub(crate) fn network_signals(
    headers: &HeaderMap,
    peer: &str,
) -> Result<Option<cap_detect::NetworkSignals>, NetworkSignalError> {
    let cfg = settings();
    network_signals_with(
        headers,
        proxy_trusted(headers, peer),
        &cfg.proxy_secret,
        cfg.require_network_fingerprint,
    )
}

fn network_signals_with(
    headers: &HeaderMap,
    trusted: bool,
    secret: &str,
    required: bool,
) -> Result<Option<cap_detect::NetworkSignals>, NetworkSignalError> {
    if !trusted {
        return if required {
            Err(NetworkSignalError::Required)
        } else {
            Ok(None)
        };
    }
    // Invalid evidence must never be replaced by a TLS-only fallback, even
    // when fingerprint enforcement is optional.
    let mut net = parse_signed_network_fp(headers, secret)?;
    if required && net.is_none() {
        return Err(NetworkSignalError::Required);
    }
    if secret.is_empty() {
        return Ok(None);
    }
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
    Ok(net)
}

/// None means both headers are absent; partial or malformed evidence is Err.
fn parse_signed_network_fp(
    headers: &HeaderMap,
    secret: &str,
) -> Result<Option<cap_detect::NetworkSignals>, NetworkSignalError> {
    use NetworkSignalError::Invalid;
    let mut values = headers.get_all(NET_FP_HEADER).iter();
    let mut sigs = headers.get_all(NET_FP_SIG_HEADER).iter();
    let (raw, sig) = match (values.next(), sigs.next()) {
        (None, None) => return Ok(None),
        (Some(raw), Some(sig)) => (raw, sig),
        _ => return Err(Invalid),
    };
    if values.next().is_some() || sigs.next().is_some() {
        return Err(Invalid);
    }
    let raw = raw.to_str().map_err(|_| Invalid)?;
    let sig = sig.to_str().map_err(|_| Invalid)?;
    if raw.is_empty() || raw.len() > NET_FP_MAX_LEN || secret.is_empty() {
        return Err(Invalid);
    }
    if sig.len() != 64 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Invalid);
    }
    let expected = hex_hmac_sha256(secret, raw);
    // Fixed-length hex, compared without early exit.
    let ok = expected
        .as_bytes()
        .iter()
        .zip(sig.as_bytes())
        .fold(0u8, |acc, (a, b)| {
            acc | (a.to_ascii_lowercase() ^ b.to_ascii_lowercase())
        })
        == 0;
    if !ok {
        return Err(Invalid);
    }
    // Deserialize directly into a strict wire type: duplicate fields, unknown
    // fields, nulls, non-booleans and empty objects are not observations.
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Wire {
        #[serde(default, deserialize_with = "present_bool")]
        tls: Option<bool>,
        #[serde(default, deserialize_with = "present_bool")]
        ja3_browser: Option<bool>,
        #[serde(default, deserialize_with = "present_bool")]
        ja4_browser: Option<bool>,
        #[serde(default, deserialize_with = "present_bool")]
        http2_browser: Option<bool>,
        #[serde(default, deserialize_with = "present_bool")]
        ua_mismatch: Option<bool>,
    }
    fn present_bool<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
        <bool as serde::Deserialize>::deserialize(d).map(Some)
    }
    let w: Wire = serde_json::from_str(raw).map_err(|_| Invalid)?;
    let net = cap_detect::NetworkSignals {
        tls: w.tls,
        ja3_browser: w.ja3_browser,
        ja4_browser: w.ja4_browser,
        http2_browser: w.http2_browser,
        ua_mismatch: w.ua_mismatch,
    };
    if net == cap_detect::NetworkSignals::default() {
        return Err(Invalid);
    }
    Ok(Some(net))
}

/// Transport security of the hop the proxy terminated, from the rightmost
/// `X-Forwarded-Proto` value: proxies that append put their own hop last, so
/// taking the left value would let a client prepend `https` and suppress the
/// `tls_missing` signal.
fn forwarded_tls(headers: &HeaderMap) -> Option<bool> {
    let proto = headers
        .get_all("x-forwarded-proto")
        .iter()
        .last()?
        .to_str()
        .ok()?;
    match proto
        .rsplit(',')
        .next()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "https" => Some(true),
        "http" => Some(false),
        _ => None,
    }
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
    client_ip_with(
        headers,
        peer,
        proxy_trusted(headers, peer),
        &settings().ip_header,
        &settings().trusted_proxy_cidrs,
    )
}

pub(crate) fn canonical_ip(value: &str) -> Option<String> {
    use std::net::IpAddr;
    value.parse::<IpAddr>().ok().map(|ip| {
        match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        }
        .to_string()
    })
}

fn client_ip_with(
    headers: &HeaderMap,
    peer: &str,
    trusted: bool,
    configured: &str,
    cidrs: &[String],
) -> String {
    let fallback = || canonical_ip(peer).unwrap_or_else(|| peer.to_string());
    if !trusted {
        return fallback();
    }
    // Repeated field lines form one ordered list; malformed lines fail closed.
    let get = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().ok())
            .collect::<Option<Vec<_>>>()
            .map(|values| values.join(","))
    };
    if !configured.is_empty() {
        // An explicitly configured header is the only source: falling through
        // to XFF would let a client supply the address when the header is
        // absent.
        return get(configured)
            .and_then(|v| forwarded_client(&v, cidrs))
            .unwrap_or_else(fallback);
    }
    // X-Forwarded-For is the only default source: Caddy and Traefik set it,
    // while they neither set nor strip `CF-Connecting-IP` / `X-Real-IP`, so
    // trusting those implicitly lets any client claim an arbitrary address.
    // Operators behind Cloudflare can opt in via `RATELIMIT_IP_HEADER`.
    get("x-forwarded-for")
        .and_then(|v| forwarded_client(&v, cidrs))
        .unwrap_or_else(fallback)
}

/// Default: only the appended rightmost client is authoritative, including
/// private clients. Walk further left only across explicitly trusted CIDRs.
/// An invalid/empty hop terminates resolution, never exposing a spoofed left hop.
fn forwarded_client(v: &str, cidrs: &[String]) -> Option<String> {
    let mut hops = v.rsplit(',').peekable();
    while let Some(hop) = hops.next() {
        let ip = canonical_ip(hop.trim())?;
        if hops.peek().is_none() || !cidrs.iter().any(|net| cidr_match(net, &ip)) {
            return Some(ip);
        }
    }
    None
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
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
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
    let platform = if ua.contains("iPhone") || (ua.contains("Android") && ua.contains("Mobile")) {
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
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            (u32::from(base) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(base), IpAddr::V6(ip)) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            (u128::from(base) & mask) == (u128::from(ip) & mask)
        }
        (IpAddr::V6(base), IpAddr::V4(ip)) if base.to_ipv4_mapped().is_some() => {
            cidr_match(net, &ip.to_ipv6_mapped().to_string())
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
            ("::ffff:192.0.2.0/120", "192.0.2.42"),
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
        let got = parse_signed_network_fp(&hdr(body, Some(&sig)), secret)
            .unwrap()
            .unwrap();
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
        assert_eq!(parse_signed_network_fp(&HeaderMap::new(), secret), Ok(None));
        assert!(parse_signed_network_fp(&hdr(body, None), secret).is_err());
        assert!(parse_signed_network_fp(&hdr(body, Some("00")), secret).is_err());
        let tampered = body.replace("\"ja4Browser\":true", "\"ja4Browser\":false");
        assert!(parse_signed_network_fp(&hdr(&tampered, Some(&sig)), secret).is_err());
        for bad in [
            "not-json",
            "{}",
            "[]",
            "null",
            r#"{"tls":null}"#,
            r#"{"tls":"true"}"#,
            r#"{"extra":true}"#,
            r#"{"tls":true,"tls":false}"#,
            r#"{"tls":true,"extra":1}"#,
        ] {
            assert!(
                parse_signed_network_fp(&hdr(bad, Some(&hex_hmac_sha256(secret, bad))), secret)
                    .is_err(),
                "{bad}"
            );
        }
        let long = "x".repeat(NET_FP_MAX_LEN + 1);
        assert!(
            parse_signed_network_fp(&hdr(&long, Some(&hex_hmac_sha256(secret, &long))), secret)
                .is_err()
        );
        assert!(
            parse_signed_network_fp(&hdr(body, Some(&sig.to_ascii_uppercase())), secret)
                .unwrap()
                .is_some()
        );
        for name in [NET_FP_HEADER, NET_FP_SIG_HEADER] {
            let mut h = hdr(body, Some(&sig));
            h.append(name, h.get(name).unwrap().clone());
            h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
            assert_eq!(
                network_signals_with(&h, true, secret, false),
                Err(NetworkSignalError::Invalid)
            );
        }
        let mut sig_only = HeaderMap::new();
        sig_only.insert(NET_FP_SIG_HEADER, HeaderValue::from_str(&sig).unwrap());
        assert!(parse_signed_network_fp(&sig_only, secret).is_err());
        assert!(parse_signed_network_fp(&hdr(body, Some(&sig)), "").is_err());
        let mut h = hdr(body, Some(&sig));
        h.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert_eq!(
            network_signals_with(&h, true, secret, true)
                .unwrap()
                .unwrap()
                .tls,
            Some(true)
        );
        assert_eq!(network_signals_with(&h, false, secret, false), Ok(None));
        assert!(network_signals_with(&h, false, secret, true).is_err());
        let mut empty = HeaderMap::new();
        assert_eq!(network_signals_with(&empty, true, secret, false), Ok(None));
        assert_eq!(network_signals_with(&empty, true, "", false), Ok(None));
        empty.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(network_signals_with(&empty, true, secret, true).is_err());
        assert_eq!(
            network_signals_with(&empty, true, secret, false)
                .unwrap()
                .unwrap()
                .tls,
            Some(true)
        );
        let mut bad = hdr(body, Some(&"0".repeat(64)));
        bad.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(network_signals_with(&bad, true, secret, false).is_err());
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
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.1",
            "192.168.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_loopback_or_private(ip), "{ip}");
        }
        for ip in [
            "172.2.0.1",
            "172.200.1.1",
            "172.32.0.1",
            "8.8.8.8",
            "2001:db8::1",
            "fcdn.example",
            "",
        ] {
            assert!(!is_loopback_or_private(ip), "{ip}");
        }
    }

    #[test]
    fn forwarded_respects_explicit_trust_boundary() {
        for (chain, expected) in [
            ("1.1.1.1, 203.0.113.7", "203.0.113.7"),
            ("6.6.6.6, 10.0.0.2", "10.0.0.2"),
            ("6.6.6.6, fd00::1", "fd00::1"),
            ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
            ("::ffff:192.0.2.1", "192.0.2.1"),
        ] {
            assert_eq!(forwarded_client(chain, &[]).as_deref(), Some(expected));
        }
        let cidrs = vec!["10.0.0.0/24".into(), "2001:db8::/32".into()];
        assert_eq!(
            forwarded_client("6.6.6.6, 192.168.1.9, 10.0.0.2, 2001:db8::1", &cidrs).as_deref(),
            Some("192.168.1.9")
        );
        assert_eq!(
            forwarded_client("6.6.6.6, 192.168.1.9, ::ffff:10.0.0.2", &cidrs).as_deref(),
            Some("192.168.1.9")
        );
        for chain in ["not-an-ip", "  ,  ", "6.6.6.6,", "6.6.6.6, bad, 10.0.0.2"] {
            assert_eq!(forwarded_client(chain, &cidrs), None);
        }
    }

    #[test]
    fn proxy_secret_and_ip_headers_do_not_expand_trust() {
        let mut h = HeaderMap::new();
        assert!(!proxy_trusted_with(&h, "127.0.0.1", true, "secret"));
        assert!(!proxy_trusted_with(&h, "203.0.113.1", true, ""));
        assert!(proxy_trusted_with(&h, "127.0.0.1", true, ""));
        h.insert("x-cap-proxy-secret", HeaderValue::from_static("secret"));
        assert!(proxy_trusted_with(&h, "203.0.113.1", true, "secret"));
        assert!(!proxy_trusted_with(&h, "127.0.0.1", false, "secret"));
        assert!(!proxy_trusted_with(&h, "127.0.0.1", true, "wrong"));
        h.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        h.append("x-forwarded-for", HeaderValue::from_static("10.1.2.3"));
        assert_eq!(
            client_ip_with(&h, "::ffff:127.0.0.1", false, "", &[]),
            "127.0.0.1"
        );
        assert_eq!(client_ip_with(&h, "::1", true, "", &[]), "10.1.2.3");
        assert_eq!(client_ip_with(&h, "::1", true, "x-real-ip", &[]), "::1");
        h.insert("x-real-ip", HeaderValue::from_static("::ffff:192.0.2.1"));
        assert_eq!(
            client_ip_with(&h, "::1", true, "x-real-ip", &[]),
            "192.0.2.1"
        );
        h.append("x-forwarded-for", HeaderValue::from_static("bad"));
        assert_eq!(client_ip_with(&h, "::1", true, "", &[]), "::1");
    }
}
