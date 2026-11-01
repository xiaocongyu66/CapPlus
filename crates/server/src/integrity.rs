//! Asset-integrity baseline sealing and challenge environment continuity.

use std::net::SocketAddr;

use axum::http::HeaderMap;
use cap_core::jwt_verify;
use cap_store::now_ms;
use serde_json::{json, Value};

use crate::http_util::{client_ip, header_str};
use crate::{v2, AppState, CHALLENGE_TTL_MS};

/// A verified embed context: which allowed parent framed the page, and the
/// random session id that ties challenge and redeem to that framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmbedContext {
    pub parent: String,
    pub sid: String,
}

/// Validate an optional embed context. Only the signed, canonical, currently
/// allowed parent may supply the session hostname; request origins never do.
pub(crate) fn embed_parent(
    headers: &HeaderMap,
    site_key: &str,
    secret: &str,
    origins: &[String],
) -> Result<Option<EmbedContext>, &'static str> {
    let Some(raw) = headers.get("x-cap-embed-context") else {
        return Ok(None);
    };
    let claims = raw.to_str().ok().and_then(|v| jwt_verify(v, secret))
        .ok_or("invalid_embed_context")?;
    if claims["typ"].as_str() != Some("embed")
        || claims["sk"].as_str() != Some(site_key)
        || claims["exp"].as_i64().unwrap_or(0) <= now_ms()
    {
        return Err("invalid_embed_context");
    }
    let sid = claims["sid"].as_str().ok_or("invalid_embed_context")?;
    if sid.len() != 32 || !sid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid_embed_context");
    }
    let parent = claims["parent"].as_str().ok_or("invalid_embed_context")?;
    match cap_embed::frame_policy(origins, parent) {
        cap_embed::FramePolicy::Allow(canonical) if canonical == parent => Ok(Some(EmbedContext {
            parent: canonical,
            sid: sid.to_ascii_lowercase(),
        })),
        _ => Err("invalid_embed_context"),
    }
}

/// Record UA/IP continuity and the server-validated embedding parent.
pub(crate) async fn remember_challenge_env(
    st: &AppState,
    token: &str,
    headers: &HeaderMap,
    addr: &SocketAddr,
    embed: Option<&EmbedContext>,
) -> Result<(), String> {
    let ua = header_str(headers, "user-agent");
    let ip = client_ip(headers, &addr.ip().to_string());
    let doc = json!({
        "ua": cap_core::sha256_hex(&ua)[..32].to_string(),
        "ip": if ip.is_empty() { Value::Null } else { json!(ip) },
        "parent": embed.map(|e| e.parent.clone()),
        "sid": embed.map(|e| e.sid.clone()),
    });
    st.kv
        .set_ex(
            &chalenv_key(token),
            &doc.to_string(),
            CHALLENGE_TTL_MS / 1000,
        )
        .await
        .map_err(|e| e.to_string())
}

/// Reject a redeem whose UA (or, with session binding, IP) differs from the
/// challenge request.
pub(crate) async fn check_challenge_env(
    st: &AppState,
    token: &str,
    headers: &HeaderMap,
    addr: &SocketAddr,
    require_ip: bool,
) -> Result<ChallengeEnv, String> {
    let raw = st.kv.get(&chalenv_key(token)).await.map_err(|e| {
        eprintln!("[redeem] challenge environment read failed: {e}");
        "store_unavailable".to_string()
    });
    let env = parse_challenge_env(raw)?;
    let ua = header_str(headers, "user-agent");
    let ua_now = cap_core::sha256_hex(&ua)[..32].to_string();
    if let Some(want) = env.get("ua").and_then(Value::as_str) {
        if !want.is_empty() && want != ua_now {
            return Err("session_env_changed".into());
        }
    }
    if require_ip {
        let ip_now = client_ip(headers, &addr.ip().to_string());
        if let Some(want) = env.get("ip").and_then(Value::as_str) {
            if !want.is_empty() && !ip_now.is_empty() && want != ip_now {
                return Err("session_env_changed".into());
            }
        }
    }
    Ok(ChallengeEnv {
        parent: env.get("parent").and_then(Value::as_str).map(str::to_owned),
        sid: env.get("sid").and_then(Value::as_str).map(str::to_owned),
    })
}

/// Challenge environment records are keyed by a digest: the token itself can
/// be several KB, and the record only needs to be found again.
pub(crate) fn chalenv_key(token: &str) -> String {
    format!("chalenv:{}", cap_core::sha256_hex(token))
}

/// What the challenge recorded about the request that asked for it.
#[derive(Debug, Default)]
pub(crate) struct ChallengeEnv {
    pub parent: Option<String>,
    pub sid: Option<String>,
}

/// Fail closed for unavailable, missing, or structurally damaged environment records.
fn parse_challenge_env(raw: Result<Option<String>, String>) -> Result<Value, String> {
    let raw = raw?.ok_or_else(|| "challenge_env_missing".to_string())?;
    let env: Value = serde_json::from_str(&raw)
        .map_err(|_| "challenge_env_invalid".to_string())?;
    let valid_ua = env.get("ua").and_then(Value::as_str)
        .map(|ua| ua.len() == 32 && ua.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false);
    let valid_ip = matches!(env.get("ip"), Some(Value::Null))
        || env.get("ip").and_then(Value::as_str).map(|ip| !ip.is_empty()).unwrap_or(false);
    let valid_parent = match env.get("parent") {
        Some(Value::Null) => true,
        Some(Value::String(parent)) => matches!(
            cap_embed::frame_policy(&["*".to_string()], parent),
            cap_embed::FramePolicy::Allow(canonical) if canonical == *parent
        ),
        _ => false,
    };
    let valid_sid = match env.get("sid") {
        Some(Value::Null) => true,
        Some(Value::String(sid)) => {
            sid.len() == 32 && sid.bytes().all(|b| b.is_ascii_hexdigit())
        }
        _ => false,
    };
    if !valid_ua || !valid_ip || !valid_parent || !valid_sid {
        return Err("challenge_env_invalid".into());
    }
    Ok(env)
}

#[cfg(test)]
mod embed_context_tests {
    use super::*;

    use axum::http::HeaderValue;
    use cap_core::jwt_sign;

    #[test]
    fn challenge_env_fails_closed() {
        assert_eq!(parse_challenge_env(Err("store_unavailable".into())).unwrap_err(), "store_unavailable");
        assert_eq!(parse_challenge_env(Ok(None)).unwrap_err(), "challenge_env_missing");
        for raw in ["{", "null", "[]", "{}"] {
            assert_eq!(parse_challenge_env(Ok(Some(raw.into()))).unwrap_err(), "challenge_env_invalid");
        }
        let valid = json!({"ua": cap_core::sha256_hex("UA")[..32], "ip": "192.0.2.1", "parent": "https://app.example:8443", "sid": "0123456789abcdef0123456789abcdef"});
        assert_eq!(parse_challenge_env(Ok(Some(valid.to_string()))).unwrap(), valid);
        for (field, value) in [
            ("ua", Value::Null), ("ua", json!("")), ("ua", json!(42)),
            ("ip", json!(false)), ("parent", json!(42)),
            ("parent", json!("https://APP.example/path")),
            ("sid", json!("0123456789abcdef")),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert_eq!(parse_challenge_env(Ok(Some(invalid.to_string()))).unwrap_err(), "challenge_env_invalid");
        }
        for field in ["ua", "ip", "parent"] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert_eq!(parse_challenge_env(Ok(Some(invalid.to_string()))).unwrap_err(), "challenge_env_invalid");
        }
        let mut direct = valid;
        direct["parent"] = Value::Null;
        direct["ip"] = Value::Null;
        assert_eq!(parse_challenge_env(Ok(Some(direct.to_string()))).unwrap(), direct);
    }

    #[test]
    fn embed_context_is_scoped_signed_current_and_canonical() {
        let origins = vec!["https://app.example:8443".to_string()];
        let valid = json!({"typ":"embed", "sk":"site-a",
            "sid":"0123456789abcdef0123456789abcdef",
            "parent":"https://app.example:8443", "exp":now_ms() + 60_000});
        let check = |claims: &Value, secret: &str, site: &str, allowed: &[String]| {
            let mut headers = HeaderMap::new();
            headers.insert("x-cap-embed-context", HeaderValue::from_str(&jwt_sign(claims, secret)).unwrap());
            embed_parent(&headers, site, "secret", allowed)
        };
        assert_eq!(
            check(&valid, "secret", "site-a", &origins).unwrap(),
            Some(EmbedContext {
                parent: "https://app.example:8443".into(),
                sid: "0123456789abcdef0123456789abcdef".into(),
            })
        );
        assert!(check(&valid, "wrong", "site-a", &origins).is_err());
        assert!(check(&valid, "secret", "site-b", &origins).is_err());
        assert!(check(&valid, "secret", "site-a", &["https://other.example".into()]).is_err());
        assert!(check(&valid, "secret", "site-a", &["https://app.example".into()]).is_err());
        for (field, value) in [
            ("typ", json!("chal")), ("exp", json!(now_ms() - 1)),
            ("exp", Value::Null), ("parent", json!("https://APP.example:8443/path")),
            ("parent", json!("https://evil.example")),
            ("sid", Value::Null),
            ("sid", json!("")),
            ("sid", json!("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")),
            ("sid", json!("0123456789abcdef")),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(check(&bad, "secret", "site-a", &origins).is_err(), "{bad}");
        }
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static("https://evil.example"));
        headers.insert("referer", HeaderValue::from_static("https://evil.example/path"));
        assert_eq!(embed_parent(&headers, "site-a", "secret", &origins).unwrap(), None);
        headers.insert("x-cap-embed-context", HeaderValue::from_static("invalid"));
        assert!(embed_parent(&headers, "site-a", "secret", &origins).is_err());
        headers.insert("x-cap-embed-context", HeaderValue::from_static(""));
        assert!(embed_parent(&headers, "site-a", "secret", &origins).is_err());
    }
}

/// 加载资产基线；读取失败或配置损坏不能等同于未配置。
pub(crate) async fn load_integrity(st: &AppState) -> Result<Option<Value>, &'static str> {
    parse_integrity_config(st.cache.setting_checked(&st.kv, "settings:integrity").await)
}

fn parse_integrity_config(doc: Result<Value, &'static str>) -> Result<Option<Value>, &'static str> {
    let doc = doc?;
    if doc.is_null() {
        return Ok(None);
    }
    let fields = doc.as_object().ok_or("integrity_config_invalid")?;
    if fields.keys().any(|key| !matches!(key.as_str(), "widget" | "capWasm" | "hashwxWasm")) {
        return Err("integrity_config_invalid");
    }
    let mut out = serde_json::Map::new();
    for key in ["widget", "capWasm", "hashwxWasm"] {
        if let Some(value) = doc.get(key) {
            if value.is_null() {
                continue;
            }
            let v = value.as_str().ok_or("integrity_config_invalid")?.trim().to_ascii_lowercase();
            if v.is_empty() {
                continue;
            }
            if v.len() != 64 || !v.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err("integrity_config_invalid");
            }
            out.insert(key.to_string(), json!(v));
        }
    }
    Ok(if out.is_empty() { None } else { Some(Value::Object(out)) })
}

#[cfg(test)]
mod integrity_config_tests {
    use super::*;

    #[test]
    fn unavailable_or_malformed_baseline_is_not_absent() {
        assert_eq!(parse_integrity_config(Err("setting_unavailable")), Err("setting_unavailable"));
        for doc in [json!([]), json!(false), json!({"widget": 42}),
            json!({"capWasm": "bad"}), json!({"hashwxWasm": "z".repeat(64)})] {
            assert_eq!(parse_integrity_config(Ok(doc)), Err("integrity_config_invalid"));
        }
        let mixed = json!({"widget": "a".repeat(64), "capWasm": "invalid"});
        assert_eq!(parse_integrity_config(Ok(mixed)), Err("integrity_config_invalid"));
    }

    #[test]
    fn disabled_baseline_and_valid_hashes_remain_supported() {
        for doc in [Value::Null, json!({}), json!({"widget": "", "capWasm": null})] {
            assert_eq!(parse_integrity_config(Ok(doc)), Ok(None));
        }
        let doc = json!({"widget": format!(" {} ", "A".repeat(64))});
        assert_eq!(parse_integrity_config(Ok(doc)), Ok(Some(json!({"widget": "a".repeat(64)}))));
    }
}

/// Seal the baseline into the token: `ig` (encrypted) so the client cannot
/// read or tamper with it.
pub(crate) fn seal_integrity(
    payload: &mut Value,
    integrity: &Option<Value>,
    secret: &str,
) -> Result<(), &'static str> {
    let Some(ig) = integrity else {
        return Ok(());
    };
    // A configured baseline that cannot be sealed must fail the challenge:
    // issuing one without `ig` would silently disable the check downstream.
    let blob = v2::encrypt_gcm(ig, secret, "cap:integrity-v1")
        .ok_or("integrity_seal_failed")?;
    let obj = payload.as_object_mut().ok_or("integrity_seal_failed")?;
    obj.insert("ig".into(), json!(blob));
    Ok(())
}

/// Verify the client's reported assets and request proof against the sealed
/// baseline. `Err(reason)` means the solve must be rejected.
pub(crate) fn check_integrity(claims: &Value, body: &Value, secret: &str) -> Result<(), String> {
    let Some(blob) = claims.get("ig").and_then(Value::as_str) else {
        return Ok(()); // legacy challenge without a baseline
    };
    let Some(expected) = v2::decrypt_gcm(blob, secret, "cap:integrity-v1") else {
        return Err("integrity_corrupted".into());
    };
    let reported = body.get("integrity").cloned().unwrap_or(Value::Null);
    if !reported.is_object() {
        return Err("integrity_missing".into());
    }

    // Strong: the served asset hashes must match exactly.
    for key in ["capWasm", "hashwxWasm", "widget"] {
        if let Some(want) = expected.get(key).and_then(Value::as_str) {
            let got = reported
                .get(key)
                .and_then(Value::as_str)
                .map(|v| v.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if got != want {
                return Err(format!("integrity_mismatch:{key}"));
            }
        }
    }

    // Request proof: sha256(nonce|ts|solDigest|hashes) with a replay window.
    let Some(proof) = reported
        .get("proof")
        .and_then(Value::as_str)
        .map(|v| v.trim().to_ascii_lowercase())
    else {
        return Err("proof_missing".into());
    };
    let Some(ts) = reported.get("ts").and_then(Value::as_i64).or_else(|| {
        reported
            .get("ts")
            .and_then(Value::as_f64)
            .map(|v| v as i64)
    }) else {
        return Err("proof_missing_ts".into());
    };
    if (now_ms() - ts).abs() > 120_000 {
        return Err("proof_stale".into());
    }
    let Some(nonce) = claims
        .get("n")
        .or_else(|| claims.get("nonce"))
        .and_then(Value::as_str)
    else {
        return Err("proof_no_nonce".into());
    };
    let solutions = body.get("solutions").cloned().unwrap_or(Value::Null);
    let sol_digest = cap_core::sha256_hex(&serde_json::to_string(&solutions).unwrap_or_default());
    let mut pairs: Vec<String> = ["capWasm", "hashwxWasm", "widget", "scriptHash"]
        .iter()
        .filter_map(|k| {
            reported
                .get(*k)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(|v| format!("{k}={v}"))
        })
        .collect();
    pairs.sort();
    let expected_proof = cap_core::sha256_hex(&format!(
        "{nonce}|{ts}|{sol_digest}|{}",
        pairs.join(",")
    ));
    if expected_proof != proof {
        return Err("proof_mismatch".into());
    }
    Ok(())
}
