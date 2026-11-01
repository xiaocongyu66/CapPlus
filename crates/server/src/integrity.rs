//! Asset-integrity baseline sealing and challenge environment continuity.

use super::*;

/// Record the UA/IP/host that asked for the challenge so redeem can reject a
/// solve submitted from a different environment (`session_env_changed`).
pub(crate) async fn remember_challenge_env(
    st: &AppState,
    token: &str,
    headers: &HeaderMap,
    addr: &SocketAddr,
) {
    let ua = header_str(headers, "user-agent");
    let ip = client_ip(headers, &addr.ip().to_string());
    let origin = header_str(headers, "origin");
    let host = if origin.is_empty() {
        header_str(headers, "referer")
    } else {
        origin
    };
    let doc = json!({
        "ua": cap_core::sha256_hex(&ua)[..32].to_string(),
        "ip": if ip.is_empty() { Value::Null } else { json!(ip) },
        "host": if host.is_empty() { Value::Null } else { json!(host) },
    });
    let _ = st
        .kv
        .set_ex(
            &format!("chalenv:{token}"),
            &doc.to_string(),
            CHALLENGE_TTL_MS / 1000,
        )
        .await;
}

/// Reject a redeem whose UA (or, with session binding, IP) differs from the
/// challenge request.
pub(crate) async fn check_challenge_env(
    st: &AppState,
    token: &str,
    headers: &HeaderMap,
    addr: &SocketAddr,
    require_ip: bool,
) -> Result<(), String> {
    let Ok(Some(raw)) = st.kv.get(&format!("chalenv:{token}")).await else {
        return Ok(());
    };
    let Ok(env) = serde_json::from_str::<Value>(&raw) else {
        return Ok(());
    };
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
    Ok(())
}

/// The operator's asset baseline (`settings:integrity`), or `None` when no
/// usable sha256 hash is configured.
pub(crate) async fn load_integrity(st: &AppState) -> Option<Value> {
    let doc: Value = st.cache.setting(&st.kv, "settings:integrity").await;
    if doc.is_null() {
        return None;
    }
    let mut out = serde_json::Map::new();
    for key in ["widget", "capWasm", "hashwxWasm"] {
        if let Some(v) = doc.get(key).and_then(Value::as_str) {
            let v = v.trim().to_ascii_lowercase();
            if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
                out.insert(key.to_string(), json!(v));
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

/// Seal the baseline into the token: `ig` (encrypted) so the client cannot
/// read or tamper with it.
pub(crate) fn seal_integrity(payload: &mut Value, integrity: &Option<Value>, secret: &str) {
    if let Some(ig) = integrity {
        if let Some(blob) = v2::encrypt_gcm(ig, secret, "cap:integrity-v1") {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("ig".into(), json!(blob));
            }
        }
    }
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

    // Strong: WASM hashes must match exactly.
    for key in ["capWasm", "hashwxWasm"] {
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
