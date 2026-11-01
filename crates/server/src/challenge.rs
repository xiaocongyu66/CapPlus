//! `POST /:siteKey/challenge`: mint a PoW challenge plus, when enabled, the
//! instrumentation script and its sealed metadata (v1 `ei`, v2 challenge list).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cap_core::{jwt_sign, random_hex, PowParams};
use cap_store::{now_ms, KeyConfig};
use serde_json::{json, Value};

use crate::demo::filter_request;
use crate::http_util::{client_ip, cors_origins, header_str, hourly_bucket, parse_ua, proxy_trusted};
use crate::integrity::{embed_parent, load_integrity, remember_challenge_env, seal_integrity};
use crate::{
    ensure_rsw_keypair, is_blocked, rate_allowed, rsw_minter, v2, AppState, CHALLENGE_TTL_MS,
    DEFAULT_RL_MAX, DEFAULT_RL_WINDOW_MS,
};

/// Append the generated instrumentation challenge (script + sealed meta) when
/// the key enables instrumentation. Shared by the rsw and hashwx v2 branches.
pub(crate) fn instr_options<'a>(
    cfg: &'a KeyConfig,
    ext_names: &'a [String],
    ext: cap_instr::ExtProbes<'a>,
) -> cap_instr::InstrOptions<'a> {
    let _ = (ext_names, ext);
    cap_instr::InstrOptions {
        block_automated_browsers: cfg.block_automated_browsers,
        extended_probes: ext,
        polymorphism: cfg.polymorphism.clamp(0.0, 1.0),
        sign_results: true,
        obfuscation_level: cfg.obfuscation_level,
        ttl_ms: CHALLENGE_TTL_MS,
    }
}

/// Build the v1 instrumentation: the sealed meta (`ei`) and the script the
/// client must run. Mirrors the v2 challenge entry but uses the v1 wire shape
/// (`payload.ei` + a top-level `instrumentation` field).
pub(crate) fn v1_instrumentation(cfg: &KeyConfig, expires: i64, secret: &str) -> Option<(String, String)> {
    if !cfg.instrumentation {
        return None;
    }
    let ext_names: Vec<String> = match &cfg.extended_probes {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Value::Bool(true) => cap_instr::EXTENDED_PROBE_KEYS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        _ => Vec::new(),
    };
    let ext_refs: Vec<&str> = ext_names.iter().map(String::as_str).collect();
    let ext = if matches!(cfg.extended_probes, Value::Bool(true)) {
        cap_instr::ExtProbes::All
    } else if ext_refs.is_empty() {
        cap_instr::ExtProbes::Off
    } else {
        cap_instr::ExtProbes::List(&ext_refs)
    };
    let instr = cap_instr::generate(&instr_options(cfg, &ext_names, ext));
    let meta = json!({
        "id": instr.id,
        "expectedVals": instr.expected_vals,
        "vars": instr.vars,
        "blockAutomatedBrowsers": instr.block_automated_browsers,
        "extendedFields": instr.extended_fields,
        "scriptHash": instr.script_hash,
        "macKey": instr.mac_key,
        "iat": now_ms(),
        "expires": expires,
    });
    let ei = v2::encrypt_gcm(&meta, secret, v2::INFO_FMT2)?;
    Some((ei, cap_instr::script_blob(&instr.script)))
}

pub(crate) fn append_instrumentation(
    cfg: &KeyConfig,
    expires: i64,
    challenges: &mut Vec<Value>,
    expected_list: &mut Vec<Value>,
) {
    if !cfg.instrumentation {
        return;
    }
    let ext_names: Vec<String> = match &cfg.extended_probes {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Value::Bool(true) => cap_instr::EXTENDED_PROBE_KEYS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        _ => Vec::new(),
    };
    let ext_refs: Vec<&str> = ext_names.iter().map(String::as_str).collect();
    let ext = if matches!(cfg.extended_probes, Value::Bool(true)) {
        cap_instr::ExtProbes::All
    } else if ext_refs.is_empty() {
        cap_instr::ExtProbes::Off
    } else {
        cap_instr::ExtProbes::List(&ext_refs)
    };
    let instr = cap_instr::generate(&cap_instr::InstrOptions {
        block_automated_browsers: cfg.block_automated_browsers,
        extended_probes: ext,
        polymorphism: cfg.polymorphism.clamp(0.0, 1.0),
        sign_results: true,
        obfuscation_level: cfg.obfuscation_level,
        ttl_ms: CHALLENGE_TTL_MS,
    });
    let (payload, meta) = v2::instrumentation_challenge(&instr, expires);
    challenges.push(payload);
    expected_list.push(meta);
}

pub(crate) async fn challenge(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let started = std::time::Instant::now();
    let resp = challenge_inner(st.clone(), addr, site_key.clone(), headers).await;
    if resp.status().is_success() {
        record_latency(&st, &site_key, started.elapsed().as_millis() as i64);
    }
    resp
}

pub(crate) fn record_latency(st: &AppState, site_key: &str, ms: i64) {
    let bucket = hourly_bucket(now_ms()).to_string();
    st.metrics.latency(
        &format!("metrics:latency_sum:{site_key}"),
        &format!("metrics:latency_count:{site_key}"),
        &bucket,
        ms,
    );
}

pub(crate) async fn challenge_inner(
    st: AppState,
    addr: SocketAddr,
    site_key: String,
    headers: HeaderMap,
) -> Response {
    let key = match st.cache.key(&st.store, &site_key).await {
        Some(k) => Arc::unwrap_or_clone(k),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Invalid site key or secret"})),
            )
                .into_response()
        }
    };
    let cfg = key.config.clone();
    let parent = match embed_parent(&headers, &site_key, &key.jwt_secret, &cors_origins(&cfg)) {
        Ok(parent) => parent,
        Err(reason) => {
            return (StatusCode::FORBIDDEN, Json(json!({"error": reason}))).into_response();
        }
    };

    if let Some(resp) = filter_request(&st, &cfg, &headers, &site_key).await {
        return resp;
    }
    let ip = client_ip(&headers, &addr.ip().to_string());
    // Geo headers are client-controlled unless a proxy is declared; a client
    // must not be able to claim a blocked-country header (or avoid one).
    let headers_trusted = proxy_trusted(&headers, &addr.ip().to_string());
    if is_blocked(&st, &site_key, &ip, &headers, headers_trusted).await {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "blocked", "reason": "This IP, network or region is blocked for this site key"})),
        )
            .into_response();
    }
    // Per-key limits win; otherwise the global `settings:ratelimit` applies.
    let global_rl_raw = st.cache.setting(&st.kv, "settings:ratelimit").await;
    let global_rl = (!global_rl_raw.is_null()).then_some(global_rl_raw);
    let max = cfg
        .ratelimit_max
        .or_else(|| global_rl.as_ref().and_then(|v| v.get("max").and_then(Value::as_i64)))
        .unwrap_or(DEFAULT_RL_MAX);
    let window = cfg
        .ratelimit_duration
        .or_else(|| global_rl.as_ref().and_then(|v| v.get("duration").and_then(Value::as_i64)))
        .unwrap_or(DEFAULT_RL_WINDOW_MS);
    let allowed = rate_allowed(&st, &format!("challenge:{site_key}"), &ip, window, max).await;
    if !allowed {
        st.metrics.incr(
            &format!("metrics:ratelimited:{site_key}"),
            &hourly_bucket(now_ms()).to_string(),
            1,
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "Rate limit exceeded"})),
        )
            .into_response();
    }

    // Platform / OS tallies for the Location & Networks charts (one pipeline).
    let ua = header_str(&headers, "user-agent");
    let (platform, os) = parse_ua(&ua);
    let platform_key = format!("metrics:platform:{site_key}");
    let os_key = format!("metrics:os:{site_key}");
    let mut metrics = Vec::with_capacity(2);
    if let Some(p) = platform {
        metrics.push((platform_key, p.to_string(), 1i64));
    }
    if let Some(o) = os {
        metrics.push((os_key, o.to_string(), 1i64));
    }
    for (name, field, by) in metrics {
        st.metrics.incr(&name, &field, by);
    }

    if cfg.protocol == "hashwx" {
        let Some((challs, expected)) = v2::hashwx_challenges(
            // cap.js clamps to [50_000, 5_000_000]; a tiny value makes the PoW
            // trivial, a huge one makes it unsolvable.
            cfg.hashwx_difficulty.clamp(50_000, 5_000_000),
            cap_proto::hashwx::DEFAULT_HASHWX_NONCES_PER_HASH,
            cap_proto::hashwx::DEFAULT_HASHWX_CHALLENGE_COUNT,
        ) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "hashwx_mint_failed"})),
            )
                .into_response();
        };
        let now = now_ms();
        let expires = now + CHALLENGE_TTL_MS;
        let nonce = random_hex(32);
        let mut challenges = challs;
        let mut expected_list = expected;
        append_instrumentation(&cfg, expires, &mut challenges, &mut expected_list);
        let Some(ev2) = v2::encrypt_gcm(
            &json!({ "expected": expected_list }),
            &key.jwt_secret,
            v2::INFO_FMT2,
        )
        else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "seal_failed"})),
            )
                .into_response();
        };
        let mut payload = json!({
            "typ": "chal", "f": 2, "n": nonce, "exp": expires, "iat": now, "sk": site_key, "ev": ev2,
        });
        seal_integrity(&mut payload, &load_integrity(&st).await, &key.jwt_secret);
        let token = jwt_sign(&payload, &key.jwt_secret);
        if let Err(e) = remember_challenge_env(&st, &token, &headers, &addr, parent.as_deref()).await {
            eprintln!("[challenge] challenge environment write failed: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "store_unavailable"}))).into_response();
        }
        return Json(json!({
            "token": token,
            "format": 2,
            "challenges": challenges,
            "expires": expires,
            "nonce": nonce,
        }))
        .into_response();
    }

    if cfg.protocol == "rsw" {
        let fields = match ensure_rsw_keypair(&st).await {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    { eprintln!("[challenge] store_error: {e}"); Json(json!({"error": "store_error"})) },
                )
                    .into_response()
            }
        };
        // RSA modexp: run on the blocking pool so a burst cannot stall the
        // async workers. Clamp `t` like cap.js ([10_000, 300_000]) — a value
        // above 2^31 wraps negative in the worker (`t | 0`) and never solves.
        let rsw_t = cfg.rsw_t.clamp(10_000, 300_000);
        let Some(minter) = rsw_minter(&st, fields, rsw_t).await else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "rsw_keypair_unavailable"})),
            )
                .into_response();
        };
        // Minting is four half-size modpows; still CPU, still off the workers.
        let Some((challenge, expected)) =
            tokio::task::spawn_blocking(move || v2::rsw_challenge(&minter)).await.ok()
        else {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "rsw_keypair_unavailable"})),
            )
                .into_response();
        };
        let now = now_ms();
        let expires = now + CHALLENGE_TTL_MS;
        let nonce = random_hex(32);

        let mut challenges = vec![challenge];
        let mut expected_list = vec![expected];
        append_instrumentation(&cfg, expires, &mut challenges, &mut expected_list);

        let Some(ev) = v2::encrypt_gcm(
            &json!({ "expected": expected_list }),
            &key.jwt_secret,
            v2::INFO_FMT2,
        ) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "seal_failed"})),
            )
                .into_response();
        };
        let mut payload = json!({
            "typ": "chal", "f": 2, "n": nonce, "exp": expires, "iat": now, "sk": site_key, "ev": ev,
        });
        seal_integrity(&mut payload, &load_integrity(&st).await, &key.jwt_secret);
        let token = jwt_sign(&payload, &key.jwt_secret);
        if let Err(e) = remember_challenge_env(&st, &token, &headers, &addr, parent.as_deref()).await {
            eprintln!("[challenge] challenge environment write failed: {e}");
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "store_unavailable"}))).into_response();
        }
        return Json(json!({
            "token": token,
            "format": 2,
            "challenges": challenges,
            "expires": expires,
            "nonce": nonce,
        }))
        .into_response();
    }

    if cfg.protocol != "sha256-pow" {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "protocol_not_supported",
                "protocol": cfg.protocol,
                "hint": "supported: sha256-pow (v1), rsw (v2)"
            })),
        )
            .into_response();
    }

    let params = PowParams {
        c: cfg.challenge_count.clamp(1, cap_core::MAX_CHALLENGE_COUNT),
        s: cfg.salt_size.clamp(1, cap_core::MAX_CHALLENGE_SIZE),
        d: cfg.difficulty.clamp(1, cap_core::MAX_CHALLENGE_DIFFICULTY),
    };
    let now = now_ms();
    let expires = now + CHALLENGE_TTL_MS;
    let nonce = random_hex(25);
    let mut payload = json!({
        "typ": "chal", "n": nonce, "c": params.c, "s": params.s, "d": params.d,
        "exp": expires, "iat": now, "sk": site_key,
    });
    // v1 carries the instrumentation meta sealed in `ei`, exactly like the JS
    // reference; without it an automated client on the old protocol is never
    // fingerprinted and scores as clean.
    let instrument = v1_instrumentation(&cfg, expires, &key.jwt_secret);
    if let Some((ei, _)) = &instrument {
        payload["ei"] = json!(ei);
    }
    seal_integrity(&mut payload, &load_integrity(&st).await, &key.jwt_secret);
    let token = jwt_sign(&payload, &key.jwt_secret);
    if let Err(e) = remember_challenge_env(&st, &token, &headers, &addr, parent.as_deref()).await {
        eprintln!("[challenge] challenge environment write failed: {e}");
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "store_unavailable"}))).into_response();
    }
    let mut body = json!({
        "challenge": {"c": params.c, "s": params.s, "d": params.d},
        "token": token,
        "expires": expires,
        "nonce": nonce,
    });
    if let Some((_, script)) = instrument {
        body["instrumentation"] = json!(script);
    }
    Json(body).into_response()
}
