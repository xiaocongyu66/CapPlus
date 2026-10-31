//! cap-server — axum wiring for the verified-embed-only Cap architecture.
//!
//!   GET  /health
//!   POST /:siteKey/challenge
//!   POST /:siteKey/redeem            (only accepts requests from the Cap origin)
//!   POST /:siteKey/siteverify        (Turnstile-compatible, consume-once)
//!   POST /turnstile/v0/siteverify    (alias; site key from the token prefix)
//!   POST /:siteKey/validate          (non-consuming)
//!   GET  /embed.js                   (parent loader, Cap origin)
//!   GET  /embed/:siteKey             (cross-origin verification iframe)
//!
//! Phase 1 supports the `sha256-pow` protocol; `hashwx`/`rsw`/instrumentation
//! answer `protocol_not_supported` until ported.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

mod cache;
mod config;
mod metrics_buf;
mod ratelimit;
mod v2;

// mimalloc: per-thread heaps cut allocator contention on the request path
// (short-lived Json/header/Bytes allocations dominate). Falls back to the
// system allocator only if this line is removed.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use cap_core::{jwt_sign, jwt_sig_hex, jwt_verify, random_hex, verify_pow, PowParams, SessionBind};
use cap_store::{now_ms, KeyConfig, Store};
use cap_verify::{
    bind_inputs, check_secret, err_response, ok_response, parse_body, parse_request,
    token_site_key, ErrorCode, SecretCheck,
};

const CHALLENGE_TTL_MS: i64 = 15 * 60 * 1000;
const TOKEN_TTL_MS: i64 = 2 * 60 * 60 * 1000;
const DEFAULT_RL_MAX: i64 = 30;
const DEFAULT_RL_WINDOW_MS: i64 = 5_000;

static SETTINGS: std::sync::OnceLock<config::Settings> = std::sync::OnceLock::new();

/// JS-compatible metric bucket: epoch seconds rounded down to the hour.
fn hourly_bucket(now_ms: i64) -> i64 {
    (now_ms / 1000 / 3600) * 3600
}

fn settings() -> &'static config::Settings {
    SETTINGS.get().expect("settings initialised in main")
}

#[derive(Clone)]
struct AppState {
    store: Store,
    embed_widget_url: String,
    admin: Option<cap_admin::AdminStore>,
    admin_cfg: Arc<cap_admin::AdminConfig>,
    assets: Arc<cap_assets::AssetCache>,
    releases: Arc<cap_assets::ReleaseStore>,
    kv: cap_kv::Kv,
    ipdb: Arc<cap_ipdb::IpDb>,
    cache: Arc<cache::ConfigCache>,
    limiter: Arc<ratelimit::LocalLimiter>,
    metrics: Arc<metrics_buf::MetricsBuffer>,
    /// `CAP_RL_MODE=redis` forces the shared Redis limiter.
    redis_ratelimit: bool,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn is_loopback_or_private(addr: &str) -> bool {
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

fn proxy_trusted(headers: &HeaderMap, peer: &str) -> bool {
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

fn client_ip(headers: &HeaderMap, peer: &str) -> String {
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

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn cors_origins(cfg: &KeyConfig) -> Vec<String> {
    cfg.cors_origins.clone().unwrap_or_default()
}

fn same_origin(headers: &HeaderMap) -> bool {
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

fn html_response(status: StatusCode, csp: Option<&str>, body: String) -> Response {
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

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// Readiness probe: the storage backend must answer within 2 seconds.
async fn health_check(State(st): State<AppState>) -> Response {
    match tokio::time::timeout(std::time::Duration::from_secs(2), st.kv.get("__health__")).await {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded", "error": e.to_string() })),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded", "error": "storage timeout" })),
        )
            .into_response(),
    }
}

/// Liveness probe: the process is up.
async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

/// Append the generated instrumentation challenge (script + sealed meta) when
/// the key enables instrumentation. Shared by the rsw and hashwx v2 branches.
fn append_instrumentation(
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

async fn challenge(
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

fn record_latency(st: &AppState, site_key: &str, ms: i64) {
    let bucket = hourly_bucket(now_ms()).to_string();
    st.metrics.latency(
        &format!("metrics:latency_sum:{site_key}"),
        &format!("metrics:latency_count:{site_key}"),
        &bucket,
        ms,
    );
}

async fn challenge_inner(
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
    let allowed = if st.redis_ratelimit {
        st.store
            .rate_hit(&format!("challenge:{site_key}"), &ip, window, max)
            .await
            .unwrap_or(true)
    } else {
        st.limiter.hit(&format!("challenge:{site_key}"), &ip, window, max)
    };
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
            "f": 2, "n": nonce, "exp": expires, "iat": now, "sk": site_key, "ev": ev2,
        });
        seal_integrity(&mut payload, &load_integrity(&st).await, &key.jwt_secret);
        let token = jwt_sign(&payload, &key.jwt_secret);
        remember_challenge_env(&st, &token, &headers, &addr).await;
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
                    Json(json!({"error": format!("store: {e}")})),
                )
                    .into_response()
            }
        };
        // RSA modexp: run on the blocking pool so a burst cannot stall the
        // async workers. Clamp `t` like cap.js ([10_000, 300_000]) — a value
        // above 2^31 wraps negative in the worker (`t | 0`) and never solves.
        let rsw_t = cfg.rsw_t.clamp(10_000, 300_000);
        let Some((challenge, expected)) = tokio::task::spawn_blocking(move || {
            v2::rsw_challenge(&fields, rsw_t)
        })
        .await
        .ok()
        .flatten()
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
            "f": 2, "n": nonce, "exp": expires, "iat": now, "sk": site_key, "ev": ev,
        });
        seal_integrity(&mut payload, &load_integrity(&st).await, &key.jwt_secret);
        let token = jwt_sign(&payload, &key.jwt_secret);
        remember_challenge_env(&st, &token, &headers, &addr).await;
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
        "n": nonce, "c": params.c, "s": params.s, "d": params.d,
        "exp": expires, "iat": now, "sk": site_key,
    });
    seal_integrity(&mut payload, &load_integrity(&st).await, &key.jwt_secret);
    let token = jwt_sign(&payload, &key.jwt_secret);
    remember_challenge_env(&st, &token, &headers, &addr).await;
    Json(json!({
        "challenge": {"c": params.c, "s": params.s, "d": params.d},
        "token": token,
        "expires": expires,
        "nonce": nonce,
    }))
    .into_response()
}

async fn redeem(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "verified_session_required",
                "reason": "solve challenges inside the Cap-hosted iframe (embed.js)"
            })),
        )
            .into_response();
    }

    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_body"}))).into_response();
    };
    let token = payload.get("token").and_then(Value::as_str).unwrap_or("");
    if token.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing_token"}))).into_response();
    }
    let Some(sols) = payload.get("solutions").and_then(Value::as_array) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing_solutions"})),
        )
            .into_response();
    };
    // v1 solutions are bare integers; v2 solutions are objects per challenge.
    if sols.len() > 4096 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid solutions"})),
        )
            .into_response();
    }
    let solutions_raw: Vec<Value> = sols.clone();

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

    let Some(claims) = jwt_verify(token, &key.jwt_secret) else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
    };
    if claims.get("sk").and_then(Value::as_str) != Some(site_key.as_str()) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "scope_mismatch"}))).into_response();
    }
    if let Err(reason) =
        check_challenge_env(&st, token, &headers, &addr, key.config.require_session_bind).await
    {
        let _ = st
            .kv
            .hincrby(
                &format!("metrics:failed:{site_key}"),
                &hourly_bucket(now_ms()).to_string(),
                1,
            )
            .await;
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": reason }))).into_response();
    }
    if let Err(reason) = check_integrity(&claims, &payload, &key.jwt_secret) {
        let _ = st
            .kv
            .hincrby(
                &format!("metrics:failed:{site_key}"),
                &hourly_bucket(now_ms()).to_string(),
                1,
            )
            .await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "integrity", "reason": reason })),
        )
            .into_response();
    }
    let now = now_ms();
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if exp <= now {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "expired"}))).into_response();
    }
    let is_v2 = claims.get("f").and_then(Value::as_u64) == Some(2);
    let mut v2_trust: Option<(cap_detect::Trust, cap_detect::Action)> = None;
    if is_v2 {
        let Some(ev) = claims.get("ev").and_then(Value::as_str) else {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        };
        let Some(expected) = v2::decrypt_gcm(ev, &key.jwt_secret, v2::INFO_FMT2) else {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        };
        // Instrumentation outcomes the widget reports explicitly.
        let blocked_flag = payload
            .get("instr_blocked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let timeout_flag = payload
            .get("instr_timeout")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let instr_meta = expected
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|c| c.get("protocol").and_then(Value::as_str) == Some("instrumentation"))
            })
            .and_then(|c| c.get("instrMeta"));
        if let Some(meta) = instr_meta {
            if let Some(sealed_exp) = meta.get("expires").and_then(Value::as_i64) {
                if sealed_exp <= now {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "instr_expired"})),
                    )
                        .into_response();
                }
            }
        }
        if blocked_flag {
            let automated = instr_meta
                .and_then(|m| m.get("blockAutomatedBrowsers"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let _ = st
                .kv
                .hincrby(
                    &format!("metrics:failed:{site_key}"),
                    &hourly_bucket(now).to_string(),
                    1,
                )
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": if automated { "instr_automated_browser" } else { "instr_failed" },
                    "instr_error": true,
                })),
            )
                .into_response();
        }
        if timeout_flag {
            let _ = st
                .kv
                .hincrby(
                    &format!("metrics:failed:{site_key}"),
                    &hourly_bucket(now).to_string(),
                    1,
                )
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "instr_timeout", "instr_error": true})),
            )
                .into_response();
        }

        // Run the probe detector on the captured instrumentation payload and
        // remember the verdict; the deny decision is enforced after the nonce
        // has been consumed (same ordering as the JS server).
        let captured = v2::take_probe(&expected, &solutions_raw);
        if captured.is_none() {
            eprintln!("[redeem] no probe captured (solutions={})", solutions_raw.len());
        }
        if let Some(cap) = captured {
            let accept_language = header_str(&headers, "accept-language");
            let primary_lang = accept_language
                .split(',')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let opts = cap_detect::DetectOpts {
                font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
                optional_fields: &cap.optional_fields,
                accept_language: primary_lang,
            };
            let outcome = cap_detect::detect_automation(&cap.p, &opts);
            let owned = outcome.signals.clone();
            let sigs: Vec<cap_detect::Signal> =
                owned.iter().map(|s| s.as_signal()).collect();
            let trust = cap_detect::compute_trust_signals(&sigs, None, Some(outcome.pass));
            let action = cap_detect::trust_action(&trust);
            v2_trust = Some((trust, action));
        }
        if let Err(reason) = v2::verify_solutions(&expected, &solutions_raw) {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), hourly_bucket(now))
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Invalid solution", "reason": reason})),
            )
                .into_response();
        }
    } else {
        let mut solutions = Vec::with_capacity(solutions_raw.len());
        for v in &solutions_raw {
            match v.as_u64() {
                Some(n) => solutions.push(n),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "invalid_solutions"})),
                    )
                        .into_response()
                }
            }
        }
        let params = PowParams {
            c: claims.get("c").and_then(Value::as_u64).unwrap_or(0) as u32,
            s: claims.get("s").and_then(Value::as_u64).unwrap_or(0) as u32,
            d: claims.get("d").and_then(Value::as_u64).unwrap_or(0) as u32,
        };
        if !params.valid() {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        }
        if !verify_pow(token, params, &solutions) {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), hourly_bucket(now))
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Invalid solution"})),
            )
                .into_response();
        }
    }

    let Some(sig) = jwt_sig_hex(token) else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
    };
    match st.store.consume_nonce(&sig, exp - now).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Challenge already redeemed"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("nonce_store_error: {e}")})),
            )
                .into_response()
        }
    }

    if let Some((trust, action)) = &v2_trust {
        eprintln!(
            "[redeem] site={site_key} trust score={} level={:?} action={action:?}",
            trust.score, trust.level
        );
        if matches!(action, cap_detect::Action::Deny) && key.config.block_on_deny {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), hourly_bucket(now))
                .await;
            let mut doc = json!({ "success": false, "error": "trust_denied" });
            if st.admin_cfg.demo {
                doc["trust"] = trust_json(trust);
                doc["action"] = json!(action_str(*action));
            }
            return (StatusCode::FORBIDDEN, Json(doc)).into_response();
        }
    }

    let redeem_token = format!("{site_key}:{}:{}", random_hex(8), random_hex(15));
    let ua = header_str(&headers, "user-agent");
    let ip = client_ip(&headers, &addr.ip().to_string());
    let bind = SessionBind::new(if ip.is_empty() { None } else { Some(ip) }, &ua, now);
    let token_expires = now + TOKEN_TTL_MS;
    if let Err(e) = st
        .store
        .issue(&redeem_token, &bind.to_json(), token_expires, TOKEN_TTL_MS)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("bind_failed: {e}")})),
        )
            .into_response();
    }
    let _ = st.kv.del(&format!("chalenv:{token}")).await;
    eprintln!("[redeem] site={site_key} issued token (verified)");
    st.metrics
        .incr(
            &format!("metrics:verified:{site_key}"),
            &hourly_bucket(now).to_string(),
            1,
        );

    record_geo(&st, &site_key, &headers, &addr).await;

    // Detection details are a probe oracle: only the demo mode exposes them.
    let demo = st.admin_cfg.demo;
    if demo {
        if let Some((trust, action)) = &v2_trust {
            let _ = st
                .kv
                .set_ex(
                    &format!("demo:last-trust:{site_key}"),
                    &json!({ "trust": trust_json(trust), "action": action_str(*action) })
                        .to_string(),
                    120,
                )
                .await;
        }
    }
    let mut doc = json!({
        "success": true,
        "token": redeem_token,
        "expires": token_expires,
        "scope": site_key,
    });
    // Detection details are a probe oracle: the fields do not exist at all
    // outside demo mode.
    if demo {
        if let Some((trust, action)) = &v2_trust {
            doc["trust"] = trust_json(trust);
            doc["action"] = json!(action_str(*action));
        }
    }
    Json(doc).into_response()
}

/// Trust result in the shape the dashboard/test page expects
/// (`{score, level, reasons, gatingFailure}`), with the JS level names.
fn trust_json(trust: &cap_detect::Trust) -> Value {
    let level = match trust.level {
        cap_detect::Level::Clean => "trusted",
        cap_detect::Level::Restricted => {
            // trust.js:levelFor splits neutral/suspicious at 55.
            if trust.score >= 55 {
                "neutral"
            } else {
                "suspicious"
            }
        }
        cap_detect::Level::Hostile => "hostile",
    };
    json!({
        "score": trust.score,
        "level": level,
        "reasons": trust.reasons,
        "gatingFailure": trust.gating_failure,
    })
}

fn action_str(action: cap_detect::Action) -> &'static str {
    match action {
        cap_detect::Action::Allow => "allow",
        cap_detect::Action::Deny => "deny",
    }
}

async fn verify_common(
    st: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    path_site_key: Option<&str>,
    consume: bool,
) -> Response {
    let content_type = header_str(headers, "content-type");
    let raw = String::from_utf8_lossy(body);
    let Some(map) = parse_body(&content_type, &raw) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(err_response(
                ErrorCode::BadRequest,
                "The request is invalid or malformed.",
            )),
        )
            .into_response();
    };
    let req = match parse_request(&map) {
        Ok(r) => r,
        Err(code) => {
            let status = match code {
                ErrorCode::MissingInputSecret | ErrorCode::MissingInputResponse => {
                    StatusCode::BAD_REQUEST
                }
                _ => StatusCode::OK,
            };
            return (status, Json(err_response(code, error_message(code)))).into_response();
        }
    };

    let site_key = match path_site_key {
        Some(sk) if !sk.is_empty() => sk.to_string(),
        _ => match token_site_key(&req.response) {
            Some(sk) => sk.to_string(),
            None => {
                return (
                    StatusCode::OK,
                    Json(err_response(
                        ErrorCode::MissingInputResponse,
                        error_message(ErrorCode::MissingInputResponse),
                    )),
                )
                    .into_response()
            }
        },
    };

    // A site key in the path scopes the token: a secret for site B must not
    // verify a token minted for site A.
    if path_site_key.map(|sk| !sk.is_empty()).unwrap_or(false)
        && !req.response.starts_with(&format!("{site_key}:"))
    {
        return (
            StatusCode::OK,
            Json(err_response(
                ErrorCode::InvalidInputResponse,
                error_message(ErrorCode::InvalidInputResponse),
            )),
        )
            .into_response();
    }

    let key = match st.cache.key(&st.store, &site_key).await {
        Some(k) => Arc::unwrap_or_clone(k),
        None => {
            return (
                StatusCode::OK,
                Json(err_response(
                    ErrorCode::InvalidInputSecret,
                    "The secret parameter is invalid or malformed.",
                )),
            )
                .into_response()
        }
    };

    match check_secret(&key.secret_hash, &req.secret) {
        SecretCheck::Fast(true) => {}
        SecretCheck::Fast(false) => {
            return (
                StatusCode::OK,
                Json(err_response(
                    ErrorCode::InvalidInputSecret,
                    "The secret parameter is invalid or malformed.",
                )),
            )
                .into_response()
        }
        SecretCheck::Argon2Unsupported => {
            return (
                StatusCode::OK,
                Json(err_response(
                    ErrorCode::InvalidInputSecret,
                    "The secret parameter is invalid or malformed.",
                )),
            )
                .into_response()
        }
    }

    let bind_raw = st.store.peek_bind(&req.response).await.ok().flatten();
    let bind = bind_raw
        .as_deref()
        .and_then(|raw| serde_json::from_str::<SessionBind>(raw).ok());
    let strict = key.config.require_session_bind;
    let (ctx_ip, ctx_ua, ctx_host) = bind_inputs(
        &req,
        Some(&header_str(headers, "x-forwarded-for")),
        Some(&header_str(headers, "x-cap-client-ua")),
        Some(&header_str(headers, "x-cap-client-host")),
    );
    let bind_ok = match &bind {
        Some(b) => b.matches(strict, &ctx_ip, &ctx_ua, &ctx_host),
        None => !strict,
    };
    if !bind_ok {
        return (
            StatusCode::OK,
            Json(err_response(
                ErrorCode::InvalidInputResponse,
                "Session mismatch",
            )),
        )
            .into_response();
    }

    // Peek before consume: a burned token must report "duplicate", not
    // "not verified" — same ordering as the JS implementation.
    let expires = match st.store.peek_token(&req.response).await {
        Ok(Some(ts)) if ts > now_ms() => ts,
        _ => {
            return (
                StatusCode::OK,
                Json(err_response(
                    ErrorCode::TimeoutOrDuplicate,
                    "The response has already been redeemed or has expired.",
                )),
            )
                .into_response()
        }
    };

    if !st.store.has_verified(&req.response).await.unwrap_or(false) {
        return (
            StatusCode::OK,
            Json(err_response(
                ErrorCode::InvalidInputResponse,
                "Token was not issued by a verified embed session",
            )),
        )
            .into_response();
    }

    if consume {
        if !st.store.consume_token(&req.response).await.unwrap_or(false) {
            return (
                StatusCode::OK,
                Json(err_response(
                    ErrorCode::TimeoutOrDuplicate,
                    "The response has already been redeemed or has expired.",
                )),
            )
                .into_response();
        }
        let _ = st.store.drop_verified(&req.response).await;
    }

    let ts = bind.as_ref().map(|b| b.ts).unwrap_or_else(now_ms);
    let hostname = bind
        .as_ref()
        .and_then(|b| b.host.clone())
        .filter(|h| !h.is_empty())
        .unwrap_or(ctx_host);
    let mut resp = ok_response(ts, &hostname);
    if !consume {
        resp["expires"] = json!(expires);
    }
    (StatusCode::OK, Json(resp)).into_response()
}

fn error_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::MissingInputSecret => "The secret parameter is missing.",
        ErrorCode::InvalidInputSecret => "The secret parameter is invalid or malformed.",
        ErrorCode::MissingInputResponse => "The response parameter is missing.",
        ErrorCode::InvalidInputResponse => "The response parameter is invalid or malformed.",
        ErrorCode::TimeoutOrDuplicate => "The response has already been redeemed or has expired.",
        ErrorCode::BadRequest => "The request is invalid or malformed.",
    }
}

async fn siteverify(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 300 verifications per 10 s per IP (matches siteverify.js).
    let ip = client_ip(&headers, &addr.ip().to_string());
    let allowed = if st.redis_ratelimit {
        st.store
            .rate_hit(&format!("siteverify:{site_key}"), &ip, 10_000, 300)
            .await
            .unwrap_or(true)
    } else {
        st.limiter.hit(&format!("siteverify:{site_key}"), &ip, 10_000, 300)
    };
    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_response(ErrorCode::BadRequest, "Rate limit exceeded")),
        )
            .into_response();
    }
    verify_common(&st, &headers, &body, Some(&site_key), true).await
}

async fn siteverify_alias(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    verify_common(&st, &headers, &body, None, true).await
}

async fn validate(
    State(st): State<AppState>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    verify_common(&st, &headers, &body, Some(&site_key), false).await
}

/// The official dashboard's frontend, served straight from the Cap source
/// tree (`cap/standalone/public`) — the same files `static.js` in the JS
/// server serves, not a build artifact.
///
/// `ADMIN_LEGACY_DIR` (or `dashboard_dir` in config.toml) overrides the
/// directory. Without it, candidates next to the executable, next to the
/// build-time manifest, and relative to the working directory are tried in
/// that order, so the location does not depend on where the process was
/// started from.
fn dashboard_root() -> std::path::PathBuf {
    if let Some(dir) = &settings().dashboard_dir {
        return dir.clone();
    }
    let mut candidates: Vec<std::path::PathBuf> = vec![
        // Inside the data directory, for self-contained deployments.
        settings().data_dir.join("dashboard"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("../cap/standalone/public"));
            candidates.push(dir.join("cap/standalone/public"));
            candidates.push(dir.join("dashboard"));
        }
    }
    // Build-time location: `<workspace>/crates/server` → `<workspace>/../cap/...`
    candidates.push(std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../cap/standalone/public"
    )));
    candidates.push("../cap/standalone/public".into());
    candidates.push("./static/admin".into());

    for p in candidates {
        if p.join("index.html").is_file() {
            return p;
        }
    }
    std::path::PathBuf::from("dashboard")
}

/// Files an unauthenticated visitor may fetch: the login page needs its
/// stylesheet, fonts and the i18n script, and the flag sprites are public.
/// Mirrors `UNAUTHED_ALLOWLIST` in `standalone/src/static.js`.
const PUBLIC_UNAUTHED: [&str; 7] = [
    "logo-small.webp",
    "assets/ibm-plex-sans.woff2",
    "assets/lilex-regular.woff2",
    "assets/style.css",
    "assets/chart.js@4.5.0.min.js",
    "js/geo.js",
    "js/share.js",
];

fn is_unauthed_public(rel: &str) -> bool {
    PUBLIC_UNAUTHED.contains(&rel)
        || rel == "js/i18n.js"
        || rel.starts_with("assets/flags/")
}

fn content_type_for(rel: &str) -> &'static str {
    match rel.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

/// The `cap_authed` cookie's value, if the request carries one.
fn auth_cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    raw.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == "cap_authed").then(|| v.trim().to_string())
    })
}

/// A cookie only counts when its session binding still exists in *this*
/// install's Redis. A stale `cap_authed=yes` (from the JS server or an
/// earlier build) resolves to nothing, so the visitor gets the login page
/// instead of a dashboard that cannot load any data.
async fn cookie_authed(st: &AppState, headers: &HeaderMap) -> bool {
    let Some(value) = auth_cookie_value(headers) else {
        return false;
    };
    if value.is_empty() {
        return false;
    }
    let Some(admin) = st.admin.as_ref() else {
        return false;
    };
    admin
        .kv_exists(&cap_admin::cookie_session_key(&value))
        .await
        .unwrap_or(false)
}

async fn serve_dashboard_file(rel: &str, cache: &'static str) -> Response {
    let root = dashboard_root();
    // Resolve inside the root only; `.` and `..` are rejected outright, as in
    // `static.js`.
    let safe = !rel.is_empty()
        && !rel.contains('\0')
        && !rel.split('/').any(|seg| seg == ".." || seg == ".");
    if !safe {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let candidate = root.join(rel);
    let ok = match (std::fs::canonicalize(&root), std::fs::canonicalize(&candidate)) {
        (Ok(base), Ok(path)) => path.starts_with(&base),
        _ => false,
    };
    if !ok {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let bytes = match tokio::fs::read(&candidate).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let mut out = HeaderMap::new();
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type_for(rel)),
    );
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if rel.ends_with(".html") {
        out.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        out.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        );
        out.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        );
    }
    (StatusCode::OK, out, bytes).into_response()
}

/// `GET /` — the dashboard when `cap_authed=yes`, the login page otherwise
/// (the same switch `standalone/src/index.js` makes).
async fn root_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let page = if st.admin_cfg.demo || cookie_authed(&st, &headers).await {
        "index.html"
    } else {
        "login.html"
    };
    serve_dashboard_file(page, "no-cache").await
}

async fn login_page() -> Response {
    serve_dashboard_file("login.html", "no-cache").await
}

/// `GET /tester` — the challenge tester: solve against a site key and watch
/// the solver log (progress, timing, token, siteverify result).
async fn tester_page() -> Response {
    serve_dashboard_file("tester.html", "no-cache").await
}

/// `GET /public/*` — assets behind the same authentication gate as the JS
/// server: unauthenticated visitors only get the login page's own files.
async fn public_asset(State(st): State<AppState>, Path(rel): Path<String>, headers: HeaderMap) -> Response {
    let rel = rel.trim_start_matches('/').to_string();
    let allowed = is_unauthed_public(&rel)
        || st.admin_cfg.demo
        || cookie_authed(&st, &headers).await;
    if !allowed {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    // Revalidate on every load: the panel ships inside the binary, so a
    // stale cached script after an upgrade would break the UI.
    let cache = "no-cache";
    serve_dashboard_file(&rel, cache).await
}

/// `GET /demo` — the original challenge tester (`tester.html`) with the demo
/// site key and secret pre-filled, so the whole solve → verify loop can be
/// exercised from one page. Everything else (layout, log box, messages) is the
/// upstream file, unmodified.
async fn demo_page(State(st): State<AppState>) -> Response {
    if !st.admin_cfg.demo {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    // The reputation test page: click "开始验证", and the panel underneath
    // shows the score, level, recommended action and every penalty reason.
    let (site_key, secret) = match demo_widget_credentials(&st).await {
        Ok(k) => k,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("demo key: {e}")).into_response()
        }
    };

    let path = dashboard_root().join("reputation.html");
    let html = match tokio::fs::read_to_string(&path).await {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                "reputation.html is missing from the dashboard bundle",
            )
                .into_response()
        }
    };
    let html = html
        .replace(
            r#"<cap-embed id="cap" data-site-key=""></cap-embed>"#,
            &format!(r#"<cap-embed id="cap" data-site-key="{site_key}"></cap-embed>"#),
        )
        .replace(
            r#"<script src="/embed.js"></script>"#,
            &format!(
                "<script>window.CAP_SITE={:?};window.CAP_SECRET={:?};</script><script src=\"/embed.js\"></script>",
                site_key, secret
            ),
        )
        .replace(
            r#"fetch("/verify""#,
            &format!(r#"fetch("/demo/verify""#),
        );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    (StatusCode::OK, headers, html).into_response()
}

/// `POST /demo/verify` — siteverify for the demo page (the secret never
/// leaves the server; the page just forwards the token).
async fn demo_verify(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !st.admin_cfg.demo {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let (site_key, secret) = match demo_widget_credentials(&st).await {
        Ok(k) => k,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("demo key: {e}")).into_response()
        }
    };
    let token = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v.get("response").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    let payload = json!({ "secret": secret, "response": token });
    let bytes = Bytes::from(payload.to_string());
    // This is a server-to-server call on behalf of the browser that solved the
    // challenge, so forward its UA for the session-binding check.
    let mut fwd = headers.clone();
    if let Some(ua) = headers.get(header::USER_AGENT) {
        fwd.insert(HeaderName::from_static("x-cap-client-ua"), ua.clone());
    }
    let resp = verify_common(&st, &fwd, &bytes, Some(&site_key), true).await;
    // Attach the score of the solve that produced this token.
    let last = st
        .kv
        .get(&format!("demo:last-trust:{site_key}"))
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    let mut doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "trust".into(),
            last.get("trust").cloned().unwrap_or(Value::Null),
        );
        obj.insert(
            "action".into(),
            last.get("action").cloned().unwrap_or(Value::Null),
        );
    }
    (status, Json(doc)).into_response()
}

/// A site key + secret for the demo page. Created on first use and kept in
/// Redis under `demo:widget-key`; demo instances have no real keys otherwise.
async fn demo_widget_credentials(st: &AppState) -> Result<(String, String), String> {
    if let Ok(Some(existing)) = st.kv.get("demo:widget-key").await {
        if let Some((sk, secret)) = existing.split_once(':') {
            if st.kv.exists(&format!("key:{sk}")).await.unwrap_or(false) {
                return Ok((sk.to_string(), secret.to_string()));
            }
        }
    }

    let site_key = random_hex(5);
    let secret = format!("sk-{}", cap_core::random_hex(24));
    let secret_hash = format!("sha256:{}", cap_core::sha256_hex(&secret));
    let jwt_secret = format!("{}{}", random_hex(24), random_hex(8));
    let config = serde_json::json!({
        "protocol": "hashwx", "hashwxDifficulty": 1000000, "rsw": false,
        "difficulty": 4, "challengeCount": 80, "saltSize": 32,
        "instrumentation": true, "obfuscationLevel": 5,
        "blockAutomatedBrowsers": false, "ratelimitMax": null,
        "ratelimitDuration": null, "corsOrigins": null,
        "blockNonBrowserUA": false, "requiredHeaders": null,
        // Demo only: let headless/automated browsers through so the test
        // page always reaches siteverify.
        "blockOnDeny": false,
    });
    st.kv
        .hset_pairs(
            &format!("key:{site_key}"),
            &[
                ("name", "demo-widget".to_string()),
                ("secretHash", secret_hash),
                ("jwtSecret", jwt_secret),
                ("config", config.to_string()),
                ("created", now_ms().to_string()),
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
    st.kv
        .sadd("keys", &site_key)
        .await
        .map_err(|e| e.to_string())?;

    // First-writer wins: a burst of first visits must not create one key per
    // request (the losers would serve a key whose token /demo/verify rejects).
    let _ = st
        .kv
        .set_nx_ex(
            "demo:widget-key",
            &format!("{site_key}:{secret}"),
            365 * 86_400,
        )
        .await
        .map_err(|e| e.to_string())?;

    // Always answer with the authoritative pointer: a request that lost the
    // race must not render its own (now deleted) key, or its token would be
    // rejected by /demo/verify.
    if let Ok(Some(existing)) = st.kv.get("demo:widget-key").await {
        if let Some((sk, secret)) = existing.split_once(':') {
            if sk != site_key {
                let _ = st.kv.del(&format!("key:{site_key}")).await;
                let _ = st.kv.srem("keys", &site_key).await;
            } else {
                eprintln!("[cap] demo page created site key {site_key}");
            }
            return Ok((sk.to_string(), secret.to_string()));
        }
    }
    Err("demo key could not be stored".into())
}

/// `GET /share/:token` — the public share page (its token lives in the URL hash).
async fn share_page() -> Response {
    serve_dashboard_file("share.html", "no-cache").await
}

/// Platform / OS from a User-Agent string, matching `parseUA` in `cap.js`.
fn parse_ua(ua: &str) -> (Option<&'static str>, Option<&'static str>) {
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

/// Record the UA/IP/host that asked for the challenge so redeem can reject a
/// solve submitted from a different environment (`session_env_changed`).
async fn remember_challenge_env(
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
async fn check_challenge_env(
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
async fn load_integrity(st: &AppState) -> Option<Value> {
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
fn seal_integrity(payload: &mut Value, integrity: &Option<Value>, secret: &str) {
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
fn check_integrity(claims: &Value, body: &Value, secret: &str) -> Result<(), String> {
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

/// `true` when the UA looks like a real browser (mirrors the JS check).
fn is_browser_ua(ua: &str) -> bool {
    if ua.is_empty() {
        return false;
    }
    let lower = ua.to_ascii_lowercase();
    lower.contains("mozilla/")
        && !lower.contains("python-requests")
        && !lower.contains("curl/")
        && !lower.contains("wget/")
        && !lower.contains("httpclient")
        && !lower.contains("okhttp")
        && !lower.contains("go-http-client")
        && !lower.contains("node-fetch")
        && !lower.contains("axios")
        && !lower.contains("headlesschrome")
}

/// Per-key filtering: block non-browser UAs and requests missing the
/// configured headers. Global settings apply unless the key overrides them.
async fn filter_request(st: &AppState, cfg: &KeyConfig, headers: &HeaderMap, site_key: &str) -> Option<Response> {
    let global = st.cache.setting(&st.kv, "settings:filtering").await;

    let block_ua = cfg
        .block_non_browser_ua
        .or_else(|| global.get("blockNonBrowserUA").and_then(Value::as_bool))
        .unwrap_or(false);
    let required: Vec<String> = cfg
        .required_headers
        .clone()
        .or_else(|| {
            global
                .get("requiredHeaders")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        })
        .unwrap_or_default();

    let ua = header_str(headers, "user-agent");
    let blocked = (block_ua && !is_browser_ua(&ua))
        || required.iter().any(|name| {
            headers
                .get(name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().is_empty())
                .unwrap_or(true)
        });

    if !blocked {
        return None;
    }
    let _ = st
        .kv
        .hincrby(
            &format!("metrics:failed:{site_key}"),
            &hourly_bucket(now_ms()).to_string(),
            1,
        )
        .await;
    Some(
        (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "filtered", "reason": "Request does not look like a real browser"})),
        )
            .into_response(),
    )
}

/// Permissive CORS for the challenge endpoints: the widget may run from a
/// different origin, and the JS server's CORS layer allows it by default.
/// Authentication still applies to the real (non-preflight) request.
async fn cors_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if req.method() == axum::http::Method::OPTIONS {
        let mut resp = Response::new(axum::body::Body::empty());
        *resp.status_mut() = StatusCode::NO_CONTENT;
        if let Some(origin) = &origin {
            if let Ok(v) = HeaderValue::from_str(origin) {
                let h = resp.headers_mut();
                h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
                h.insert(
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("GET, POST, OPTIONS"),
                );
                h.insert(
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    HeaderValue::from_static(
                        "content-type, authorization, x-requested-with, x-cap-client-ua, x-cap-client-host",
                    ),
                );
                h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("3600"));
                h.insert(header::VARY, HeaderValue::from_static("Origin"));
            }
        }
        return resp;
    }

    let mut resp = next.run(req).await;
    if let Some(origin) = origin {
        if let Ok(v) = HeaderValue::from_str(&origin) {
            resp.headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            resp.headers_mut()
                .insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    resp
}

/// Whether `ip` falls inside `net` (`a.b.c.d/len`, IPv4 only).
fn cidr_match(net: &str, ip: &str) -> bool {
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

/// Check `blocked:<siteKey>` for an exact IP, a CIDR, or a country/ASN match
/// (the latter resolved through the local database or proxy headers).
async fn is_blocked(
    st: &AppState,
    site_key: &str,
    ip: &str,
    headers: &HeaderMap,
    headers_trusted: bool,
) -> bool {
    let Ok(entries) = st.kv.hgetall(&format!("blocked:{site_key}")).await else {
        return false;
    };
    if entries.is_empty() {
        return false;
    }
    let now = now_ms();
    let mut expired = Vec::new();
    let mut hit = false;
    let mut wants_country = false;
    let mut wants_asn = false;

    for (field, value) in &entries {
        let permanent = value == "0";
        let expires = value.parse::<i64>().unwrap_or(0);
        if !permanent && expires <= now {
            expired.push(field.clone());
            continue;
        }
        if field == ip {
            hit = true;
            break;
        }
        if let Some(net) = field.strip_prefix("cidr:") {
            if cidr_match(net, ip) {
                hit = true;
                break;
            }
        } else if field.starts_with("country:") {
            wants_country = true;
        } else if field.starts_with("asn:") {
            wants_asn = true;
        }
    }

    if !expired.is_empty() {
        let refs: Vec<&str> = expired.iter().map(String::as_str).collect();
        let _ = st.kv.hdel_fields(&format!("blocked:{site_key}"), &refs).await;
    }
    if hit {
        return true;
    }
    if !wants_country && !wants_asn {
        return false;
    }

    // Header-configured values win, then the local database.
    let cfg = st.cache.setting(&st.kv, "settings:headers").await;
    let header_val = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let country = if headers_trusted {
        header_val(cfg.get("countryHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };
    let asn = if headers_trusted {
        header_val(cfg.get("asnHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };
    let (db_country, db_asn) = match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => cap_ipdb::lookup(&st.ipdb, addr),
        Err(_) => (None, None),
    };
    let country = country.or(db_country);
    let asn = asn.or(db_asn.map(|n| n.to_string()));

    if wants_country {
        if let Some(c) = country {
            if entries.contains_key(&format!("country:{c}")) {
                return true;
            }
        }
    }
    if wants_asn {
        if let Some(a) = asn {
            if entries.contains_key(&format!("asn:{a}")) {
                return true;
            }
        }
    }
    false
}

/// Load the RSW keypair, generating it on first use (the JS server does the
/// same at key creation and at challenge time).
async fn ensure_rsw_keypair(st: &AppState) -> Result<std::collections::HashMap<String, String>, String> {
    let fields = st
        .store
        .hgetall("settings:rsw_keypair")
        .await
        .map_err(|e| e.to_string())?;
    if !fields.is_empty() {
        return Ok(fields);
    }
    let bits = settings().rsw_bits.max(512) & !1; // even, at least 512
    let pair = tokio::task::spawn_blocking(move || cap_proto::generate_keypair(bits))
        .await
        .map_err(|e| e.to_string())?;
    let pairs = [
        ("N", pair.n.to_str_radix(10)),
        ("p", pair.p.to_str_radix(10)),
        ("q", pair.q.to_str_radix(10)),
        ("bits", pair.bits.to_string()),
        ("created", now_ms().to_string()),
    ];
    st.kv
        .hset_pairs("settings:rsw_keypair", &pairs)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("[cap] generated the RSW keypair on first use");
    st.store
        .hgetall("settings:rsw_keypair")
        .await
        .map_err(|e| e.to_string())
}

/// Attribute a successful solve to a country / ASN. Explicit proxy headers
/// (configured in Settings → IP data) win over the local database.
async fn record_geo(st: &AppState, site_key: &str, headers: &HeaderMap, addr: &SocketAddr) {
    let ip = client_ip(headers, &addr.ip().to_string());
    let header = |name: &str| -> Option<String> {
        if name.is_empty() {
            return None;
        }
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let cfg = st.cache.setting(&st.kv, "settings:headers").await;

    // Geo headers are only trusted from a declared proxy: otherwise a client
    // could claim any country/ASN and dodge a country blocklist.
    let trusted = proxy_trusted(headers, &addr.ip().to_string());
    let country = if trusted {
        header(cfg.get("countryHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };
    let asn = if trusted {
        header(cfg.get("asnHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };

    let (db_country, db_asn) = match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => cap_ipdb::lookup(&st.ipdb, addr),
        Err(_) => (None, None),
    };

    if let Some(code) = country.or(db_country) {
        st.metrics
            .incr(&format!("metrics:country:{site_key}"), &code, 1);
    }
    if let Some(net) = asn.or(db_asn.map(|n| n.to_string())) {
        st.metrics
            .incr(&format!("metrics:asn:{site_key}"), &net, 1);
    }
}

// ---------------------------------------------------------------------------
// IP database settings (download, progress, delete)
// ---------------------------------------------------------------------------

async fn ipdb_status(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let stored = st
        .kv
        .get("settings:ipdb")
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let mode = st.ipdb.mode();
    let progress = st.ipdb.progress();
    json_resp(
        StatusCode::OK,
        json!({
            "mode": mode.as_str(),
            "provider": mode.as_str(),
            "configured": mode != cap_ipdb::Mode::None,
            "country": if st.ipdb.country_exists() {
                json!({ "exists": true, "size": st.ipdb.country_size() })
            } else {
                json!({ "exists": false })
            },
            "asn": if st.ipdb.asn_exists() {
                json!({ "exists": true, "size": st.ipdb.asn_size() })
            } else {
                json!({ "exists": false })
            },
            "loaded": {
                "country": st.ipdb.country_exists(),
                "asn": st.ipdb.asn_exists(),
            },
            "lastUpdated": stored.get("updatedAt").cloned().unwrap_or(Value::Null),
            "error": progress.error,
            "progress": {
                "active": progress.active,
                "file": progress.file,
                "downloaded": progress.downloaded,
                "total": progress.total,
            },
            "sources": {
                "maxmind": {
                    "accountIdSet": stored.get("maxmindAccountId").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false),
                    "keySet": stored.get("maxmindKey").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false),
                },
                "ipinfo": {
                    "tokenSet": stored.get("ipinfoToken").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false),
                },
            },
        }),
    )
}

async fn ipdb_put(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "Invalid body" }),
        );
    };
    let provider = payload
        .get("provider")
        .or_else(|| payload.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("none");
    let Some(mode) = cap_ipdb::Mode::parse(provider) else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "provider must be none, dbip, maxmind or ipinfo" }),
        );
    };

    let mut doc = serde_json::Map::new();
    doc.insert("provider".into(), json!(mode.as_str()));
    doc.insert("mode".into(), json!(mode.as_str()));
    for field in ["maxmindAccountId", "maxmindKey", "ipinfoToken"] {
        if let Some(v) = payload.get(field) {
            if let Some(s) = v.as_str() {
                doc.insert(field.into(), json!(s));
            }
        }
    }
    doc.insert(
        "updatedAt".into(),
        json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
    );
    let raw = Value::Object(doc).to_string();
    if st.kv.set("settings:ipdb", &raw).await.is_err() {
        return json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "storage error" }),
        );
    }
    json_resp(StatusCode::OK, json!({ "success": true }))
}

async fn ipdb_download(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let stored = st
        .kv
        .get("settings:ipdb")
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);

    let provider = payload
        .get("provider")
        .or_else(|| payload.get("mode"))
        .and_then(Value::as_str)
        .or_else(|| stored.get("provider").and_then(Value::as_str))
        .unwrap_or("none");
    let Some(mode) = cap_ipdb::Mode::parse(provider) else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "unknown provider" }),
        );
    };
    if mode == cap_ipdb::Mode::None {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "pick a provider first" }),
        );
    }

    let pick = |name: &str| -> String {
        payload
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                stored
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default()
    };
    let creds = cap_ipdb::Credentials {
        maxmind_account_id: pick("maxmindAccountId"),
        maxmind_key: pick("maxmindKey"),
        ipinfo_token: pick("ipinfoToken"),
    };

    // Persist credentials alongside the provider.
    if let Value::Object(obj) = &payload {
        let mut doc = stored.as_object().cloned().unwrap_or_default();
        for (k, v) in obj {
            if matches!(k.as_str(), "maxmindAccountId" | "maxmindKey" | "ipinfoToken") {
                doc.insert(k.clone(), v.clone());
            }
        }
        doc.insert("provider".into(), json!(mode.as_str()));
        doc.insert("mode".into(), json!(mode.as_str()));
        let _ = st.kv.set("settings:ipdb", &Value::Object(doc).to_string()).await;
    }

    if !st.ipdb.start_download(mode, creds) {
        return json_resp(
            StatusCode::CONFLICT,
            json!({ "success": false, "error": "A download is already running" }),
        );
    }
    json_resp(StatusCode::OK, json!({ "success": true, "started": true }))
}

async fn ipdb_progress(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let p = st.ipdb.progress();
    json_resp(
        StatusCode::OK,
        json!({
            "active": p.active,
            "file": p.file,
            "downloaded": p.downloaded,
            "total": p.total,
            "error": p.error,
        }),
    )
}

async fn ipdb_delete(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let _ = st.kv.del("settings:ipdb").await;
    let _ = std::fs::remove_file(st.ipdb.country_path());
    let _ = std::fs::remove_file(st.ipdb.asn_path());
    st.ipdb.reload();
    st.ipdb.set_mode(cap_ipdb::Mode::None);
    json_resp(StatusCode::OK, json!({ "success": true }))
}

// ---------------------------------------------------------------------------
// Front-end releases (upload a zip / list / activate / delete / download)
// ---------------------------------------------------------------------------

fn json_resp(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn admin_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
        .collect()
}

async fn require_admin(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let Some(admin) = st.admin.as_ref() else {
        return Err(json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "success": false, "error": "Admin API is not configured" }),
        ));
    };
    match cap_admin::require_session(admin, &admin_headers(headers)).await {
        Ok(()) => Ok(()),
        Err(r) => Err(json_resp(
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::UNAUTHORIZED),
            r.body,
        )),
    }
}

/// `GET /server/releases` — published bundles, newest first.
async fn releases_list(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    json_resp(
        StatusCode::OK,
        json!({
            "releases": st.releases.list(),
            "active": st.releases.active_release_id(),
        }),
    )
}

/// `POST /server/releases` — body is the zip archive itself
/// (`Content-Type: application/zip`, or anything else: the bytes are sniffed).
async fn release_upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    if body.is_empty() {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "Empty upload" }),
        );
    }
    let store = Arc::clone(&st.releases);
    match tokio::task::spawn_blocking(move || store.publish(&body)).await {
        Ok(Ok(meta)) => json_resp(StatusCode::OK, json!({ "success": true, "release": meta })),
        Ok(Err(e)) => json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": e }),
        ),
        Err(_) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "publish task failed" }),
        ),
    }
}

/// `POST /server/releases/:id/activate` — switch (or roll back) to a release.
async fn release_activate(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let store = Arc::clone(&st.releases);
    let id_for_task = id.clone();
    match tokio::task::spawn_blocking(move || store.activate(&id_for_task)).await {
        Ok(Ok(())) => json_resp(StatusCode::OK, json!({ "success": true, "active": id })),
        Ok(Err(e)) => json_resp(StatusCode::BAD_REQUEST, json!({ "success": false, "error": e })),
        Err(_) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "activate task failed" }),
        ),
    }
}

/// `DELETE /server/releases/:id`
async fn release_delete(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    let store = Arc::clone(&st.releases);
    let id_for_task = id.clone();
    match tokio::task::spawn_blocking(move || store.delete(&id_for_task)).await {
        Ok(Ok(())) => json_resp(StatusCode::OK, json!({ "success": true })),
        Ok(Err(e)) => json_resp(StatusCode::BAD_REQUEST, json!({ "success": false, "error": e })),
        Err(_) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "delete task failed" }),
        ),
    }
}

/// `GET /server/releases/:id/archive` — the original uploaded zip.
async fn release_archive(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return r;
    }
    match st.releases.source_zip(&id) {
        Some(bytes) => {
            let mut out = HeaderMap::new();
            out.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            out.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{id}.zip\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            (StatusCode::OK, out, bytes).into_response()
        }
        None => json_resp(
            StatusCode::NOT_FOUND,
            json!({ "success": false, "error": "archive not found" }),
        ),
    }
}

async fn admin_handler(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(admin) = st.admin.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"success": false, "error": "admin API disabled (ADMIN_KEY unset)"})),
        )
            .into_response();
    };
    let path = uri.path();
    let admin_path = if let Some(rest) = path.strip_prefix("/server") {
        if rest.is_empty() {
            "/".to_string()
        } else {
            rest.to_string()
        }
    } else {
        path.to_string()
    };
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
        .collect();
    let peer_ip = peer.ip().to_string();
    let req = cap_admin::AdminRequest {
        method: method.as_str(),
        path: &admin_path,
        query: uri.query().unwrap_or(""),
        headers: &header_pairs,
        body: &body,
        peer: &peer_ip,
    };
    let resp = cap_admin::handle(admin, st.admin_cfg.as_ref(), &req).await;
    // A successful admin write must be visible immediately on this instance;
    // otherwise a revoked key keeps redeeming (and a new one 404s) for up to
    // the cache TTL.
    if resp.status < 300
        && matches!(
            method,
            axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE
        )
    {
        st.cache.clear();
    }
    let mut out_headers = HeaderMap::new();
    for (k, v) in &resp.headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            out_headers.insert(name, value);
        }
    }
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, out_headers, Json(resp.body)).into_response()
}

async fn asset_handler(
    State(st): State<AppState>,
    Path(name): Path<String>,
    req_headers: HeaderMap,
) -> Response {
    // A published release always wins over the CDN cache.
    if let Some(file) = st.releases.get(&name) {
        let accepts_gzip = req_headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("gzip"))
            .unwrap_or(false);
        let (body, encoded) = match (accepts_gzip, file.gzip) {
            (true, Some(gz)) => (gz, true),
            _ => (file.plain, false),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(file.content_type),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        if encoded {
            headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
        }
        return (StatusCode::OK, headers, body).into_response();
    }
    let Some((bytes, content_type)) = st.assets.get(&name) else {
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain; charset=utf-8")],
            "asset not cached yet (set ENABLE_ASSETS_SERVER=true and wait for the first refresh)",
        )
            .into_response();
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    (StatusCode::OK, headers, bytes).into_response()
}

async fn embed_js() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    (StatusCode::OK, headers, cap_embed::loader_js()).into_response()
}

async fn embed_page(
    State(st): State<AppState>,
    Path(site_key): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    if !cap_embed::validate_site_key(&site_key) {
        return (StatusCode::BAD_REQUEST, "invalid site key").into_response();
    }
    let key = match st.cache.key(&st.store, &site_key).await {
        Some(k) => Arc::unwrap_or_clone(k),
        None => return (StatusCode::NOT_FOUND, "unknown site key").into_response(),
    };
    let parent = query
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "parent")
        .map(|(_, v)| {
            form_urlencoded::parse(v.as_bytes())
                .map(|(_, val)| val.to_string())
                .collect::<String>()
        })
        .unwrap_or_default();

    let policy = cap_embed::frame_policy(&cors_origins(&key.config), &parent);
    let (frame_ancestors, parent_origin) = match policy {
        cap_embed::FramePolicy::Allow(origin) => (origin, parent.clone()),
        cap_embed::FramePolicy::Deny => {
            return html_response(
                StatusCode::FORBIDDEN,
                Some("frame-ancestors 'none'"),
                "embedding not allowed for this origin".into(),
            )
        }
    };

    let html = cap_embed::embed_page(&site_key, &parent_origin, &st.embed_widget_url);
    html_response(
        StatusCode::OK,
        Some(&format!("frame-ancestors {frame_ancestors}")),
        html,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::init()?;
    eprintln!("[cap] data directory: {}", cfg.data_dir.display());

    let kv = cap_kv::Kv::connect_redis(&cfg.redis_url).await?;
    eprintln!("[cap] storage: {} ({})", kv.backend_name(), cfg.redis_url);

    let store = Store::new(kv.clone());
    let admin_cfg = cap_admin::AdminConfig {
        admin_key: cfg.admin_key.clone(),
        demo: cfg.demo,
    };
    let admin_store = if cfg.admin_key.is_empty() {
        None
    } else {
        Some(cap_admin::AdminStore::new(kv.clone()))
    };

    let assets = Arc::new(cap_assets::AssetCache::new());
    if cfg.cdn_fallback {
        let asset_cfg = cap_assets::AssetConfig {
            cache_host: cfg.cache_host.clone(),
            widget_version: cfg.widget_version.clone(),
            wasm_version: cfg.wasm_version.clone(),
        };
        asset_cfg.warn_on_latest();
        cap_assets::spawn_refresher(
            assets.clone(),
            asset_cfg,
            Some(cfg.redis_url.clone()),
            cap_assets::DEFAULT_REFRESH_INTERVAL,
        );
    }

    let ipdb = Arc::new(
        cap_ipdb::IpDb::open(&cfg.data_dir.join("ipdb"), &cfg.tmp_dir())
            .map_err(|e| format!("cannot open ip database directory: {e}"))?,
    );
    if let Ok(Some(raw)) = kv.get("settings:ipdb").await {
        if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&raw) {
            let provider = doc
                .get("provider")
                .or_else(|| doc.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            if let Some(mode) = cap_ipdb::Mode::parse(provider) {
                ipdb.set_mode(mode);
            }
        }
    }
    eprintln!(
        "[cap] ip database: mode={}, country={}, asn={}",
        ipdb.mode().as_str(),
        ipdb.country_exists(),
        ipdb.asn_exists()
    );

    let releases = Arc::new(
        cap_assets::ReleaseStore::open(&cfg.data_dir)
            .map_err(|e| format!("cannot open releases directory: {e}"))?,
    );
    // Ship the compiled-in widget as the default release, so a fresh install
    // serves /assets/* locally instead of depending on the CDN.
    match releases.publish_builtin(config::builtin_widget_zip(), config::WIDGET_ID.trim()) {
        Ok(meta) => eprintln!(
            "[cap] built-in widget release: {} file(s), {} protected, active={}",
            meta.files, meta.protected, meta.active
        ),
        Err(e) => eprintln!("[cap] could not publish the built-in widget: {e}"),
    }

    let embed_widget_url = cfg.embed_widget_url.clone();
    let port = cfg.port;
    let _ = SETTINGS.set(cfg);

    let state = AppState {
        store,
        embed_widget_url,
        admin: admin_store,
        admin_cfg: Arc::new(admin_cfg),
        assets,
        releases,
        kv,
        ipdb,
        cache: Arc::new(cache::ConfigCache::new()),
        limiter: Arc::new(ratelimit::LocalLimiter::new()),
        metrics: Arc::new(metrics_buf::MetricsBuffer::new()),
        redis_ratelimit: std::env::var("CAP_RL_MODE")
            .map(|v| v.eq_ignore_ascii_case("redis"))
            .unwrap_or(false),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(health))
        .route("/embed.js", get(embed_js))
        .route("/embed/:siteKey", get(embed_page))
        .route("/assets/:name", get(asset_handler))
        .route("/", get(root_page))
        .route("/login", get(login_page))
        .route("/public/*rest", get(public_asset))
        .route("/demo", get(demo_page))
        .route(
            "/demo/verify",
            post(demo_verify).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/tester", get(tester_page))
        .route("/share", get(share_page))
        .route("/share/:token", get(admin_handler))
        .route("/share/:token/geo-stats", get(admin_handler))
        .route(
            "/server/settings/ipdb",
            get(ipdb_status)
                .put(ipdb_put)
                .post(ipdb_download)
                .delete(ipdb_delete),
        )
        .route("/server/settings/ipdb/download", post(ipdb_download))
        .route("/server/settings/ipdb/progress", get(ipdb_progress))
        .route(
            "/server/releases",
            get(releases_list).post(release_upload),
        )
        .route("/server/releases/:id/activate", post(release_activate))
        .route("/server/releases/:id/archive", get(release_archive))
        .route("/server/releases/:id", axum::routing::delete(release_delete))
        .route("/auth/login", axum::routing::any(admin_handler))
        .route("/server", axum::routing::any(admin_handler))
        .route("/server/*rest", axum::routing::any(admin_handler))
        // Public share links (no auth) live outside /server.
        .route("/shares", axum::routing::any(admin_handler))
        .route("/shares/:id", axum::routing::any(admin_handler))
        .route(
            "/turnstile/v0/siteverify",
            post(siteverify_alias).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/:siteKey/challenge",
            post(challenge).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/:siteKey/redeem",
            post(redeem).layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/:siteKey/siteverify",
            post(siteverify).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/:siteKey/validate",
            post(validate).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .layer(axum::middleware::from_fn(cors_layer))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024));

    // Flush buffered metric counters once per second, in one pipeline.
    {
        let metrics = state.metrics.clone();
        let kv = state.kv.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                let _ = metrics.flush(&kv).await;
            }
        });
    }

    // Expire stale cache entries (site keys, settings) every minute.
    {
        let cache = state.cache.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                cache.sweep();
            }
        });
    }

    // Expire stale rate-limit windows so the map cannot grow with the IP count.
    {
        let limiter = state.limiter.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                limiter.sweep();
            }
        });
    }

    let app = app.with_state(state);

    let host = settings().hostname.clone();
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| format!("invalid SERVER_HOSTNAME {host}: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cap-server (rust) listening on http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
