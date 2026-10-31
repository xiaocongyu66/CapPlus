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
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

mod config;
mod v2;
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
    if proxy_trusted(headers, peer) {
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
    let host = {
        let fwd = header_str(headers, "x-forwarded-host");
        if fwd.is_empty() {
            header_str(headers, "host")
        } else {
            fwd
        }
    };
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
    let key = match st.store.key(&site_key).await {
        Ok(Some(k)) => k,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Invalid site key or secret"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("store: {e}")})),
            )
                .into_response()
        }
    };
    let cfg = key.config.clone();

    let ip = client_ip(&headers, &addr.ip().to_string());
    let max = cfg.ratelimit_max.unwrap_or(DEFAULT_RL_MAX);
    let window = cfg.ratelimit_duration.unwrap_or(DEFAULT_RL_WINDOW_MS);
    if let Ok(false) = st.store.rate_hit("challenge", &ip, window, max).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "Rate limit exceeded"})),
        )
            .into_response();
    }

    if cfg.protocol == "hashwx" {
        let Some((challs, expected)) = v2::hashwx_challenges(
            cfg.hashwx_difficulty.max(1),
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
        let Some(ev) = v2::encrypt_gcm(&json!(expected), &key.jwt_secret, v2::INFO_FMT2) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "seal_failed"})),
            )
                .into_response();
        };
        let mut challenges = challs;
        let mut expected_list = expected;
        append_instrumentation(&cfg, expires, &mut challenges, &mut expected_list);
        let Some(ev2) = v2::encrypt_gcm(&json!(expected_list), &key.jwt_secret, v2::INFO_FMT2)
        else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "seal_failed"})),
            )
                .into_response();
        };
        let _ = ev;
        let payload = json!({
            "f": 2, "n": nonce, "exp": expires, "iat": now, "sk": site_key, "ev": ev2,
        });
        let token = jwt_sign(&payload, &key.jwt_secret);
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
        let fields = match st.store.hgetall("settings:rsw_keypair").await {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("store: {e}")})),
                )
                    .into_response()
            }
        };
        let Some((challenge, expected)) = v2::rsw_challenge(&fields, cfg.rsw_t) else {
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
            &json!(expected_list),
            &key.jwt_secret,
            v2::INFO_FMT2,
        ) else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "seal_failed"})),
            )
                .into_response();
        };
        let payload = json!({
            "f": 2, "n": nonce, "exp": expires, "iat": now, "sk": site_key, "ev": ev,
        });
        let token = jwt_sign(&payload, &key.jwt_secret);
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
    let payload = json!({
        "n": nonce, "c": params.c, "s": params.s, "d": params.d,
        "exp": expires, "iat": now, "sk": site_key,
    });
    let token = jwt_sign(&payload, &key.jwt_secret);
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
    let solutions_raw: Vec<Value> = sols.clone();

    let key = match st.store.key(&site_key).await {
        Ok(Some(k)) => k,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Invalid site key or secret"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("store: {e}")})),
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
    let now = now_ms();
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if exp <= now {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "expired"}))).into_response();
    }
    let is_v2 = claims.get("f").and_then(Value::as_u64) == Some(2);
    let mut v2_trust: Option<(i32, String, cap_detect::Action)> = None;
    if is_v2 {
        let Some(ev) = claims.get("ev").and_then(Value::as_str) else {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        };
        let Some(expected) = v2::decrypt_gcm(ev, &key.jwt_secret, v2::INFO_FMT2) else {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        };
        // Run the probe detector on the captured instrumentation payload and
        // remember the verdict; the deny decision is enforced after the nonce
        // has been consumed (same ordering as the JS server).
        let captured = v2::take_probe(&expected, &solutions_raw);
        if captured.is_none() {
            eprintln!("[redeem] no probe captured (solutions={})", solutions_raw.len());
        }
        if let Some(cap) = captured {
            let opts = cap_detect::DetectOpts {
                font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
                optional_fields: &cap.optional_fields,
                accept_language: None,
            };
            let outcome = cap_detect::detect_automation(&cap.p, &opts);
            let owned = outcome.signals.clone();
            let sigs: Vec<cap_detect::Signal> =
                owned.iter().map(|s| s.as_signal()).collect();
            let trust = cap_detect::compute_trust_signals(&sigs, None, Some(outcome.pass));
            let action = cap_detect::trust_action(&trust);
            v2_trust = Some((trust.score, format!("{:?}", trust.level).to_lowercase(), action));
        }
        if let Err(reason) = v2::verify_solutions(&expected, &solutions_raw) {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), now / 3_600_000)
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
                .incr_metric(&format!("metrics:failed:{site_key}"), now / 3_600_000)
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

    if let Some((score, level, action)) = &v2_trust {
        eprintln!("[redeem] site={site_key} trust score={score} level={level} action={action:?}");
        if matches!(action, cap_detect::Action::Deny) && key.config.block_on_deny {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), now / 3_600_000)
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"success": false, "error": "trust_denied", "level": level, "score": score})),
            )
                .into_response();
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
    eprintln!("[redeem] site={site_key} issued token (verified)");
    let _ = st
        .store
        .incr_metric(&format!("metrics:verified:{site_key}"), now / 3_600_000)
        .await;

    Json(json!({
        "success": true,
        "token": redeem_token,
        "expires": token_expires,
        "scope": site_key,
    }))
    .into_response()
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

    let key = match st.store.key(&site_key).await {
        Ok(Some(k)) => k,
        _ => {
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
                    "Legacy argon2 secret hashes are not supported yet; rotate the secret key.",
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
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
    let page = if cookie_authed(&st, &headers).await {
        "index.html"
    } else {
        "login.html"
    };
    serve_dashboard_file(page, "no-cache").await
}

async fn login_page() -> Response {
    serve_dashboard_file("login.html", "no-cache").await
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

/// `GET /share/:token` — the public share page (its token lives in the URL hash).
async fn share_page() -> Response {
    serve_dashboard_file("share.html", "no-cache").await
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
    let req = cap_admin::AdminRequest {
        method: method.as_str(),
        path: &admin_path,
        query: uri.query().unwrap_or(""),
        headers: &header_pairs,
        body: &body,
    };
    let resp = cap_admin::handle(admin, st.admin_cfg.as_ref(), &req).await;
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

async fn asset_handler(State(st): State<AppState>, Path(name): Path<String>) -> Response {
    // A published release always wins over the CDN cache.
    if let Some((bytes, content_type)) = st.releases.get(&name) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        return (StatusCode::OK, headers, bytes).into_response();
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
    let key = match st.store.key(&site_key).await {
        Ok(Some(k)) => k,
        _ => return (StatusCode::NOT_FOUND, "unknown site key").into_response(),
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

    let releases = Arc::new(
        cap_assets::ReleaseStore::open(&cfg.data_dir)
            .map_err(|e| format!("cannot open releases directory: {e}"))?,
    );

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
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/embed.js", get(embed_js))
        .route("/embed/:siteKey", get(embed_page))
        .route("/assets/:name", get(asset_handler))
        .route("/", get(root_page))
        .route("/login", get(login_page))
        .route("/public/*rest", get(public_asset))
        .route("/share", get(share_page))
        .route("/share/:token", get(admin_handler))
        .route("/share/:token/geo-stats", get(admin_handler))
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
        .route("/turnstile/v0/siteverify", post(siteverify_alias))
        .route("/:siteKey/challenge", post(challenge))
        .route("/:siteKey/redeem", post(redeem))
        .route("/:siteKey/siteverify", post(siteverify))
        .route("/:siteKey/validate", post(validate))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cap-server (rust) listening on http://{addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
