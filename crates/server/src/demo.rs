//! Demo-mode page (reputation test), its verify proxy, and per-key request
//! filtering (UA / required headers).

use crate::business::{failure, store_failure};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use cap_core::business::{
    BusinessBinding, request_digest, sign_business_token, verify_business_token,
};
use cap_core::random_hex;
use cap_store::{KeyConfig, now_ms};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AppState;
use crate::http_util::{header_str, hourly_bucket};
use crate::pages::dashboard_root;
use crate::siteverify::verify_common;

/// Public shell only. Business issuance and verification require a real admin session.
pub(crate) async fn demo_page(State(st): State<AppState>) -> Response {
    if !st.admin_cfg.demo {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    if crate::settings().demo_allowed_domains.is_none() {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "demo_domains_missing: configure CAP_DEMO_ALLOWED_DOMAINS or server.demo_allowed_domains (not SERVER_HOSTNAME)",
        );
    }
    // Do not create keys as a side effect of an unauthenticated page view.

    let path = dashboard_root().join("reputation.html");
    let html = match tokio::fs::read_to_string(&path).await {
        Ok(h) => h,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                "reputation.html is missing from the dashboard bundle",
            )
                .into_response();
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (StatusCode::OK, headers, html).into_response()
}

fn demo_configuration_failure(error: &str) -> Response {
    // Only expose operator guidance, never raw Redis errors/URLs/credentials.
    let message = if error.starts_with("demo_domains_missing:") {
        "demo_domains_missing: configure CAP_DEMO_ALLOWED_DOMAINS or server.demo_allowed_domains"
    } else {
        "demo_configuration_unavailable: operator must check dedicated demo key corsOrigins against CAP_DEMO_ALLOWED_DOMAINS; no automatic key rotation"
    };
    failure(StatusCode::SERVICE_UNAVAILABLE, message)
}

fn matching_demo_domains(configured: &[String], expected: &[String]) -> bool {
    let Ok(mut configured) = cap_embed::normalize_domains(configured) else {
        return false;
    };
    configured.sort();
    configured.dedup();
    let mut expected = expected.to_vec();
    expected.sort();
    expected.dedup();
    configured == expected
}

const DEMO_BODY_LIMIT: usize = 16 * 1024;
const DEMO_TTL_MS: i64 = 120_000;
// The only operation offered here is a verification receipt, not arbitrary business execution.
const DEMO_OPERATION: &[u8] = br#"{"operation":"demo-verification-receipt","version":1}"#;

#[derive(Serialize, Deserialize)]
struct DemoContext {
    owner: String,
    expires: i64,
    binding: BusinessBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DemoVerifyRequest {
    response: String,
    handle: String,
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Exactly one real session authentication; no demo-mode authenticate shortcut,
/// query token or cookie fallback. Hash the authenticated bearer for ownership.
async fn demo_owner(st: &AppState, headers: &HeaderMap) -> Result<String, Response> {
    if !st.admin_cfg.demo {
        return Err(failure(StatusCode::NOT_FOUND, "not_found"));
    }
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED, "admin_session_required"))?;
    crate::admin_routes::require_admin(st, headers)
        .await
        .map_err(no_store)?;
    Ok(cap_core::sha256_hex(bearer))
}

async fn demo_body(request: Request) -> Result<Bytes, Response> {
    if !header_str(request.headers(), "content-type")
        .split(';')
        .next()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required"));
    }
    axum::body::to_bytes(request.into_body(), DEMO_BODY_LIMIT)
        .await
        .map_err(|_| failure(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"))
}

fn demo_digest() -> String {
    request_digest("POST", "/demo/verify", DEMO_OPERATION).expect("fixed demo operation")
}

/// POST /demo/credential. Only an empty JSON object is accepted: the server
/// chooses site/action/session/nonce/digest, never a browser-controlled proxy.
pub(crate) async fn demo_credential(State(st): State<AppState>, request: Request) -> Response {
    let owner = match demo_owner(&st, request.headers()).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = match demo_body(request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if serde_json::from_slice::<Value>(&body).ok() != Some(json!({})) {
        return failure(StatusCode::BAD_REQUEST, "empty_object_required");
    }
    if !crate::rate_allowed(&st, "demo-credential", &owner, DEMO_TTL_MS, 20).await {
        return failure(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let (site, _) = match demo_widget_credentials(&st).await {
        Ok(v) => v,
        Err(error) => return demo_configuration_failure(&error),
    };
    let Ok(Some(key)) = st.cache.key_checked(&st.store, &site).await else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "demo_configuration_unavailable",
        );
    };
    let binding = BusinessBinding {
        site: site.clone(),
        session: random_hex(32),
        action: "demo-verification-receipt".into(),
        nonce: random_hex(32),
        request_digest: demo_digest(),
    };
    let now = now_ms();
    let token = match sign_business_token(binding.clone(), &key.jwt_secret, now, Some(DEMO_TTL_MS))
    {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::INTERNAL_SERVER_ERROR, "credential_failed"),
    };
    let claims = match verify_business_token(&token, &key.jwt_secret, now) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::INTERNAL_SERVER_ERROR, "credential_failed"),
    };
    let issued = match st.store.issue_business(&claims, &token).await {
        Ok(v) => v,
        Err(e) => return store_failure(e),
    };
    let handle = random_hex(48);
    let context = DemoContext {
        owner,
        expires: issued.claims.exp,
        binding,
    };
    match st
        .kv
        .set_nx_ex(
            &format!("demo:context:{handle}"),
            &serde_json::to_string(&context).expect("demo context"),
            DEMO_TTL_MS / 1000,
        )
        .await
    {
        Ok(true) => (),
        _ => return failure(StatusCode::SERVICE_UNAVAILABLE, "context_unavailable"),
    }
    no_store(
        Json(
            json!({"businessToken": issued.token, "expires": issued.claims.exp,
        "handle": handle, "siteKey": site}),
        )
        .into_response(),
    )
}

fn context_matches(context: &DemoContext, owner: &str, now: i64) -> bool {
    context.owner == owner
        && context.expires > now
        && context.expires <= now + DEMO_TTL_MS
        && context.binding.action == "demo-verification-receipt"
        && context.binding.request_digest == demo_digest()
        && context.binding.validate().is_ok()
}

/// POST /demo/verify. Context is authoritative; success is only a fixed demo
/// verification receipt. Do not attach site-global last-trust as this user's score.
pub(crate) async fn demo_verify(State(st): State<AppState>, request: Request) -> Response {
    let owner = match demo_owner(&st, request.headers()).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let headers = request.headers().clone();
    let body = match demo_body(request).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let req: DemoVerifyRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if req.response.is_empty()
        || req.response.len() > 256
        || req.handle.len() != 48
        || !req.handle.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let raw = match st.kv.get(&format!("demo:context:{}", req.handle)).await {
        Ok(Some(v)) => v,
        Ok(None) => return failure(StatusCode::BAD_REQUEST, "context_expired"),
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "context_unavailable"),
    };
    let context: DemoContext = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "context_unavailable"),
    };
    if !context_matches(&context, &owner, now_ms()) {
        return failure(StatusCode::FORBIDDEN, "context_mismatch_or_expired");
    }
    let (site, secret) = match demo_widget_credentials(&st).await {
        Ok(v) => v,
        Err(error) => return demo_configuration_failure(&error),
    };
    if context.binding.site != site {
        return failure(StatusCode::FORBIDDEN, "context_mismatch_or_expired");
    }
    let b = context.binding;
    let bytes = Bytes::from(
        json!({"secret": secret, "response": req.response,
        "session": b.session, "action": b.action, "nonce": b.nonce,
        "requestDigest": b.request_digest})
        .to_string(),
    );
    // Do not forward arbitrary x-cap-client-* verification overrides.
    let mut fwd = HeaderMap::new();
    fwd.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(ua) = headers.get(header::USER_AGENT) {
        fwd.insert(HeaderName::from_static("x-cap-client-ua"), ua.clone());
    }
    no_store(verify_common(&st, &fwd, &bytes, Some(&site)).await)
}

/// A site key + secret for the demo page. Created on first use and kept in
/// Redis under `demo:widget-key`; demo instances have no real keys otherwise.
pub(crate) async fn demo_widget_credentials(st: &AppState) -> Result<(String, String), String> {
    let domains = crate::settings().demo_allowed_domains.clone().ok_or(
        "demo_domains_missing: configure CAP_DEMO_ALLOWED_DOMAINS or server.demo_allowed_domains (not SERVER_HOSTNAME)"
    )?;
    if let Some(existing) = st
        .kv
        .get("demo:widget-key")
        .await
        .map_err(|e| e.to_string())?
    {
        let (sk, secret) = existing
            .split_once(':')
            .ok_or("invalid demo pointer; operator repair required")?;
        if !cap_embed::validate_site_key(sk) || secret.is_empty() {
            return Err("invalid demo pointer; operator repair required".into());
        }
        let key = st
            .store
            .key(sk)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("missing demo key; operator repair required")?;
        // Never rotate an existing/shared key or silently relax legacy policy.
        if !matching_demo_domains(key.config.cors_origins.as_deref().unwrap_or(&[]), &domains) {
            return Err(
                "demo_domains_migration_required: existing demo key corsOrigins must match CAP_DEMO_ALLOWED_DOMAINS; operator migration required (key not rotated)"
                    .into(),
            );
        }
        return Ok((sk.to_string(), secret.to_string()));
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
        "ratelimitDuration": null, "corsOrigins": domains,
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
            if !cap_embed::validate_site_key(sk) || secret.is_empty() {
                return Err("invalid demo pointer".into());
            }
            let key = st
                .store
                .key(sk)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("missing demo key")?;
            if !matching_demo_domains(key.config.cors_origins.as_deref().unwrap_or(&[]), &domains) {
                return Err("demo domains require operator migration".into());
            }
            return Ok((sk.to_string(), secret.to_string()));
        }
    }
    Err("demo key could not be stored".into())
}

#[cfg(test)]
#[path = "demo_tests.rs"]
mod tests;

/// `true` when the UA looks like a real browser (mirrors the JS check).
pub(crate) fn is_browser_ua(ua: &str) -> bool {
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
pub(crate) async fn filter_request(
    st: &AppState,
    cfg: &KeyConfig,
    headers: &HeaderMap,
    site_key: &str,
) -> Option<Response> {
    let global = match st
        .cache
        .setting_optional(&st.kv, "settings:filtering")
        .await
        .and_then(|v| crate::cache::effective_filtering(v.as_ref(), cfg))
    {
        Ok(global) => global,
        Err(_) => {
            return Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "store_unavailable"})),
                )
                    .into_response(),
            );
        }
    };

    let block_ua = global.block_ua;
    let required = &global.required_headers;

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
            Json(
                json!({"error": "filtered", "reason": "Request does not look like a real browser"}),
            ),
        )
            .into_response(),
    )
}
