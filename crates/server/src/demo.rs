//! Demo-mode page (reputation test), its verify proxy, and per-key request
//! filtering (UA / required headers).

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cap_core::random_hex;
use cap_store::{now_ms, KeyConfig};
use serde_json::{json, Value};

use crate::http_util::{header_str, hourly_bucket};
use crate::pages::dashboard_root;
use crate::siteverify::verify_common;
use crate::AppState;

/// `GET /demo` — the original challenge tester (`tester.html`) with the demo
/// site key and secret pre-filled, so the whole solve → verify loop can be
/// exercised from one page. Everything else (layout, log box, messages) is the
/// upstream file, unmodified.
pub(crate) async fn demo_page(State(st): State<AppState>) -> Response {
    if !st.admin_cfg.demo {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    // The reputation test page: click "开始验证", and the panel underneath
    // shows the score, level, recommended action and every penalty reason.
    let (site_key, secret) = match demo_widget_credentials(&st).await {
        Ok(k) => k,
        Err(e) => {
            {
                eprintln!("[demo] demo key: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "demo key unavailable").into_response();
            }
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
pub(crate) async fn demo_verify(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !st.admin_cfg.demo {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let (site_key, secret) = match demo_widget_credentials(&st).await {
        Ok(k) => k,
        Err(e) => {
            {
                eprintln!("[demo] demo key: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "demo key unavailable").into_response();
            }
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
pub(crate) async fn demo_widget_credentials(st: &AppState) -> Result<(String, String), String> {
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
        "ratelimitDuration": null, "corsOrigins": ["*"],
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
pub(crate) async fn filter_request(st: &AppState, cfg: &KeyConfig, headers: &HeaderMap, site_key: &str) -> Option<Response> {
    let global = match st.cache.setting_optional(&st.kv, "settings:filtering").await
        .and_then(|v| crate::cache::effective_filtering(v.as_ref(), cfg)) {
        Ok(global) => global,
        Err(_) => return Some((StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "store_unavailable"}))).into_response()),
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
            Json(json!({"error": "filtered", "reason": "Request does not look like a real browser"})),
        )
            .into_response(),
    )
}
