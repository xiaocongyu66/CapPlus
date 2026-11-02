//! `POST /:siteKey/siteverify` (Turnstile-compatible), `/validate` and the
//! `/turnstile/v0/siteverify` alias.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cap_core::SessionBind;
use cap_store::now_ms;
use cap_verify::{
    bind_inputs, check_secret, err_response, ok_response, parse_body, parse_request,
    token_site_key, ErrorCode, SecretCheck,
};
use serde_json::json;

use crate::http_util::{client_ip, header_str};
use crate::{rate_allowed, AppState};

pub(crate) async fn verify_common(
    st: &AppState,
    headers: &HeaderMap,
    body: &Bytes,
    path_site_key: Option<&str>,
) -> Response {
    let content_type = header_str(headers, "content-type");
    let Ok(raw) = std::str::from_utf8(body) else {
        return (StatusCode::BAD_REQUEST, Json(err_response(ErrorCode::BadRequest, "Invalid UTF-8"))).into_response();
    };
    let Some(map) = parse_body(&content_type, raw) else {
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

    let key = match st.cache.key_checked(&st.store, &site_key).await {
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(err_response(ErrorCode::BadRequest, "Temporarily unavailable"))).into_response(),
        Ok(Some(k)) => Arc::unwrap_or_clone(k),
        Ok(None) => {
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

    // Legacy `$argon2` hashes cost tens of ms; keep them off async workers.
    let secret_check = if key.secret_hash.starts_with("$argon2") {
        if cap_verify::validate_argon2_phc(&key.secret_hash).is_err() {
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"success": false, "error": "internal_error"}))).into_response();
        }
        let (stored, provided) = (key.secret_hash.clone(), req.secret.clone());
        match cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::Argon,
            move || cap_verify::verify_argon2(&provided, &stored)).await {
            Ok(Ok(result)) => SecretCheck::Fast(result),
            Ok(Err(_)) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"success": false, "error": "internal_error"})),
            ).into_response(),
            Err(cap_kv::cpu::CpuError::Busy) => return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"success": false, "error": "server_busy"})),
            ).into_response(),
            Err(_) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"success": false, "error": "internal_error"})),
            ).into_response(),
        }
    } else {
        check_secret(&key.secret_hash, &req.secret)
    };
    match secret_check {
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

    let binding = cap_core::business::BusinessBinding {
        site: site_key.clone(), session: req.session.clone(), action: req.action.clone(),
        nonce: req.nonce.clone(), request_digest: req.request_digest.clone(),
    };
    let state = match st.store.business_token_state(&binding, &req.response).await {
        Ok(state) => state,
        Err(error) => return business_verify_error(error),
    };
    let bind = match serde_json::from_str::<SessionBind>(&state.bind_json) {
        Ok(bind) => Some(bind),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(err_response(ErrorCode::BadRequest, "Temporarily unavailable"))).into_response(),
    };
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

    // A burned token must report "duplicate", not "not verified" — same
    // ordering as the JS implementation.
    let duplicate = || {
        (
            StatusCode::OK,
            Json(err_response(
                ErrorCode::TimeoutOrDuplicate,
                "The response has already been redeemed or has expired.",
            )),
        )
            .into_response()
    };
    if state.expires_ms <= now_ms() { return duplicate(); }
    // Pass the exact snapshot checked above; never reserialize it for CAS.
    if let Err(error) = st.store.consume_business(&binding, &req.response, &state.bind_json).await {
        return business_verify_error(error);
    }

    let ts = bind.as_ref().map(|b| b.ts).unwrap_or_else(now_ms);
    // Caller-provided hostname is only a comparison input, never provenance.
    let hostname = bound_hostname(bind.as_ref());
    (StatusCode::OK, [("cache-control", "no-store")], Json(ok_response(ts, hostname))).into_response()
}

fn business_verify_error(error: cap_store::BusinessStoreError) -> Response {
    use cap_store::BusinessStoreError::*;
    let (status, code, message) = match error {
        Storage(_) | Busy => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::BadRequest, "Temporarily unavailable"),
        Expired | Used => (StatusCode::OK, ErrorCode::TimeoutOrDuplicate, "The response has already been redeemed or has expired."),
        Mismatch | Conflict => (StatusCode::OK, ErrorCode::InvalidInputResponse, "Business or session mismatch"),
        Invalid => (StatusCode::OK, ErrorCode::InvalidInputResponse, "Invalid business response"),
    };
    (status, Json(err_response(code, message))).into_response()
}

fn bound_hostname(bind: Option<&SessionBind>) -> &str {
    bind.and_then(|b| b.host.as_deref()).unwrap_or_default()
}

#[cfg(test)]
mod hostname_tests {
    use super::*;

    #[tokio::test]
    async fn business_error_semantics_fail_closed() {
        use cap_store::BusinessStoreError::*;
        for (error, status, code) in [
            (Storage(cap_kv::KvError("private diagnostic".into())), StatusCode::SERVICE_UNAVAILABLE, "bad-request"),
            (Busy, StatusCode::SERVICE_UNAVAILABLE, "bad-request"),
            (Expired, StatusCode::OK, "timeout-or-duplicate"),
            (Used, StatusCode::OK, "timeout-or-duplicate"),
            (Mismatch, StatusCode::OK, "invalid-input-response"),
        ] {
            let response = business_verify_error(error);
            assert_eq!(response.status(), status);
            let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["success"], false);
            assert_eq!(value["error-codes"][0], code);
            assert!(!String::from_utf8_lossy(&body).contains("private diagnostic"));
        }
    }

    #[test]
    fn response_hostname_uses_only_server_binding() {
        let mut bind = SessionBind::new(None, "UA", 1);
        assert_eq!(ok_response(1, bound_hostname(None))["hostname"], "");
        assert_eq!(ok_response(1, bound_hostname(Some(&bind)))["hostname"], "");
        bind.host = Some("app.example".into());
        assert_eq!(ok_response(1, bound_hostname(Some(&bind)))["hostname"], "app.example");
        // A caller cannot replace the output hostname, even in non-strict mode.
        assert!(!bind.matches(false, "", "UA", "forged.example"));
        assert!(bind.matches(false, "", "UA", ""));
        assert_eq!(bound_hostname(Some(&bind)), "app.example");
    }
}

pub(crate) fn error_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::MissingInputSecret => "The secret parameter is missing.",
        ErrorCode::InvalidInputSecret => "The secret parameter is invalid or malformed.",
        ErrorCode::MissingInputResponse => "The response parameter is missing.",
        ErrorCode::InvalidInputResponse => "The response parameter is invalid or malformed.",
        ErrorCode::TimeoutOrDuplicate => "The response has already been redeemed or has expired.",
        ErrorCode::BadRequest => "The request is invalid or malformed.",
    }
}

/// 300 verifications per 10 s per IP and site key (matches siteverify.js).
/// Applied to every verification entry point: each one checks a secret.
async fn verify_limited(st: &AppState, headers: &HeaderMap, addr: &SocketAddr, scope: &str) -> Option<Response> {
    let ip = client_ip(headers, &addr.ip().to_string());
    if rate_allowed(st, &format!("siteverify:{scope}"), &ip, 10_000, 300).await {
        return None;
    }
    Some(
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(err_response(ErrorCode::BadRequest, "Rate limit exceeded")),
        )
            .into_response(),
    )
}

pub(crate) async fn siteverify(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !cap_embed::validate_site_key(&site_key) {
        return (
            StatusCode::OK,
            axum::Json(json!({"success": false, "error-codes": ["invalid-input-response"]})),
        )
            .into_response();
    }
    if let Some(r) = verify_limited(&st, &headers, &addr, &site_key).await {
        return r;
    }
    verify_common(&st, &headers, &body, Some(&site_key)).await
}

pub(crate) async fn siteverify_alias(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = verify_limited(&st, &headers, &addr, "_turnstile").await {
        return r;
    }
    verify_common(&st, &headers, &body, None).await
}

pub(crate) async fn validate(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(r) = verify_limited(&st, &headers, &addr, &site_key).await {
        return r;
    }
    verify_common(&st, &headers, &body, Some(&site_key)).await
}
