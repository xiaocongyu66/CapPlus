//! `POST /:siteKey/siteverify` (Turnstile-compatible), `/validate` and the
//! `/turnstile/v0/siteverify` alias.

use super::*;

pub(crate) async fn verify_common(
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

pub(crate) async fn siteverify(
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

pub(crate) async fn siteverify_alias(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    verify_common(&st, &headers, &body, None, true).await
}

pub(crate) async fn validate(
    State(st): State<AppState>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    verify_common(&st, &headers, &body, Some(&site_key), false).await
}
