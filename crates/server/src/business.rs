//! Backend-only business credential issuance. Credentials never belong in URLs.
use crate::{
    AppState,
    http_util::{client_ip, header_str},
    rate_allowed,
};
use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cap_core::business::{
    BusinessBinding, BusinessClaims, sign_business_token, verify_business_token,
};
use cap_store::{BusinessStoreError, now_ms};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueRequest {
    secret: String,
    session: String,
    action: String,
    nonce: String,
    request_digest: String,
}

pub(crate) fn failure(status: StatusCode, error: &str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(json!({"success": false, "error": error})),
    )
        .into_response()
}

pub(crate) fn store_failure(error: BusinessStoreError) -> Response {
    let (status, code) = match error {
        BusinessStoreError::Storage(_) => (StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
        BusinessStoreError::Busy => (StatusCode::SERVICE_UNAVAILABLE, "server_busy"),
        BusinessStoreError::Conflict => (StatusCode::CONFLICT, "business_conflict"),
        BusinessStoreError::Mismatch => (StatusCode::BAD_REQUEST, "business_mismatch"),
        BusinessStoreError::Expired => (StatusCode::BAD_REQUEST, "business_expired"),
        BusinessStoreError::Used => (StatusCode::CONFLICT, "business_used"),
        BusinessStoreError::Invalid => (StatusCode::BAD_REQUEST, "invalid_business_token"),
    };
    failure(status, code)
}

pub(crate) async fn authenticate(stored: &str, provided: &str) -> Result<(), Box<Response>> {
    let valid = if stored.starts_with("$argon2") {
        if cap_verify::validate_argon2_phc(stored).is_err() {
            return Err(Box::new(failure(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")));
        }
        let (stored, provided) = (stored.to_owned(), provided.to_owned());
        match cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::Argon, move || {
            cap_verify::verify_argon2(&provided, &stored)
        })
        .await
        {
            Ok(Ok(valid)) => valid,
            Err(cap_kv::cpu::CpuError::Busy) => {
                return Err(Box::new(failure(StatusCode::SERVICE_UNAVAILABLE, "server_busy")));
            }
            _ => return Err(Box::new(failure(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))),
        }
    } else {
        matches!(
            cap_verify::check_secret(stored, provided),
            cap_verify::SecretCheck::Fast(true)
        )
    };
    if valid {
        Ok(())
    } else {
        Err(Box::new(failure(StatusCode::UNAUTHORIZED, "invalid_secret")))
    }
}

pub(crate) async fn checked_credential(
    st: &AppState,
    site: &str,
    secret: &str,
    token: &str,
) -> Result<BusinessClaims, Box<Response>> {
    let claims = verify_business_token(token, secret, now_ms())
        .map_err(|_| Box::new(failure(StatusCode::BAD_REQUEST, "invalid_business_token")))?;
    if claims.binding.site != site {
        return Err(Box::new(failure(StatusCode::BAD_REQUEST, "business_mismatch")));
    }
    st.store
        .check_business(&claims, token)
        .await
        .map_err(|error| Box::new(store_failure(error)))?;
    Ok(claims)
}

fn parse_issue(body: &[u8], site: &str) -> Result<(String, BusinessBinding), ()> {
    if body.len() > 16 * 1024 {
        return Err(());
    }
    let req: IssueRequest = serde_json::from_slice(body).map_err(|_| ())?;
    if req.secret.is_empty() || req.secret.len() > 1024 {
        return Err(());
    }
    let binding = BusinessBinding {
        site: site.into(),
        session: req.session,
        action: req.action,
        nonce: req.nonce,
        request_digest: req.request_digest,
    };
    binding.validate().map_err(|_| ())?;
    Ok((req.secret, binding))
}

pub(crate) async fn issue(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&headers, &addr.ip().to_string());
    if !rate_allowed(&st, "business-credential:preauth", &ip, 10_000, 300).await {
        return failure(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    if !cap_embed::validate_site_key(&site) {
        return failure(StatusCode::NOT_FOUND, "invalid_site");
    }
    let key = match st.cache.key_checked(&st.store, &site).await {
        Ok(Some(key)) => key,
        Ok(None) => return failure(StatusCode::NOT_FOUND, "invalid_site"),
        Err(_) => return failure(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
    };
    if !rate_allowed(
        &st,
        &format!("business-credential:{site}"),
        &ip,
        10_000,
        300,
    )
    .await
    {
        return failure(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    if !header_str(&headers, "content-type")
        .split(';')
        .next()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"))
    {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }
    let Ok((secret, binding)) = parse_issue(&body, &site) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if let Err(response) = authenticate(&key.secret_hash, &secret).await {
        return *response;
    }
    let now = now_ms();
    let Ok(token) = sign_business_token(binding, &key.jwt_secret, now, None) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Ok(claims) = verify_business_token(&token, &key.jwt_secret, now) else {
        return failure(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
    };
    match st.store.issue_business(&claims, &token).await {
        Ok(issued) => (
            StatusCode::OK,
            [("cache-control", "no-store")],
            Json(json!({"businessToken": issued.token, "expires": issued.claims.exp})),
        )
            .into_response(),
        Err(error) => store_failure(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // A real TCP HTTP fixture for business binding/consumption, NOT a PoW or
    // browser success fixture. Result preparation explicitly uses Store's API.
    #[tokio::test]
    #[ignore = "requires dedicated temporary Redis, matching dual URLs and CAPPRO_DIR"]
    async fn isolated_http_business_binding() {
        use std::sync::Arc;
        use axum::{Router, routing::post};
        use http_body_util::{BodyExt, Full};
        use hyper_util::{client::legacy::Client, rt::TokioExecutor};
        let url = std::env::var("CAP_TEST_REDIS_URL").expect("explicit isolated Redis");
        assert_eq!(std::env::var("REDIS_URL").unwrap(), url);
        let dir = std::path::PathBuf::from(std::env::var("CAPPRO_DIR").expect("isolated data directory"));
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("cap-business-http-"));
        let cfg = crate::config::init().unwrap();
        let _ = crate::SETTINGS.set(cfg);
        let kv = cap_kv::Kv::connect_redis(&url).await.unwrap();
        let store = cap_store::Store::new(kv.clone());
        let site = cap_core::random_hex(10);
        let secret = cap_core::random_hex(32);
        let jwt_secret = cap_core::random_hex(64);
        kv.hset_pairs(&format!("key:{site}"), &[
            ("jwtSecret", jwt_secret.clone()),
            ("secretHash", format!("sha256:{}", cap_core::sha256_hex(&secret))),
            ("config", json!({"corsOrigins":["https://app.example"], "requireSessionBind":true}).to_string()),
        ]).await.unwrap();
        let state = AppState {
            store: store.clone(), kv: kv.clone(), embed_widget_url: String::new(), admin: None,
            admin_cfg: Arc::new(cap_admin::AdminConfig { admin_key: String::new(), demo: false }),
            releases: Arc::new(cap_assets::ReleaseStore::open(&dir).unwrap()),
            ipdb: Arc::new(cap_ipdb::IpDb::open(&dir.join("ipdb"), &dir.join("tmp")).unwrap()),
            cache: Arc::new(crate::cache::ConfigCache::new()),
            limiter: Arc::new(crate::ratelimit::LocalLimiter::new()),
            metrics: Arc::new(crate::metrics_buf::MetricsBuffer::new()), training: None,
            redis_ratelimit: false, rsw_minters: moka::future::Cache::new(32), rsw_keygen: Default::default(),
        };
        let cache = state.cache.clone();
        let app = Router::new()
            .route("/:site/challenge", post(crate::challenge::challenge))
            .route("/:site/redeem", post(crate::redeem::redeem))
            .route("/:site/business-credential", post(issue).layer(axum::extract::DefaultBodyLimit::max(16384)))
            .route("/:site/siteverify", post(crate::siteverify::siteverify))
            .route("/:site/validate", post(crate::siteverify::validate))
            .route("/turnstile/v0/siteverify", post(crate::siteverify::siteverify_alias))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
        });
        struct Stop(tokio::task::JoinHandle<()>);
        impl Drop for Stop { fn drop(&mut self) { self.0.abort(); } }
        let _server = Stop(server);
        let client = Client::builder(TokioExecutor::new()).build_http::<Full<bytes::Bytes>>();
        let request = |path: String, body: serde_json::Value| {
            let client = client.clone();
            async move {
                let req = hyper::Request::post(format!("http://{addr}{path}"))
                    .header("content-type", "application/json")
                    .header("origin", format!("http://{addr}"))
                    .body(Full::new(bytes::Bytes::from(body.to_string()))).unwrap();
                let response = client.request(req).await.unwrap();
                let status = response.status();
                let headers = response.headers().clone();
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                (status, headers, value)
            }
        };
        let issue_path = format!("/{site}/business-credential");
        let body = json!({"secret":secret, "session":"backend-session", "action":"pay", "nonce":cap_core::random_hex(32), "requestDigest":"a".repeat(64)});
        // Cold-cache wrong Redis type and malformed persisted config are 503,
        // not an absent site or a bad caller secret, on every security handler.
        for broken_config in [false, true] {
            let broken = cap_core::random_hex(10);
            let key_name = format!("key:{broken}");
            if broken_config {
                kv.hset_pairs(&key_name, &[("jwtSecret", jwt_secret.clone()), ("config", "{broken".into())]).await.unwrap();
            } else {
                kv.set_ex(&key_name, "wrong Redis type", 60).await.unwrap();
            }
            for endpoint in ["business-credential", "challenge", "redeem", "siteverify", "validate"] {
                let mut input = body.clone();
                input["response"] = json!(format!("{broken}:id:token"));
                input["token"] = json!("challenge"); input["businessToken"] = json!("credential"); input["solutions"] = json!([]);
                let (status, _, response) = request(format!("/{broken}/{endpoint}"), input).await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{endpoint} config={broken_config}: {response}");
                assert!(!response.to_string().contains("WRONGTYPE"));
                assert!(!response.to_string().contains("{broken"));
            }
            // Fix immediately without TTL wait: errors must not be cached None.
            kv.del(&key_name).await.unwrap();
            kv.hset_pairs(&key_name, &[("jwtSecret", jwt_secret.clone()), ("secretHash", format!("sha256:{}", cap_core::sha256_hex(&secret)))]).await.unwrap();
            assert_eq!(request(format!("/{broken}/business-credential"), body.clone()).await.0, StatusCode::OK);
            let first = cache.key_checked(&store, &broken).await.unwrap().unwrap();
            let second = cache.key_checked(&store, &broken).await.unwrap().unwrap();
            assert!(Arc::ptr_eq(&first, &second));
            kv.del(&key_name).await.unwrap();
        }
        let absent = cap_core::random_hex(10);
        assert!(cache.key_checked(&store, &absent).await.unwrap().is_none());
        assert_eq!(request(format!("/{absent}/business-credential"), body.clone()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(request(format!("/{absent}/challenge"), json!({})).await.0, StatusCode::NOT_FOUND);
        assert_eq!(request(format!("/{absent}/redeem"), json!({"token":"c", "businessToken":"b", "solutions":[]})).await.0, StatusCode::NOT_FOUND);
        let mut absent_verify = body.clone(); absent_verify["response"] = json!(format!("{absent}:id:token"));
        let (status, _, response) = request(format!("/{absent}/siteverify"), absent_verify).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["error-codes"][0], "invalid-input-secret");
        let mut bad = body.clone(); bad["secret"] = json!("wrong");
        assert_eq!(request(issue_path.clone(), bad).await.0, StatusCode::UNAUTHORIZED);
        let mut missing = body.clone(); missing.as_object_mut().unwrap().remove("secret");
        assert_eq!(request(format!("{issue_path}?secret={secret}"), missing).await.0, StatusCode::BAD_REQUEST);
        let (status, headers, issued) = request(issue_path.clone(), body.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(request(issue_path.clone(), body.clone()).await.2, issued);
        let mut conflict = body.clone(); conflict["action"] = json!("different");
        assert_eq!(request(issue_path, conflict).await.0, StatusCode::CONFLICT);
        let credential = issued["businessToken"].as_str().unwrap();
        let claims = verify_business_token(credential, &jwt_secret, now_ms()).unwrap();
        // Even correctly signed candidates cannot replace authoritative issuance.
        for field in ["site", "session", "action", "nonce", "requestDigest"] {
            let mut changed = serde_json::to_value(&claims).unwrap();
            changed["binding"][field] = if field == "requestDigest" { json!("b".repeat(64)) } else { json!("different") };
            let forged = cap_core::jwt_sign(&changed, &jwt_secret);
            let candidate = verify_business_token(&forged, &jwt_secret, now_ms()).unwrap();
            assert!(store.check_business(&candidate, &forged).await.is_err(), "{field}");
        }
        for (field, value) in [("typ", json!("chal")), ("v", json!(2)), ("iat", json!(now_ms() + 60000)), ("exp", json!(now_ms() - 1))] {
            let mut changed = serde_json::to_value(&claims).unwrap(); changed[field] = value;
            let forged = cap_core::jwt_sign(&changed, &jwt_secret);
            assert!(verify_business_token(&forged, &jwt_secret, now_ms()).is_err());
        }
        assert!(verify_business_token(&format!("{credential}x"), &jwt_secret, now_ms()).is_err());
        let result = format!("{site}:fixture:{}", cap_core::random_hex(30));
        let mut bind = cap_core::SessionBind::new(Some("192.0.2.1".into()), "fixture-UA", now_ms());
        bind.host = Some("app.example".into());
        store.complete_business(&claims, credential, cap_store::CompleteBusiness {
            challenge_nonce: &cap_core::random_hex(64), challenge_expires_ms: claims.exp,
            token: &result, bind_json: &bind.to_json(), token_ttl_ms: 60000,
        }).await.unwrap();
        let mut verify = body; verify["response"] = json!(result);
        verify["remoteip"] = json!("192.0.2.1"); verify["userAgent"] = json!("fixture-UA"); verify["hostname"] = json!("app.example");
        let path = format!("/{site}/siteverify");
        for (field, value) in [("session", "wrong"), ("action", "wrong"), ("nonce", "wrong"), ("requestDigest", &"b".repeat(64)), ("remoteip", "192.0.2.2"), ("userAgent", "wrong"), ("hostname", "wrong.example")] {
            let mut wrong = verify.clone(); wrong[field] = json!(value);
            assert_eq!(request(path.clone(), wrong).await.2["success"], false, "{field}");
            assert!(store.business_token_state(&claims.binding, &result).await.is_ok());
        }
        for field in ["session", "action", "nonce", "requestDigest"] {
            let mut missing = verify.clone(); missing.as_object_mut().unwrap().remove(field);
            assert_eq!(request(path.clone(), missing).await.2["success"], false);
        }
        assert_eq!(request(format!("/{}/siteverify", cap_core::random_hex(10)), verify.clone()).await.2["success"], false);
        assert_eq!(request(format!("/{site}/validate"), verify.clone()).await.2["success"], true);
        for path in [path, format!("/{site}/validate"), "/turnstile/v0/siteverify".into()] {
            let response = request(path, verify.clone()).await.2;
            assert_eq!(response["success"], false);
            assert_eq!(response["error-codes"][0], "timeout-or-duplicate");
        }
        // Dedicated Redis is destroyed by the harness; no FLUSHDB or inferred namespaces.
        kv.del(&format!("key:{site}")).await.unwrap();
    }

    #[test]
    fn strict_issue_body() {
        let valid = json!({"secret":"secret", "session":"session", "action":"pay", "nonce":"n", "requestDigest":"a".repeat(64)});
        assert!(parse_issue(&serde_json::to_vec(&valid).unwrap(), "site").is_ok());
        for field in ["secret", "session", "action", "nonce", "requestDigest"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(parse_issue(&serde_json::to_vec(&missing).unwrap(), "site").is_err());
            let mut wrong = valid.clone();
            wrong[field] = json!(42);
            assert!(parse_issue(&serde_json::to_vec(&wrong).unwrap(), "site").is_err());
        }
        for field in ["ttl", "site", "expires"] {
            let mut extra = valid.clone();
            extra[field] = json!(300000);
            assert!(parse_issue(&serde_json::to_vec(&extra).unwrap(), "site").is_err());
        }
        assert!(parse_issue(&vec![b' '; 16385], "site").is_err());
    }
}
