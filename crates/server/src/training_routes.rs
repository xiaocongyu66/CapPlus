//! Session-only, bounded management of the local observation store.
use crate::{
    AppState,
    training::{Error, SiteConfig},
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Deserialize;
use serde_json::json;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/server/keys/:siteKey/training/:operation", any(handle))
        .layer(axum::middleware::from_fn(no_store))
}

async fn no_store(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn failure(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"success": false, "error": message}))).into_response()
}

pub(crate) fn service_error(error: Error) -> Response {
    let (status, message) = match error {
        Error::InvalidSite | Error::InvalidConfig | Error::InvalidLimit => (
            StatusCode::BAD_REQUEST,
            "Invalid training configuration, site or page limit",
        ),
        Error::InvalidCursor => (
            StatusCode::BAD_REQUEST,
            "Invalid or expired cursor; restart pagination for this site",
        ),
        Error::Capacity => (
            StatusCode::CONFLICT,
            "Local training site/history or tombstone capacity exhausted (at most 64 active sites); history is not automatically discarded",
        ),
        Error::Deleted => (
            StatusCode::CONFLICT,
            "Site is permanently tombstoned; collection cannot be enabled",
        ),
        Error::Busy => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Training control queue is full; retry later",
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Local training storage unavailable; operation outcome may be unknown. Refresh status before retrying",
        ),
    };
    failure(status, message)
}

/// One session authentication followed by an uncached authoritative existence check.
/// Cookies and query parameters are never used as credentials.
pub(crate) async fn authorize(
    st: &AppState,
    headers: &HeaderMap,
    site: &str,
) -> Result<(), Response> {
    if st.admin_cfg.demo {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "Training management is unavailable in demo mode",
        ));
    }
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1
        || !headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("Bearer ") && !v[7..].trim().is_empty())
    {
        return Err(failure(
            StatusCode::UNAUTHORIZED,
            "An administrator Bearer session is required",
        ));
    }
    crate::admin_routes::require_admin(st, headers).await?;
    let admin = st
        .admin
        .as_ref()
        .expect("require_admin checked admin store");
    match admin.kv_exists(&format!("key:{site}")).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(failure(StatusCode::NOT_FOUND, "Site not found")),
        Err(_) => Err(failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Site storage unavailable",
        )),
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn handle(
    State(st): State<AppState>,
    Path((site, operation)): Path<(String, String)>,
    req: Request,
) -> Response {
    // HEAD must not implicitly execute GET, authenticate or enqueue a control.
    let method = req.method().clone();
    if method == Method::HEAD {
        return failure(StatusCode::METHOD_NOT_ALLOWED, "HEAD is not supported");
    }
    if let Err(response) = authorize(&st, req.headers(), &site).await {
        return response;
    }
    let Some(service) = st.training.as_ref() else {
        return service_error(Error::Unavailable);
    };
    let query = req.uri().query().unwrap_or("");
    if operation != "export" && !query.is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "Query parameters are not supported",
        );
    }
    let result = match (operation.as_str(), method) {
        ("config", Method::GET) => service.status(&site).await.map(|s| json!(s.config)),
        ("status", Method::GET) => service.status(&site).await.map(|s| json!(s)),
        ("config", Method::PUT) => {
            let bytes = match to_bytes(req.into_body(), 4096).await {
                Ok(bytes) => bytes,
                Err(_) => {
                    return failure(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Training config body must be at most 4 KiB",
                    );
                }
            };
            let config: SiteConfig = match serde_json::from_slice(&bytes) {
                Ok(config) => config,
                Err(_) => return failure(StatusCode::BAD_REQUEST, "Invalid training config JSON"),
            };
            service
                .configure(&site, config.clone())
                .await
                .map(|()| json!(config))
        }
        ("export", Method::GET) => {
            let params = match axum::extract::Query::<ExportQuery>::try_from_uri(req.uri()) {
                Ok(params) => params.0,
                Err(_) => return failure(StatusCode::BAD_REQUEST, "Invalid export query"),
            };
            service
                .export_page(&site, params.cursor, params.limit.unwrap_or(128))
                .await
                .map(|p| json!(p))
        }
        ("data", Method::DELETE) => service
            .delete(&site)
            .await
            .map(|epoch| json!({"epoch": epoch})),
        ("config" | "status" | "export" | "data", _) => {
            return failure(StatusCode::METHOD_NOT_ALLOWED, "Method not supported");
        }
        _ => return failure(StatusCode::NOT_FOUND, "Training endpoint not found"),
    };
    match result {
        Ok(value) => Json(json!({"success": true, "data": value})).into_response(),
        Err(error) => service_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use http_body_util::{BodyExt, Full};
    use hyper_util::{client::legacy::Client, rt::TokioExecutor};
    use std::sync::Arc;

    /// Explicitly opt in to a disposable Redis on a non-default loopback port.
    /// Never reads REDIS_URL, uses a default backend, or issues FLUSHDB.
    #[tokio::test]
    #[ignore = "requires CAP_TRAINING_TEST_REDIS_URL and CAP_TRAINING_TEST_ISOLATED=YES"]
    async fn isolated_management_http() {
        assert_eq!(
            std::env::var("CAP_TRAINING_TEST_ISOLATED").as_deref(),
            Ok("YES")
        );
        let redis = std::env::var("CAP_TRAINING_TEST_REDIS_URL")
            .expect("explicit disposable Redis URL required");
        let address = redis
            .strip_prefix("redis://127.0.0.1:")
            .expect("loopback Redis only");
        let (port, db) = address.split_once('/').expect("explicit database required");
        let port: u16 = port.parse().unwrap();
        assert!(port > 1024 && port != 6379 && port != 8401);
        assert_eq!(db, "15", "test database 15 required");
        cap_kv::cpu::init(cap_kv::cpu::CpuConfig::default()).unwrap();
        let kv = cap_kv::Kv::connect_redis(&redis).await.unwrap();
        let root = std::env::temp_dir().join(format!(
            "cap-training-routes-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let _ = crate::SETTINGS.set(crate::config::Settings {
            data_dir: root.clone(), hostname: "127.0.0.1".into(), port: 0,
            ip_header: String::new(), rsw_bits: 2048, admin_key: String::new(),
            demo: false, demo_allowed_domains: None, redis_url: redis.clone(), dashboard_dir: None,
            cdn_fallback: false, cache_host: String::new(), widget_version: String::new(),
            wasm_version: String::new(), embed_widget_url: String::new(),
            trust_proxy: false, proxy_secret: String::new(), require_network_fingerprint: false,
            trusted_proxy_cidrs: vec![], trusted_peer_cidrs: vec![], require_verify_session: false,
        });
        let admin = cap_admin::AdminStore::new(kv.clone());
        let cfg = cap_admin::AdminConfig {
            admin_key: format!("test-{}", rand::random::<u64>()),
            demo: false,
        };
        let body = json!({"admin_key": cfg.admin_key}).to_string();
        let login = cap_admin::handle(
            &admin,
            &cfg,
            &cap_admin::AdminRequest {
                method: "POST",
                path: "/auth/login",
                query: "",
                headers: &[],
                body: body.as_bytes(),
                peer: "training-route-test",
            },
        )
        .await;
        assert_eq!(login.status, 200);
        assert_eq!(login.body["success"], true);
        let bearer = format!(
            "Bearer {}",
            base64::engine::general_purpose::STANDARD.encode(
                json!({"token": login.body["session_token"], "hash": login.body["hashed_token"]})
                    .to_string()
            )
        );
        let site = format!("route-test-{}", rand::random::<u64>());
        kv.set(&format!("key:{site}"), "training test")
            .await
            .unwrap();
        let training = crate::training::TrainingService::open(root.join("training")).unwrap();
        let state = AppState {
            store: cap_store::Store::new(kv.clone()),
            embed_widget_url: String::new(),
            admin: Some(admin),
            admin_cfg: Arc::new(cfg),
            releases: Arc::new(cap_assets::ReleaseStore::open(&root).unwrap()),
            ipdb: Arc::new(cap_ipdb::IpDb::open(&root.join("ipdb"), &root.join("tmp")).unwrap()),
            kv: kv.clone(),
            cache: Arc::new(crate::cache::ConfigCache::new()),
            limiter: Arc::new(crate::ratelimit::LocalLimiter::new()),
            metrics: Arc::new(crate::metrics_buf::MetricsBuffer::new()),
            training: Some(training.clone()),
            redis_ratelimit: false,
            rsw_minters: moka::future::Cache::new(32),
            rsw_keygen: Default::default(),
        };
        // Real router checks include no-store even for rejected methods/auth.
        // Merge the admin wildcard too: more-specific training routes must win.
        let app = router()
            .route("/server/*rest", any(crate::admin_handler))
            .layer(axum::middleware::from_fn(crate::cors_layer))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
        });
        struct Stop(tokio::task::JoinHandle<()>);
        impl Drop for Stop {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _server = Stop(server);
        let client: Client<_, Full<bytes::Bytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let send = |method: &'static str, suffix: String, auth: Option<String>, body: String| {
            let client = client.clone();
            let uri = format!("http://{addr}/server/keys/{site}/training/{suffix}");
            async move {
                let mut req = hyper::Request::builder().method(method).uri(uri);
                if let Some(auth) = auth {
                    req = req.header(header::AUTHORIZATION, auth);
                }
                let response = client
                    .request(req.body(Full::new(bytes::Bytes::from(body))).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
                let code = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    code,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                )
            }
        };
        for suffix in ["status", "status/", "/status"] {
            assert_eq!(send("OPTIONS", suffix.into(), None, String::new()).await.0,
                StatusCode::METHOD_NOT_ALLOWED);
        }
        for operation in ["config", "status", "export", "data"] {
            assert_eq!(
                send("HEAD", operation.into(), None, String::new()).await.0,
                StatusCode::METHOD_NOT_ALLOWED
            );
        }
        for auth in [
            None,
            Some("Bot readonly_key".into()),
            Some("Bearer broken".into()),
        ] {
            assert_eq!(
                send("GET", "status".into(), auth, String::new()).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            send(
                "GET",
                "export?token=not-a-bearer-session".into(),
                None,
                String::new()
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let mut cookie = HeaderMap::new();
        cookie.insert(
            header::COOKIE,
            HeaderValue::from_static("cap_authed=not-a-session"),
        );
        assert_eq!(
            authorize(&state, &cookie, &site)
                .await
                .unwrap_err()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let mut demo = state.clone();
        Arc::make_mut(&mut demo.admin_cfg).demo = true;
        assert_eq!(
            authorize(&demo, &HeaderMap::new(), &site)
                .await
                .unwrap_err()
                .status(),
            StatusCode::FORBIDDEN
        );
        let (_, initial) = send("GET", "config".into(), Some(bearer.clone()), String::new()).await;
        assert_eq!(initial["data"]["enabled"], false);
        assert_eq!(initial["data"]["sample_rate_ppm"], 10000);
        assert_eq!(
            send(
                "PUT",
                "config".into(),
                Some(bearer.clone()),
                " ".repeat(4097)
            )
            .await
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            send("PUT", "config".into(), Some(bearer.clone()), "{}".into())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let config = SiteConfig {
            enabled: true,
            sample_rate_ppm: 1_000_000,
            ..SiteConfig::default()
        };
        assert_eq!(
            send(
                "PUT",
                "config".into(),
                Some(bearer.clone()),
                serde_json::to_string(&config).unwrap()
            )
            .await
            .0,
            StatusCode::OK
        );
        let (_, before) = send("GET", "status".into(), Some(bearer.clone()), String::new()).await;
        assert_eq!(before["data"]["config"]["enabled"], true);
        // Anonymous and Bot generic site deletion must not tombstone or disable.
        for authorization in [None, Some("Bot readonly_key")] {
            let mut headers = HeaderMap::new();
            if let Some(value) = authorization {
                headers.insert(header::AUTHORIZATION, value.parse().unwrap());
            }
            let response = crate::admin_handler(
                State(state.clone()),
                axum::extract::ConnectInfo("127.0.0.1:12345".parse().unwrap()),
                Method::DELETE,
                format!("/server/keys//{site}/").parse().unwrap(),
                headers,
                bytes::Bytes::new(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let status = training.status(&site).await.unwrap();
            assert!(status.config.enabled);
            assert!(!status.tombstoned);
        }
        // Obtain a real cursor, then verify strict site and epoch binding.
        for _ in 0..3 {
            assert_eq!(
                training.try_record(
                    &site,
                    crate::training::Sample::new(
                        crate::training::Decision::Allow,
                        crate::training::ReasonId::ProofValid,
                        1,
                        0,
                        true,
                    )
                ),
                crate::training::RecordOutcome::Queued
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if training.status(&site).await.unwrap().written >= 3 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let (_, first_page) = send(
            "GET",
            "export?limit=1".into(),
            Some(bearer.clone()),
            String::new(),
        )
        .await;
        let cursor = first_page["data"]["next_cursor"]
            .as_str()
            .expect("real next page cursor");
        let other = format!("{site}-other");
        kv.set(&format!("key:{other}"), "training test")
            .await
            .unwrap();
        training.configure(&other, config.clone()).await.unwrap();
        let response = handle(
            State(state.clone()),
            Path((other.clone(), "export".into())),
            Request::builder()
                .uri(format!(
                    "/server/keys/{other}/training/export?limit=1&cursor={cursor}"
                ))
                .header(header::AUTHORIZATION, bearer.clone())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        kv.del(&format!("key:{other}")).await.unwrap();
        assert_eq!(
            send(
                "GET",
                "export?limit=129".into(),
                Some(bearer.clone()),
                String::new()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                "GET",
                "export?cursor=bad".into(),
                Some(bearer.clone()),
                String::new()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(
                "GET",
                "export?token=credential".into(),
                Some(bearer.clone()),
                String::new()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (_, page) = send(
            "GET",
            "export?limit=128".into(),
            Some(bearer.clone()),
            String::new(),
        )
        .await;
        assert!(page["data"]["samples"].as_array().unwrap().len() <= 128);
        assert_eq!(
            send("DELETE", "data".into(), Some(bearer.clone()), String::new())
                .await
                .0,
            StatusCode::OK
        );
        let (_, after) = send("GET", "status".into(), Some(bearer.clone()), String::new()).await;
        assert_eq!(after["data"]["config"], before["data"]["config"]);
        assert_eq!(
            send(
                "GET",
                format!("export?limit=1&cursor={cursor}"),
                Some(bearer.clone()),
                String::new()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert!(
            after["data"]["epoch"].as_u64().unwrap() > before["data"]["epoch"].as_u64().unwrap()
        );
        kv.del(&format!("key:{site}")).await.unwrap();
        assert_eq!(
            send("GET", "status".into(), Some(bearer.clone()), String::new())
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let mut unavailable = state.clone();
        unavailable.training = None;
        kv.set(&format!("key:{site}"), "training test")
            .await
            .unwrap();
        let response = handle(
            State(unavailable),
            Path((site.clone(), "status".into())),
            Request::builder()
                .header(header::AUTHORIZATION, bearer)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        // Exercise deletion through the real HTTP admin + CORS stack.
        let delete = |target: String, credential: String| {
            let client = client.clone();
            async move {
                let request = hyper::Request::builder().method("DELETE")
                    .uri(format!("http://{addr}/server/keys/{target}"))
                    .header(header::AUTHORIZATION, credential)
                    .body(Full::new(bytes::Bytes::new())).unwrap();
                let response = client.request(request).await.unwrap();
                let code = response.status();
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                (code, serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
            }
        };
        let session = format!("Bearer {}", base64::engine::general_purpose::STANDARD.encode(
            json!({"token": login.body["session_token"], "hash": login.body["hashed_token"]}).to_string()));
        for (kind, allowed) in [("readonly", false), ("cross", false), ("scoped", true), ("global", true)] {
            let target = format!("{site}-{kind}");
            kv.set(&format!("key:{target}"), "test").await.unwrap();
            let id = format!("{site}-{kind}");
            let name = format!("apikey:{id}");
            kv.hset_pairs(&name, &[("tokenHash", login.body["hashed_token"].as_str().unwrap().to_owned())]).await.unwrap();
            if kind != "global" {
                kv.hset_pairs(&name, &[("siteKeys", json!([if kind == "cross" { "elsewhere" } else { &target }]).to_string())]).await.unwrap();
            }
            if kind == "readonly" {
                kv.hset_pairs(&name, &[("readonly", "true".into())]).await.unwrap();
            }
            let credential = format!("Bot {id}_{}", login.body["session_token"].as_str().unwrap());
            let (code, result) = delete(target.clone(), credential.clone()).await;
            assert_eq!(code, if allowed { StatusCode::OK } else { StatusCode::FORBIDDEN });
            if allowed {
                assert_eq!(result["deletion"]["state"], "complete");
                assert!(training.status(&target).await.unwrap().tombstoned);
                assert_eq!(delete(target.clone(), credential).await.0, StatusCode::OK);
            } else {
                assert!(!kv.exists(&format!("site-delete:{target}")).await.unwrap());
                assert!(!training.status(&target).await.unwrap().tombstoned);
            }
            kv.del(&name).await.unwrap();
        }
        // Wrong-type index fails before DEL, after local retirement. Repair and
        // retry even after simulating a lost DEL reply / missing primary key.
        let index = format!("shares:{site}");
        kv.set(&index, "wrong type").await.unwrap();
        let cache_probe = format!("{site}:cache-probe");
        kv.set(&cache_probe, "{\"revision\":1}").await.unwrap();
        assert_eq!(state.cache.setting(&kv, &cache_probe).await["revision"], 1);
        kv.set(&cache_probe, "{\"revision\":2}").await.unwrap();
        let (code, result) = delete(site.clone(), session.clone()).await;
        assert_eq!(state.cache.setting(&kv, &cache_probe).await["revision"], 2);
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(result["deletion"]["training"], "committed");
        assert!(kv.exists(&format!("key:{site}")).await.unwrap());
        assert!(training.status(&site).await.unwrap().tombstoned);
        kv.del(&index).await.unwrap();
        kv.del(&format!("key:{site}")).await.unwrap();
        kv.sadd("keys", &site).await.unwrap();
        let share = format!("{site}-share");
        kv.sadd(&index, &share).await.unwrap();
        kv.sadd("shares", &share).await.unwrap();
        kv.set(&format!("share:{share}"), "test").await.unwrap();
        assert_eq!(delete(site.clone(), session.clone()).await.0, StatusCode::OK);
        assert!(!kv.smembers("keys").await.unwrap().contains(&site));
        assert!(!kv.smembers("shares").await.unwrap().contains(&share));
        assert!(!kv.exists(&format!("share:{share}")).await.unwrap());
        let absent = format!("{site}-absent");
        assert_eq!(delete(absent.clone(), session.clone()).await.0, StatusCode::NOT_FOUND);
        assert!(!training.status(&absent).await.unwrap().tombstoned);
        // Revocation after the single authorization cannot trigger a second
        // Argon/session lookup between irreversible local and Redis commits.
        let target = format!("{site}-authorized");
        kv.set(&format!("key:{target}"), "test").await.unwrap();
        let headers = vec![("Authorization".into(), session)];
        let path = format!("/keys/{target}");
        let request = cap_admin::AdminRequest {
            method: "DELETE", path: &path, query: "", headers: &headers,
            body: b"", peer: "training-route-test",
        };
        let authorized = match cap_admin::authorize_site_delete(state.admin.as_ref().unwrap(), &request).await {
            Ok(value) => value,
            Err(_) => panic!("valid session must authorize"),
        };
        let hash = login.body["hashed_token"].as_str().unwrap();
        kv.del(&format!("session:{hash}")).await.unwrap();
        assert!(authorized.prepare().await.is_ok());
        training.delete_site(&target).await.unwrap();
        assert_eq!(authorized.finish().await.status, 200);
        kv.srem("sessions", hash).await.unwrap();
    }
}
