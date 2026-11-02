use super::*;
use axum::body::Body;
use base64::Engine;
use std::sync::Arc;

fn request(auth: Option<&str>, body: impl Into<Body>) -> Request {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/demo/verify")
        .header("content-type", "application/json")
        .header("user-agent", "demo-test");
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    builder.body(body.into()).unwrap()
}
async fn document(response: Response) -> Value {
    assert_eq!(response.headers()["cache-control"], "no-store");
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn strict_verify_and_no_secret_html() {
    for invalid in [
        r#"{"response":"a","handle":"b","site":"evil"}"#,
        r#"{"response":42,"handle":"b"}"#,
        r#"{"response":"a","handle":"b","handle":"c"}"#,
        r#"{"response":"a","response":"b","handle":"c"}"#,
        r#"{"response":"a"}"#,
    ] {
        assert!(serde_json::from_str::<DemoVerifyRequest>(invalid).is_err());
    }
    for html in [
        include_str!("../../../frontend/reputation.html"),
        include_str!("../../../frontend/demo.html"),
    ] {
        assert!(!html.contains("CAP_SECRET"));
        assert!(!html.contains("jwtSecret"));
        assert!(!html.contains("localStorage.setItem"));
        assert!(html.contains("/login"));
    }
}

#[tokio::test]
async fn bounded_body_and_context() {
    let response = demo_body(request(None, vec![b' '; DEMO_BODY_LIMIT + 1]))
        .await
        .unwrap_err();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let mut ctx = DemoContext {
        owner: "a".into(),
        expires: 2000,
        binding: BusinessBinding {
            site: "demo".into(),
            session: "opaque".into(),
            action: "demo-verification-receipt".into(),
            nonce: "nonce".into(),
            request_digest: demo_digest(),
        },
    };
    assert!(context_matches(&ctx, "a", 1000));
    assert!(!context_matches(&ctx, "b", 1000));
    assert!(!context_matches(&ctx, "a", 2000));
    ctx.binding.request_digest = "a".repeat(64);
    assert!(!context_matches(&ctx, "a", 1000));
}

/// Starts its OWN password-protected, persistence-disabled Redis child; never
/// connects to a default/shared Redis. Both opt-in variables are mandatory.
#[tokio::test]
#[ignore = "requires CAP_DEMO_TEST_ISOLATED=YES and CAP_DEMO_TEST_REDIS_URL on an unused loopback port, DB 15"]
async fn isolated_demo_authorization_and_binding() {
    assert_eq!(
        std::env::var("CAP_DEMO_TEST_ISOLATED").as_deref(),
        Ok("YES")
    );
    let redis = std::env::var("CAP_DEMO_TEST_REDIS_URL").expect("explicit Redis URL required");
    assert_eq!(
        std::env::var("REDIS_URL").as_deref(),
        Ok(redis.as_str()),
        "explicit REDIS_URL must match isolated test URL"
    );
    assert_eq!(
        std::env::var("CAP_TEST_REDIS_URL").as_deref(),
        Ok(redis.as_str()),
        "both explicit test URLs must identify the same DB"
    );
    let (port, db) = redis
        .strip_prefix("redis://127.0.0.1:")
        .unwrap()
        .split_once('/')
        .unwrap();
    let port: u16 = port.parse().unwrap();
    assert!(port > 1024 && port != 6379 && port != 8401);
    assert_eq!(db, "15");
    // Bind first to reject occupied/shared endpoints before spawning anything.
    let reservation = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let root = std::env::temp_dir().join(format!("cap-demo-test-{}", random_hex(24)));
    std::fs::create_dir(&root).unwrap();
    struct Cleanup {
        child: std::process::Child,
        root: std::path::PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
    let password = random_hex(48);
    drop(reservation);
    let child = std::process::Command::new("redis-server")
        .args([
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--save",
            "",
            "--appendonly",
            "no",
            "--requirepass",
            &password,
        ])
        .arg("--dir")
        .arg(&root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut cleanup = Cleanup {
        child,
        root: root.clone(),
    };
    let private_url = format!("redis://:{password}@127.0.0.1:{port}/15");
    let mut connected = None;
    for _ in 0..100 {
        assert!(
            cleanup.child.try_wait().unwrap().is_none(),
            "owned Redis failed to start"
        );
        if let Ok(kv) = cap_kv::Kv::connect_redis(&private_url).await {
            connected = Some(kv);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let kv = connected.expect("owned Redis ready");
    cap_kv::cpu::init(cap_kv::cpu::CpuConfig::default()).unwrap();
    crate::SETTINGS
        .set(crate::config::Settings {
            data_dir: root.clone(),
            hostname: "127.0.0.1".into(),
            demo_allowed_domains: Some(vec!["demo.example.test".into()]),
            port: 0,
            ip_header: String::new(),
            rsw_bits: 2048,
            admin_key: String::new(),
            demo: true,
            redis_url: private_url,
            dashboard_dir: None,
            cdn_fallback: false,
            cache_host: String::new(),
            widget_version: String::new(),
            wasm_version: String::new(),
            embed_widget_url: String::new(),
            trust_proxy: false,
            proxy_secret: String::new(),
            require_network_fingerprint: false,
            trusted_proxy_cidrs: vec![],
            trusted_peer_cidrs: vec![],
            require_verify_session: false,
        })
        .expect("run isolated demo test separately from other global-settings tests");
    let admin = cap_admin::AdminStore::new(kv.clone());
    let cfg = cap_admin::AdminConfig {
        admin_key: random_hex(32),
        demo: false,
    };
    let login_body = json!({"admin_key": cfg.admin_key}).to_string();
    let login_request = cap_admin::AdminRequest {
        method: "POST",
        path: "/auth/login",
        query: "",
        headers: &[],
        body: login_body.as_bytes(),
        peer: "demo-isolated-test",
    };
    let demo_login = cap_admin::handle(
        &admin,
        &cap_admin::AdminConfig {
            demo: true,
            ..cfg.clone()
        },
        &login_request,
    )
    .await;
    assert_eq!(demo_login.body["demo"], true);
    assert!(demo_login.body.get("session_token").is_none());
    let mut auths = Vec::new();
    for _ in 0..2 {
        let login = cap_admin::handle(&admin, &cfg, &login_request).await;
        assert_eq!(login.status, 200);
        auths.push(format!(
            "Bearer {}",
            base64::engine::general_purpose::STANDARD.encode(
                json!({"token": login.body["session_token"], "hash": login.body["hashed_token"]})
                    .to_string()
            )
        ));
    }
    let st = AppState {
        store: cap_store::Store::new(kv.clone()),
        embed_widget_url: String::new(),
        admin: Some(admin),
        admin_cfg: Arc::new(cap_admin::AdminConfig { demo: true, ..cfg }),
        releases: Arc::new(cap_assets::ReleaseStore::open(&root).unwrap()),
        ipdb: Arc::new(cap_ipdb::IpDb::open(&root.join("ipdb"), &root.join("tmp")).unwrap()),
        kv: kv.clone(),
        cache: Arc::new(crate::cache::ConfigCache::new()),
        limiter: Arc::new(crate::ratelimit::LocalLimiter::new()),
        metrics: Arc::new(crate::metrics_buf::MetricsBuffer::new()),
        training: None,
        redis_ratelimit: false,
        rsw_minters: moka::future::Cache::new(32),
        rsw_keygen: Default::default(),
    };
    for auth in [
        None,
        Some("Bot readonlyBot_token"),
        Some("Bearer malformed"),
    ] {
        assert_eq!(
            demo_credential(State(st.clone()), request(auth, "{}"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            demo_verify(State(st.clone()), request(auth, "{}"))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let cookie_only = Request::builder()
        .uri("/demo/credential?token=ignored")
        .header("cookie", format!("cap_auth={}", auths[0]))
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        demo_credential(State(st.clone()), cookie_only)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(kv.get("demo:widget-key").await.unwrap().is_none());
    for body in [
        r#"{"site":"evil"}"#,
        r#"{"action":"pay","action":"demo"}"#,
        r#"[]"#,
    ] {
        assert_eq!(
            demo_credential(State(st.clone()), request(Some(&auths[0]), body))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        demo_credential(
            State(st.clone()),
            request(Some(&auths[0]), vec![b' '; DEMO_BODY_LIMIT + 1])
        )
        .await
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        demo_verify(
            State(st.clone()),
            request(Some(&auths[0]), vec![b' '; DEMO_BODY_LIMIT + 1])
        )
        .await
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let credential =
        document(demo_credential(State(st.clone()), request(Some(&auths[0]), "{}")).await).await;
    let handle = credential["handle"].as_str().unwrap();
    let key_name = format!("demo:context:{handle}");
    let context_raw = kv.get(&key_name).await.unwrap().unwrap();
    let mut ctx: DemoContext = serde_json::from_str(&context_raw).unwrap();
    let payload = json!({"response": "invalid", "handle": handle}).to_string();
    assert_eq!(
        demo_verify(State(st.clone()), request(Some(&auths[1]), payload.clone()))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let forged = json!({"response": "invalid", "handle": "0".repeat(48)}).to_string();
    assert_eq!(
        demo_verify(State(st.clone()), request(Some(&auths[0]), forged))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    ctx.expires = now_ms() - 1;
    kv.set(&key_name, &serde_json::to_string(&ctx).unwrap())
        .await
        .unwrap();
    assert_eq!(
        demo_verify(State(st.clone()), request(Some(&auths[0]), payload.clone()))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    kv.set(&key_name, &context_raw).await.unwrap();
    let (site, secret) = demo_widget_credentials(&st).await.unwrap();
    assert!(!credential.to_string().contains(&secret));
    let key = st.store.key(&site).await.unwrap().unwrap();
    assert!(!credential.to_string().contains(&key.jwt_secret));
    let token = credential["businessToken"].as_str().unwrap();
    let claims = verify_business_token(token, &key.jwt_secret, now_ms()).unwrap();
    let result_token = format!("{site}:{}:{}", random_hex(16), random_hex(32));
    let bind =
        serde_json::to_string(&cap_core::SessionBind::new(None, "demo-test", now_ms())).unwrap();
    st.store
        .complete_business(
            &claims,
            token,
            cap_store::CompleteBusiness {
                challenge_nonce: "demo-test-challenge",
                challenge_expires_ms: now_ms() + 60000,
                token: &result_token,
                bind_json: &bind,
                token_ttl_ms: 60000,
            },
        )
        .await
        .unwrap();
    let valid = json!({"response": result_token, "handle": handle}).to_string();
    let verified =
        document(demo_verify(State(st.clone()), request(Some(&auths[0]), valid.clone())).await)
            .await;
    assert_eq!(verified["success"], true, "{verified}");
    assert!(verified.get("trust").is_none());
    let replay =
        document(demo_verify(State(st.clone()), request(Some(&auths[0]), valid)).await).await;
    assert_eq!(replay["success"], false);
    // Existing invalid demo configuration must not replace the shared pointer/key.
    kv.hset_pairs(
        &format!("key:{site}"),
        &[("config", json!({"corsOrigins":["*"]}).to_string())],
    )
    .await
    .unwrap();
    let pointer = kv.get("demo:widget-key").await.unwrap();
    assert!(demo_widget_credentials(&st).await.is_err());
    assert_eq!(kv.get("demo:widget-key").await.unwrap(), pointer);
    // A store type error must fail closed, not create a replacement key.
    kv.del("demo:widget-key").await.unwrap();
    kv.hset_pairs("demo:widget-key", &[("wrong", "type".into())])
        .await
        .unwrap();
    assert!(demo_widget_credentials(&st).await.is_err());
    assert_eq!(
        demo_credential(State(st.clone()), request(Some(&auths[0]), "{}"))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Exact key cleanup on this owned child only, followed by process teardown.
    let output = std::process::Command::new("redis-cli")
        .env("REDISCLI_AUTH", &password)
        .args([
            "-h",
            "127.0.0.1",
            "-p",
            &port.to_string(),
            "-n",
            "15",
            "--scan",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    for name in String::from_utf8(output.stdout).unwrap().lines() {
        kv.del(name).await.unwrap();
    }
}
