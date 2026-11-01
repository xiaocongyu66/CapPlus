use super::*;

    // --- pure: route parsing for the new paths ---------------------------

    #[test]
    fn route_parsing_new_paths() {
        assert_eq!(share_view_id("/shares/abc123"), Some("abc123"));
        assert_eq!(share_view_id("/shares"), None);
        assert_eq!(share_view_id("/shares/"), None);
        assert_eq!(share_view_id("/shares/a/b"), None);
        assert_eq!(share_view_id("/keys/abc"), None);
    }

    // --- redis-backed: demo mode is read-only ----------------------------

    #[tokio::test]
    async fn demo_mode_read_only_matrix() {
        let Some((store, _)) = setup().await else {
            return;
        };
        let demo = AdminConfig {
            admin_key: "test-admin-key-1234567890".into(),
            demo: true,
        };

        // login hands out a fake session, no redis writes / no real token.
        let r = call(
            &store,
            &demo,
            "POST",
            "/auth/login",
            vec![],
            json!({"admin_key": demo.admin_key}),
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, json!({"success": true, "demo": true}));

        // about reports demo
        let r = call(&store, &demo, "GET", "/about", vec![], json!(null)).await;
        assert_eq!(r.body["demo"], true);

        // GETs work without credentials and stay read-only.
        let r = call(&store, &demo, "GET", "/keys", vec![], json!(null)).await;
        assert_eq!(r.status, 200);
        assert!(r.body.is_array());
        let r = call(
            &store,
            &demo,
            "GET",
            "/settings/headers",
            vec![],
            json!(null),
        )
        .await;
        assert_eq!(r.status, 200);
        assert!(r.body.is_object());

        // every mutating route returns the demo envelope ...
        let unique_name = format!("demo-should-not-exist-{}", uniq());
        let r = call(
            &store,
            &demo,
            "POST",
            "/keys",
            vec![],
            json!({"name": unique_name}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true, "demo": true}));
        let r = call(
            &store,
            &demo,
            "PUT",
            "/settings/headers",
            vec![],
            json!({"ipHeader": "X-Demo"}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true, "demo": true}));
        let r = call(
            &store,
            &demo,
            "DELETE",
            "/keys/whatever",
            vec![],
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": true, "demo": true}));
        let r = call(
            &store,
            &demo,
            "POST",
            "/shares",
            vec![],
            json!({"siteKey": "anything"}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true, "demo": true}));
        let r = call(
            &store,
            &demo,
            "DELETE",
            "/shares/deadbeefdeadbeef",
            vec![],
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": true, "demo": true}));

        // ... and nothing was persisted: the unique name is absent from /keys.
        let r = call(&store, &demo, "GET", "/keys", vec![], json!(null)).await;
        assert!(
            !r.body
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k["name"] == unique_name.as_str())
        );
    }

    // --- redis-backed: login rate limit (fixed window per IP) ------------

    #[tokio::test]
    async fn login_rate_limit_per_ip() {
        let Some((store, cfg)) = setup().await else {
            return;
        };

        let ip = format!("198.51.100.{}", (util::now_ms() % 200) + 1);
        let headers = vec![("x-test-peer".to_string(), ip.clone())];

        // 200 attempts are allowed (they fail auth but still count).
        for i in 0..200 {
            let r = call(
                &store,
                &cfg,
                "POST",
                "/auth/login",
                headers.clone(),
                json!({"admin_key": "wrong"}),
            )
            .await;
            assert_eq!(r.status, 401, "attempt {i} should be allowed");
        }
        // 201st is throttled before the key is even checked.
        let r = call(
            &store,
            &cfg,
            "POST",
            "/auth/login",
            headers.clone(),
            json!({"admin_key": cfg.admin_key}),
        )
        .await;
        assert_eq!(r.status, 429);
        assert_eq!(
            r.body,
            json!({"success": false, "error": "Too many attempts"})
        );

        // cleanup this window's counter.
        let window = util::now_ms() / 20_000;
        let _ = store.del(&format!("rl:login:{ip}:20000:{window}")).await;

        // Forwarded headers are ignored by the admin crate: rotating them
        // does not escape the bucket of the resolved client address.
        let mut spoofed = headers.clone();
        spoofed.push(("X-Forwarded-For".into(), "203.0.113.99".into()));
        for _ in 0..200 {
            let _ = call(&store, &cfg, "POST", "/auth/login", spoofed.clone(), json!({"admin_key": "wrong"})).await;
        }
        let r = call(&store, &cfg, "POST", "/auth/login", spoofed, json!({"admin_key": "wrong"})).await;
        assert_eq!(r.status, 429);
        let window = util::now_ms() / 20_000;
        let _ = store.del(&format!("rl:login:{ip}:20000:{window}")).await;
    }

    // --- redis-backed: shares create/get/list/delete + expiry ------------

    #[tokio::test]
    async fn shares_create_public_get_list_delete() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let r = call(
            &store,
            &cfg,
            "POST",
            "/keys",
            auth.clone(),
            json!({"name": format!("sharekey-{}", uniq())}),
        )
        .await;
        let sk = r.body["siteKey"].as_str().unwrap().to_string();

        // seed metrics for the stats aggregation.
        let _ = store
            .hset_pairs(
                &format!("metrics:verified:{sk}"),
                &[("100", "3".into()), ("200", "4".into())],
            )
            .await;
        let _ = store
            .hset_pairs(&format!("metrics:failed:{sk}"), &[("100", "2".into())])
            .await;

        // create
        let r = call(
            &store,
            &cfg,
            "POST",
            "/shares",
            auth.clone(),
            json!({"siteKey": sk, "name": "My share"}),
        )
        .await;
        assert_eq!(r.status, 200);
        let id = r.body["id"].as_str().unwrap().to_string();
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(r.body["url"], format!("/shares/{id}"));
        assert!(r.body["expires"].is_null());

        // public get (no auth) with stats summed from the metrics hashes.
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/shares/{id}"),
            vec![],
            json!(null),
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body["siteKey"], sk);
        assert_eq!(r.body["name"], "My share");
        assert!(r.body["created"].as_i64().unwrap() > 0);
        assert!(r.body["expires"].is_null());
        assert_eq!(r.body["stats"], json!({"verified": 7, "failed": 2}));

        // list (auth)
        let r = call(&store, &cfg, "GET", "/shares", auth.clone(), json!(null)).await;
        assert_eq!(r.status, 200);
        assert!(r.body.as_array().unwrap().iter().any(|s| s["id"] == id));

        // expiry: an expired share is treated as gone and its hash removed.
        let r = call(
            &store,
            &cfg,
            "POST",
            "/shares",
            auth.clone(),
            json!({"siteKey": sk, "name": "expiring", "expiresInMs": 60000}),
        )
        .await;
        let eid = r.body["id"].as_str().unwrap().to_string();
        assert!(r.body["expires"].as_i64().unwrap() > util::now_ms());
        let _ = store
            .hset_pairs(
                &format!("share:{eid}"),
                &[("expires", (util::now_ms() - 1000).to_string())],
            )
            .await;
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/shares/{eid}"),
            vec![],
            json!(null),
        )
        .await;
        assert_eq!(r.status, 404);
        assert!(!store.exists(&format!("share:{eid}")).await.unwrap());

        // delete
        let r = call(
            &store,
            &cfg,
            "DELETE",
            &format!("/shares/{id}"),
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/shares/{id}"),
            vec![],
            json!(null),
        )
        .await;
        assert_eq!(r.status, 404);
        // deleting an unknown share is a 404.
        let r = call(
            &store,
            &cfg,
            "DELETE",
            "/shares/0000000000000000",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.status, 404);

        // cleanup
        let _ = store.del(&format!("key:{sk}")).await;
        let _ = store.srem("keys", &sk).await;
        let _ = store.del(&format!("metrics:verified:{sk}")).await;
        let _ = store.del(&format!("metrics:failed:{sk}")).await;
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }

    // --- redis-backed: share scope guard ---------------------------------

    #[tokio::test]
    async fn shares_scope_guard() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let r = call(
            &store,
            &cfg,
            "POST",
            "/keys",
            auth.clone(),
            json!({"name": format!("sa-{}", uniq())}),
        )
        .await;
        let sk_a = r.body["siteKey"].as_str().unwrap().to_string();
        let r = call(
            &store,
            &cfg,
            "POST",
            "/keys",
            auth.clone(),
            json!({"name": format!("sb-{}", uniq())}),
        )
        .await;
        let sk_b = r.body["siteKey"].as_str().unwrap().to_string();

        // scoped, non-readonly bot key on sk_a.
        let r = call(
            &store,
            &cfg,
            "POST",
            "/settings/apikeys",
            auth.clone(),
            json!({"name": "sharebot", "siteKeys": [sk_a]}),
        )
        .await;
        let api_key = r.body["apiKey"].as_str().unwrap().to_string();
        let (api_id, _) = api_key.split_once('_').unwrap();

        // may create a share for its own key ...
        let r = call(
            &store,
            &cfg,
            "POST",
            "/shares",
            bot(&api_key),
            json!({"siteKey": sk_a, "name": "scoped"}),
        )
        .await;
        assert_eq!(r.status, 200);
        let id_a = r.body["id"].as_str().unwrap().to_string();

        // ... but not for another key.
        let r = call(
            &store,
            &cfg,
            "POST",
            "/shares",
            bot(&api_key),
            json!({"siteKey": sk_b}),
        )
        .await;
        assert_eq!(r.status, 403);
        assert_eq!(
            r.body["error"],
            "Forbidden. This API key is not scoped to this site key."
        );

        // list is filtered to the scope.
        let r = call(&store, &cfg, "GET", "/shares", bot(&api_key), json!(null)).await;
        assert_eq!(r.status, 200);
        assert!(
            r.body
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["siteKey"] == sk_a.as_str())
        );
        assert!(r.body.as_array().unwrap().iter().any(|s| s["id"] == id_a));

        // a share owned by another key cannot be deleted by the scoped bot.
        let r = call(
            &store,
            &cfg,
            "POST",
            "/shares",
            auth.clone(),
            json!({"siteKey": sk_b}),
        )
        .await;
        let id_b = r.body["id"].as_str().unwrap().to_string();
        let r = call(
            &store,
            &cfg,
            "DELETE",
            &format!("/shares/{id_b}"),
            bot(&api_key),
            json!(null),
        )
        .await;
        assert_eq!(r.status, 403);

        // readonly bot cannot create at all.
        let r = call(
            &store,
            &cfg,
            "POST",
            "/settings/apikeys",
            auth.clone(),
            json!({"name": "ro-share", "siteKeys": [sk_a], "readonly": true}),
        )
        .await;
        let ro_key = r.body["apiKey"].as_str().unwrap().to_string();
        let (ro_id, _) = ro_key.split_once('_').unwrap();
        let r = call(
            &store,
            &cfg,
            "POST",
            "/shares",
            bot(&ro_key),
            json!({"siteKey": sk_a}),
        )
        .await;
        assert_eq!(r.status, 403);
        assert_eq!(r.body["error"], "Forbidden. This API key is read-only.");

        // its own share can be deleted.
        let r = call(
            &store,
            &cfg,
            "DELETE",
            &format!("/shares/{id_a}"),
            bot(&api_key),
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));

        // cleanup
        let _ = store.del(&format!("share:{id_b}")).await;
        let _ = store.srem("shares", &id_b).await;
        for sk in [&sk_a, &sk_b] {
            let _ = store.del(&format!("key:{sk}")).await;
            let _ = store.srem("keys", sk).await;
            let _ = store.del(&format!("shares:{sk}")).await;
        }
        for id in [api_id, ro_id] {
            let _ = store.del(&format!("apikey:{id}")).await;
            let _ = store.srem("apikeys", id).await;
        }
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }

    // --- redis-backed: ipdb settings round-trip + secret masking ---------

    #[tokio::test]
    async fn ipdb_roundtrip_masking() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let _ = store.del("settings:ipdb").await;

        // defaults
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/ipdb",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["success"], true);
        assert_eq!(r.body["provider"], "none");
        assert_eq!(r.body["configured"], false);
        assert_eq!(r.body["updatedAt"], "");
        assert_eq!(r.body["sources"]["maxmind"]["accountIdSet"], false);
        assert_eq!(r.body["sources"]["maxmind"]["keySet"], false);
        assert_eq!(r.body["sources"]["ipinfo"]["tokenSet"], false);

        // write
        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/ipdb",
            auth.clone(),
            json!({
                "provider": "maxmind",
                "maxmindAccountId": "acct-123",
                "maxmindKey": "super-secret-key",
                "ipinfoToken": "tok-abc",
            }),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));

        // read back: provider + only *Set booleans, no secret values.
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/ipdb",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["provider"], "maxmind");
        assert_eq!(r.body["configured"], true);
        assert_eq!(r.body["sources"]["maxmind"]["accountIdSet"], true);
        assert_eq!(r.body["sources"]["maxmind"]["keySet"], true);
        assert_eq!(r.body["sources"]["ipinfo"]["tokenSet"], true);
        assert!(!r.body["updatedAt"].as_str().unwrap().is_empty());
        let txt = r.body.to_string();
        for secret in ["super-secret-key", "tok-abc", "acct-123"] {
            assert!(
                !txt.contains(secret),
                "secret leaked in GET response: {secret}"
            );
        }

        // invalid provider rejected
        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/ipdb",
            auth.clone(),
            json!({"provider": "bogus"}),
        )
        .await;
        assert_eq!(r.status, 400);

        // switching to none clears `configured`
        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/ipdb",
            auth.clone(),
            json!({"provider": "none"}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/ipdb",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["provider"], "none");
        assert_eq!(r.body["configured"], false);

        // ipinfo provider
        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/ipdb",
            auth.clone(),
            json!({"provider": "ipinfo", "ipinfoToken": "tok2"}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/ipdb",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["provider"], "ipinfo");
        assert_eq!(r.body["configured"], true);

        // downloader is not ported
        let r = call(
            &store,
            &cfg,
            "POST",
            "/settings/ipdb/download",
            auth.clone(),
            json!({}),
        )
        .await;
        assert_eq!(
            r.body,
            json!({"success": false, "error": "unsupported_in_rust_port"})
        );

        let _ = store.del("settings:ipdb").await;
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }
