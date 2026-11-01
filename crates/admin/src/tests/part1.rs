use super::*;

    // --- pure: constant-time admin key compare ---------------------------

    #[test]
    fn admin_key_compare() {
        assert!(util::admin_key_eq("s3cret-admin-key", "s3cret-admin-key"));
        assert!(!util::admin_key_eq("s3cret-admin-key", "s3cret-admin-kez"));
        assert!(!util::admin_key_eq("s3cret-admin-key", ""));
        assert!(!util::admin_key_eq(
            "s3cret-admin-key",
            "a much longer wrong key"
        ));
    }

    // --- pure: config validation + merge ---------------------------------

    #[test]
    fn create_config_defaults() {
        let cfg = keys::build_create_config(&json!({})).expect("defaults");
        assert_eq!(cfg["difficulty"], 4);
        assert_eq!(cfg["challengeCount"], 80);
        assert_eq!(cfg["saltSize"], 32);
        assert_eq!(cfg["protocol"], "hashwx");
        assert_eq!(cfg["rswT"], 75000);
        assert_eq!(cfg["hashwxDifficulty"], 1_000_000);
        assert_eq!(cfg["extendedProbes"], false);
        assert_eq!(cfg["blockOnDeny"], true);
        assert!(cfg["ratelimitMax"].is_null());
    }

    #[test]
    fn create_config_overrides_and_ranges() {
        let cfg = keys::build_create_config(&json!({
            "saltSize": 64, "requireSessionBind": true, "blockOnDeny": false,
            "autoBlockDenyMs": 5000, "rsw": true, "rswT": 120000,
            "corsOrigins": ["https://a.example"],
        }))
        .unwrap();
        assert_eq!(cfg["saltSize"], 64);
        assert_eq!(cfg["requireSessionBind"], true);
        assert_eq!(cfg["blockOnDeny"], false);
        assert_eq!(cfg["autoBlockDenyMs"], 5000);
        assert_eq!(cfg["rswT"], 120000);
        assert_eq!(cfg["corsOrigins"][0], "https://a.example");

        for bad in [
            json!({"saltSize": 8}),
            json!({"polymorphism": 2}),
            json!({"rswT": 1000}),
            json!({"hashwxDifficulty": 10}),
            json!({"autoBlockDenyMs": 86_400_001}),
            json!({"corsOrigins": vec!["x"; 51]}),
        ] {
            assert!(
                keys::build_create_config(&bad).is_err(),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn update_config_merge_and_ranges() {
        let existing = json!({
            "difficulty": 4, "challengeCount": 80, "saltSize": 32,
            "instrumentation": false, "obfuscationLevel": 3,
            "blockAutomatedBrowsers": false, "rsw": false, "rswT": 75000,
            "protocol": "hashwx", "hashwxDifficulty": 1000000,
            "extendedProbes": false,
        });
        let merged = keys::merge_update_config(&existing, &json!({"difficulty": 6})).unwrap();
        assert_eq!(merged["difficulty"], 6);
        assert_eq!(merged["challengeCount"], 80); // untouched

        let merged = keys::merge_update_config(
            &existing,
            &json!({"corsOrigins": null, "requiredHeaders": ["X-A"]}),
        )
        .unwrap();
        assert!(merged["corsOrigins"].is_null());
        assert_eq!(merged["requiredHeaders"][0], "X-A");

        assert!(keys::merge_update_config(&existing, &json!({"difficulty": 9})).is_err());
        assert!(keys::merge_update_config(&existing, &json!({"challengeCount": 0})).is_err());
        assert!(keys::merge_update_config(&existing, &json!({"obfuscationLevel": 11})).is_err());
        assert!(
            keys::merge_update_config(&existing, &json!({"requiredHeaders": vec!["h"; 21]}))
                .is_err()
        );
    }

    // --- pure: scope guard matrix ----------------------------------------

    #[test]
    fn scope_guard_matrix() {
        let global = Some(Scope {
            site_keys: None,
            readonly: false,
        });
        let global_ro = Some(Scope {
            site_keys: None,
            readonly: true,
        });
        let scoped = Some(Scope {
            site_keys: Some(vec!["abc".into()]),
            readonly: false,
        });
        let none = None;

        // global full access
        assert!(auth::scope_guard("POST", "/keys", &global).is_none());
        // global settings / API keys / 2FA are session-only, even for an
        // unscoped key
        for (m, p) in [
            ("GET", "/settings/headers"),
            ("POST", "/settings/apikeys"),
            ("DELETE", "/settings/apikeys/x"),
            ("PUT", "/settings/cors"),
            ("POST", "/integrity"),
            ("GET", "/settings/sessions"),
            ("POST", "/auth/2fa/disable"),
            ("POST", "/logout"),
        ] {
            let r = auth::scope_guard(m, p, &global).unwrap();
            assert_eq!(r.status, 403, "{m} {p}");
        }
        assert!(auth::scope_guard("GET", "/about", &global).is_none());
        // no scope (session)
        assert!(auth::scope_guard("POST", "/settings/apikeys", &none).is_none());
        assert!(auth::scope_guard("POST", "/keys", &none).is_none());

        // readonly blocks writes, allows reads
        let r = auth::scope_guard("POST", "/keys", &global_ro).unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body["error"], "Forbidden. This API key is read-only.");
        assert!(auth::scope_guard("GET", "/keys", &global_ro).is_none());
        assert!(auth::scope_guard("GET", "/keys/abc", &global_ro).is_none());

        // scoped: only its own site key routes + GET /keys
        assert!(auth::scope_guard("GET", "/keys/abc", &scoped).is_none());
        assert!(auth::scope_guard("GET", "/keys", &scoped).is_none());
        assert!(auth::scope_guard("GET", "/keys/other", &scoped).is_some());
        assert!(auth::scope_guard("POST", "/keys", &scoped).is_some());
        assert!(auth::scope_guard("GET", "/settings/headers", &scoped).is_some());
        assert!(auth::scope_guard("POST", "/keys/abc/rotate-secret", &scoped).is_none());
    }

    // --- redis-backed: login shape + auth failures -----------------------

    #[tokio::test]
    async fn login_shape_and_auth_failures() {
        let Some((store, cfg)) = setup().await else {
            return;
        };

        let r = call(
            &store,
            &cfg,
            "POST",
            "/auth/login",
            vec![],
            json!({"admin_key": cfg.admin_key}),
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body["success"], true);
        assert_eq!(r.body["session_token"].as_str().unwrap().len(), 60);
        assert!(
            r.body["hashed_token"]
                .as_str()
                .unwrap()
                .starts_with("$argon2")
        );
        assert!(r.body["expires"].as_i64().unwrap() > util::now_ms());
        assert!(r.headers.iter().any(|(k, _)| k == "Set-Cookie"));

        // wrong key
        let r = call(
            &store,
            &cfg,
            "POST",
            "/auth/login",
            vec![],
            json!({"admin_key": "nope"}),
        )
        .await;
        assert_eq!(r.status, 401);
        assert_eq!(r.body["success"], false);
        assert_eq!(r.body["error"], "Incorrect admin key");

        // no auth
        let r = call(&store, &cfg, "GET", "/keys", vec![], json!(null)).await;
        assert_eq!(r.status, 401);
        assert_eq!(
            r.body["error"],
            "Unauthorized. An API key or session token is required to use this endpoint."
        );

        // malformed bearer
        let r = call(
            &store,
            &cfg,
            "GET",
            "/keys",
            vec![("Authorization".into(), "Bearer not-base64-json".into())],
            json!(null),
        )
        .await;
        assert_eq!(r.status, 401);
        assert_eq!(r.body["error"], "Unauthorized. Malformed session token.");
    }

    // --- redis-backed: keys CRUD -----------------------------------------

    #[tokio::test]
    async fn keys_crud() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let name = format!("key-{}", uniq());
        let r = call(
            &store,
            &cfg,
            "POST",
            "/keys",
            auth.clone(),
            json!({"name": name, "saltSize": 64}),
        )
        .await;
        assert_eq!(r.status, 200);
        let site_key = r.body["siteKey"].as_str().unwrap().to_string();
        assert_eq!(site_key.len(), 10);
        assert!(site_key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(r.body["secretKey"].as_str().unwrap().starts_with("sk-"));
        assert!(!r.body.get("secretHash").is_some());

        // list contains it with config + metrics
        let r = call(&store, &cfg, "GET", "/keys", auth.clone(), json!(null)).await;
        assert_eq!(r.status, 200);
        let arr = r.body.as_array().unwrap();
        let item = arr
            .iter()
            .find(|k| k["siteKey"] == site_key.as_str())
            .expect("listed");
        assert_eq!(item["name"], name);
        assert_eq!(item["config"]["saltSize"], 64);
        assert_eq!(item["solvesLast24h"], 0);
        assert_eq!(item["difference"]["value"], "0.00");

        // get single
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/keys/{site_key}"),
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body["key"]["siteKey"], site_key);
        assert_eq!(r.body["key"]["config"]["saltSize"], 64);
        assert!(r.body["stats"].is_object());

        // update (via /config)
        let r = call(
            &store,
            &cfg,
            "PUT",
            &format!("/keys/{site_key}/config"),
            auth.clone(),
            json!({"difficulty": 6, "challengeCount": 12}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/keys/{site_key}"),
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["key"]["config"]["difficulty"], 6);
        assert_eq!(r.body["key"]["config"]["challengeCount"], 12);
        assert_eq!(r.body["key"]["config"]["saltSize"], 64); // preserved

        // invalid update rejected
        let r = call(
            &store,
            &cfg,
            "PUT",
            &format!("/keys/{site_key}/config"),
            auth.clone(),
            json!({"difficulty": 99}),
        )
        .await;
        assert_eq!(r.status, 400);

        // rotate
        let r = call(
            &store,
            &cfg,
            "POST",
            &format!("/keys/{site_key}/rotate-secret"),
            auth.clone(),
            json!({}),
        )
        .await;
        assert!(r.body["secretKey"].as_str().unwrap().starts_with("sk-"));

        // delete then gone
        let r = call(
            &store,
            &cfg,
            "DELETE",
            &format!("/keys/{site_key}"),
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/keys/{site_key}"),
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": false, "error": "Key not found"}));

        // cleanup session
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }

    // --- redis-backed: sessions masking + logout -------------------------

    #[tokio::test]
    async fn sessions_list_and_logout() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/sessions",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.status, 200);
        let arr = r.body.as_array().unwrap();
        let masked = util::last_chars(&hash, 14);
        let entry = arr
            .iter()
            .find(|s| s["token"] == masked.as_str())
            .expect("session listed");
        assert_eq!(entry["token"].as_str().unwrap().chars().count(), 14);
        assert!(entry["expires"].as_str().unwrap().ends_with('Z'));
        assert!(entry["created"].as_str().unwrap().ends_with('Z'));

        // too-short code rejected
        let r = call(
            &store,
            &cfg,
            "POST",
            "/logout",
            auth.clone(),
            json!({"session": "short"}),
        )
        .await;
        assert_eq!(r.body["error"], "Session code too short");

        // unknown suffix
        let r = call(
            &store,
            &cfg,
            "POST",
            "/logout",
            auth.clone(),
            json!({"session": "zzzzzzzzzzzzzz"}),
        )
        .await;
        assert_eq!(r.status, 404);

        // unique suffix logout
        let r = call(
            &store,
            &cfg,
            "POST",
            "/logout",
            auth.clone(),
            json!({"session": masked}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let still = store.exists(&format!("session:{hash}")).await.unwrap();
        assert!(!still);
        assert!(!store.smembers("sessions").await.unwrap().contains(&hash));
    }

    // --- redis-backed: api keys + bot auth + scoping ---------------------

    #[tokio::test]
    async fn apikeys_and_bot_scope() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        // two keys
        let r = call(
            &store,
            &cfg,
            "POST",
            "/keys",
            auth.clone(),
            json!({"name": format!("a{}", uniq())}),
        )
        .await;
        let sk_a = r.body["siteKey"].as_str().unwrap().to_string();
        let r = call(
            &store,
            &cfg,
            "POST",
            "/keys",
            auth.clone(),
            json!({"name": format!("b{}", uniq())}),
        )
        .await;
        let sk_b = r.body["siteKey"].as_str().unwrap().to_string();

        // scoped non-readonly api key
        let r = call(
            &store,
            &cfg,
            "POST",
            "/settings/apikeys",
            auth.clone(),
            json!({"name": "bot", "siteKeys": [sk_a]}),
        )
        .await;
        assert_eq!(r.status, 200);
        let api_key = r.body["apiKey"].as_str().unwrap().to_string();
        let (id, _) = api_key.split_once('_').unwrap();
        assert_eq!(id.len(), 32);

        // list contains it
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/apikeys",
            auth.clone(),
            json!(null),
        )
        .await;
        let item = r
            .body
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["id"] == id)
            .expect("api key listed");
        assert_eq!(item["name"], "bot");
        assert_eq!(item["siteKeys"][0], sk_a);
        assert_eq!(item["readonly"], false);
        assert!(item["created"].as_str().unwrap().ends_with('Z'));

        // bot auth: scoped list shows only sk_a
        let r = call(&store, &cfg, "GET", "/keys", bot(&api_key), json!(null)).await;
        assert_eq!(r.status, 200);
        let arr = r.body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["siteKey"], sk_a);

        // scoped cannot touch sk_b, cannot create keys
        let r = call(
            &store,
            &cfg,
            "GET",
            &format!("/keys/{sk_b}"),
            bot(&api_key),
            json!(null),
        )
        .await;
        assert_eq!(r.status, 403);
        let r = call(&store, &cfg, "POST", "/keys", bot(&api_key), json!({})).await;
        assert_eq!(r.status, 403);

        // readonly api key
        let r = call(
            &store,
            &cfg,
            "POST",
            "/settings/apikeys",
            auth.clone(),
            json!({"name": "ro", "siteKeys": [sk_a], "readonly": true}),
        )
        .await;
        let ro_key = r.body["apiKey"].as_str().unwrap().to_string();
        let r = call(&store, &cfg, "GET", "/keys", bot(&ro_key), json!(null)).await;
        assert_eq!(r.status, 200);
        let r = call(&store, &cfg, "POST", "/keys", bot(&ro_key), json!({})).await;
        assert_eq!(r.status, 403);
        assert_eq!(r.body["error"], "Forbidden. This API key is read-only.");

        // unknown site key rejected
        let r = call(
            &store,
            &cfg,
            "POST",
            "/settings/apikeys",
            auth.clone(),
            json!({"name": "bad", "siteKeys": ["doesnotexist"]}),
        )
        .await;
        assert_eq!(r.status, 400);

        // delete api key -> bot auth now 401
        let r = call(
            &store,
            &cfg,
            "DELETE",
            &format!("/settings/apikeys/{id}"),
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(&store, &cfg, "GET", "/keys", bot(&api_key), json!(null)).await;
        assert_eq!(r.status, 401);
        assert_eq!(
            r.body["error"],
            "Unauthorized. Deleted or non-existent bot token."
        );

        // cleanup
        for sk in [&sk_a, &sk_b] {
            let _ = store.del(&format!("key:{sk}")).await;
            let _ = store.srem("keys", sk).await;
        }
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }

    // --- redis-backed: settings roundtrip --------------------------------

    #[tokio::test]
    async fn settings_roundtrip() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/headers",
            auth.clone(),
            json!({"ipHeader": "CF-Connecting-IP"}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/headers",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["ipHeader"], "CF-Connecting-IP");
        assert_eq!(r.body["countryHeader"], "");

        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/ratelimit",
            auth.clone(),
            json!({"max": 50, "duration": 2000}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/ratelimit",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["max"], 50);
        assert_eq!(r.body["duration"], 2000);
        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/ratelimit",
            auth.clone(),
            json!({"max": 0}),
        )
        .await;
        assert_eq!(r.status, 400);

        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/cors",
            auth.clone(),
            json!({"origins": ["https://app.example"]}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/cors",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["origins"][0], "https://app.example");

        let r = call(
            &store,
            &cfg,
            "PUT",
            "/settings/filtering",
            auth.clone(),
            json!({"blockNonBrowserUA": true, "requiredHeaders": ["X-Cap"]}),
        )
        .await;
        assert_eq!(r.body, json!({"success": true}));
        let r = call(
            &store,
            &cfg,
            "GET",
            "/settings/filtering",
            auth.clone(),
            json!(null),
        )
        .await;
        assert_eq!(r.body["blockNonBrowserUA"], true);
        assert_eq!(r.body["requiredHeaders"][0], "X-Cap");

        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }

    // --- redis-backed: integrity + about ---------------------------------

    #[tokio::test]
    async fn integrity_and_about() {
        let Some((store, cfg)) = setup().await else {
            return;
        };
        let (token, hash) = login(&store, &cfg).await;
        let auth = bearer(&token, &hash);

        let _ = store.del("settings:integrity").await;

        let r = call(&store, &cfg, "GET", "/integrity", auth.clone(), json!(null)).await;
        assert_eq!(r.body["success"], true);
        assert!(r.body["baseline"].is_null());

        let r = call(&store, &cfg, "POST", "/integrity", auth.clone(), json!({})).await;
        assert_eq!(r.status, 400);

        let r = call(
            &store,
            &cfg,
            "POST",
            "/integrity",
            auth.clone(),
            json!({"refetch": true}),
        )
        .await;
        assert_eq!(r.body["refetch"], "unsupported_in_rust_port");

        let hash_hex = "A".repeat(64);
        let r = call(
            &store,
            &cfg,
            "POST",
            "/integrity",
            auth.clone(),
            json!({"widget": hash_hex}),
        )
        .await;
        assert_eq!(r.body["success"], true);
        assert_eq!(r.body["baseline"]["widget"], "a".repeat(64));
        assert_eq!(r.body["baseline"]["source"], "settings");
        assert!(r.body["baseline"]["capWasm"].is_null());

        let r = call(&store, &cfg, "GET", "/integrity", auth.clone(), json!(null)).await;
        assert_eq!(r.body["baseline"]["widget"], "a".repeat(64));

        let r = call(&store, &cfg, "GET", "/about", auth.clone(), json!(null)).await;
        assert_eq!(r.body["bun"], "rust");
        assert_eq!(r.body["platform"], "rust");
        assert_eq!(r.body["ver"], "3.1.17");
        assert_eq!(r.body["demo"], false);

        let _ = store.del("settings:integrity").await;
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", &hash).await;
    }
