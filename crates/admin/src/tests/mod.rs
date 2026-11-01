//! Tests for the admin API.
//!
//! Shared helpers live here; the cases are split by topic so each file stays
//! readable. Redis-backed cases skip when Redis is unavailable.

use super::*;

    use super::*;
    use base64::Engine;
    use serde_json::json;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into())
    }

    async fn setup() -> Option<(AdminStore, AdminConfig)> {
        let cfg = AdminConfig {
            admin_key: "test-admin-key-1234567890".into(),
            demo: false,
        };
        match AdminStore::connect(&redis_url()).await {
            Ok(s) => Some((s, cfg)),
            Err(e) => {
                eprintln!("[cap-admin tests] redis unavailable, skipping: {e}");
                None
            }
        }
    }

    fn uniq() -> String {
        format!("{}{}", util::now_ms(), util::random_hex(4))
    }

    async fn call(
        store: &AdminStore,
        cfg: &AdminConfig,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Value,
    ) -> AdminResponse {
        let bytes = serde_json::to_vec(&body).unwrap();
        let req = AdminRequest {
            method,
            path,
            query: "",
            headers: &headers,
            body: &bytes,
            peer: "127.0.0.1",
        };
        handle(store, cfg, &req).await
    }

    fn bearer(token: &str, hash: &str) -> Vec<(String, String)> {
        let payload = json!({ "token": token, "hash": hash }).to_string();
        let enc = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        vec![("Authorization".into(), format!("Bearer {enc}"))]
    }

    fn bot(api_key: &str) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Bot {api_key}"))]
    }

    async fn login(store: &AdminStore, cfg: &AdminConfig) -> (String, String) {
        let r = call(
            store,
            cfg,
            "POST",
            "/auth/login",
            vec![],
            json!({"admin_key": cfg.admin_key}),
        )
        .await;
        assert_eq!(r.status, 200, "login status");
        let token = r.body["session_token"].as_str().unwrap().to_string();
        let hash = r.body["hashed_token"].as_str().unwrap().to_string();
        (token, hash)
    }

mod part1;
mod part2;
