//! Admin / management API for the Cap Rust port.
//!
//! Framework-agnostic router: the lead resolves a request into an
//! [`AdminRequest`] (method, path after `/server` or `/auth/login`, headers,
//! raw body) and calls [`handle`], which returns an [`AdminResponse`]
//! (status + headers + JSON body). No HTTP framework is pulled in here.
//!
//! The endpoint set, Redis keys and JSON bodies mirror
//! `standalone/src/server.js` + `standalone/src/auth.js`.

mod auth;
mod blocked;
mod demo;
mod ipdb;
mod rsw;
mod keys;
mod settings;
mod shares;
mod store;
mod totp;
mod util;

use serde_json::{Value, json};

pub use auth::{cookie_session_key, require_session};
pub use store::AdminStore;

/// Admin router configuration.
///
/// API change: `demo` was added. Construct with a struct literal
/// (`AdminConfig { admin_key, demo: false }`) or use `..Default::default()`:
///
/// ```
/// # use cap_admin::AdminConfig;
/// let cfg = AdminConfig { admin_key: "secret-key-1234".into(), ..Default::default() };
/// assert!(!cfg.demo);
/// ```
#[derive(Clone, Default)]
pub struct AdminConfig {
    pub admin_key: String,
    /// Demo mode (mirrors `DEMO_MODE=true` in `demo.js`): mutating routes are
    /// answered with `{"success":true,"demo":true}` and never touch Redis,
    /// `/auth/login` hands out a fake session, GETs stay read-only.
    pub demo: bool,
}

pub struct AdminRequest<'a> {
    pub method: &'a str,
    /// Path *after* the `/server` prefix (e.g. `/keys`), or `/auth/login`.
    pub path: &'a str,
    /// Raw query string without the `?` (e.g. `chartDuration=last7days`).
    pub query: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

/// One query parameter, percent-decoded where possible.
pub(crate) fn query_param<'q>(query: &'q str, name: &str) -> Option<&'q str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then_some(v)
    })
}

pub struct AdminResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

/// Per-request authorisation scope derived from a `Bot` API key. `None` from
/// [`auth::authenticate`] means a full (unscoped, non-readonly) admin session.
#[derive(Clone, Debug, Default)]
pub(crate) struct Scope {
    /// `None` = global access; `Some` = restricted to these site keys.
    pub site_keys: Option<Vec<String>>,
    pub readonly: bool,
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

pub(crate) fn resp(status: u16, body: Value) -> AdminResponse {
    AdminResponse {
        status,
        headers: Vec::new(),
        body,
    }
}

pub(crate) fn ok(body: Value) -> AdminResponse {
    resp(200, body)
}

pub(crate) fn bad_request(msg: &str) -> AdminResponse {
    resp(400, json!({ "success": false, "error": msg }))
}

pub(crate) fn internal() -> AdminResponse {
    resp(
        500,
        json!({ "success": false, "error": "Internal server error" }),
    )
}

pub(crate) fn not_found() -> AdminResponse {
    resp(404, json!({ "success": false, "error": "Not found" }))
}

fn add_security_headers(mut r: AdminResponse) -> AdminResponse {
    r.headers
        .push(("X-Content-Type-Options".into(), "nosniff".into()));
    r.headers.push(("X-Frame-Options".into(), "DENY".into()));
    r.headers
        .push(("X-XSS-Protection".into(), "1; mode=block".into()));
    r
}

pub(crate) fn parse_body(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

pub(crate) fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// `GET /shares/:id` is public (mirrors the public `/share/:token` routes in
/// `share.js`). Returns the id when `path` is exactly `/shares/<id>`.
pub(crate) fn share_view_id(path: &str) -> Option<&str> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["shares", id] if !id.is_empty() => Some(id),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn handle(
    store: &AdminStore,
    cfg: &AdminConfig,
    req: &AdminRequest<'_>,
) -> AdminResponse {
    let method = req.method.to_ascii_uppercase();

    // /auth/login is the only unauthenticated non-share endpoint.
    if req.path == "/auth/login" {
        if method == "POST" {
            return auth::login(store, cfg, req).await;
        }
        return not_found();
    }

    // Demo mode: every mutating route is a no-op that never touches Redis.
    if cfg.demo && matches!(method.as_str(), "POST" | "PUT" | "DELETE") {
        return add_security_headers(ok(json!({ "success": true, "demo": true })));
    }

    // Public share views — no auth, like the `/share` server in share.js.
    if method == "GET" {
        let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
        match segs.as_slice() {
            ["share", token] => {
                let duration = query_param(req.query, "chartDuration").unwrap_or("today");
                return add_security_headers(
                    shares::public_for_token(store, token, duration).await,
                );
            }
            ["share", token, "geo-stats"] => {
                return add_security_headers(shares::public_geo_for_token(store, token).await);
            }
            _ => {}
        }
        if let Some(id) = share_view_id(req.path) {
            return add_security_headers(shares::get_public(store, id).await);
        }
    }

    let scope = if cfg.demo {
        // Demo GETs stay read-only and need no credentials.
        None
    } else {
        match auth::authenticate(store, req).await {
            Ok(s) => s,
            Err(resp) => return add_security_headers(resp),
        }
    };

    if let Some(resp) = auth::scope_guard(&method, req.path, &scope) {
        return add_security_headers(resp);
    }

    let body = parse_body(req.body);
    if cfg.demo {
        if let Some(resp) = demo_dispatch(req, &method, &body) {
            return add_security_headers(resp);
        }
    }
    let resp = dispatch(store, cfg, req, &method, &scope, &body).await;
    add_security_headers(resp)
}

/// Demo-mode reads. Returns `None` for anything this module does not own, so
/// the real handler (e.g. `/about`) still answers.
fn demo_dispatch(req: &AdminRequest<'_>, method: &str, _body: &Value) -> Option<AdminResponse> {
    if method != "GET" && method != "HEAD" {
        return None;
    }
    let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let duration = query_param(req.query, "chartDuration").unwrap_or("today");
    Some(match segs.as_slice() {
        ["keys"] => ok(demo::keys_list()),
        ["keys", sk] => match demo::key_detail(sk, duration) {
            Some(v) => ok(v),
            None => ok(json!({ "success": false, "error": "Key not found" })),
        },
        ["keys", sk, "geo-stats"] => ok(demo::geo_stats(sk)),
        ["keys", sk, "blocked-ips"] => ok(demo::blocked_ips(sk)),
        ["keys", sk, "shares"] => ok(demo::shares(sk)),
        ["settings", "sessions"] => ok(demo::sessions()),
        ["settings", "apikeys"] => ok(demo::api_keys()),
        ["settings", "headers"] => ok(json!({
            "ipHeader": "CF-Connecting-IP",
            "countryHeader": "CF-IPCountry",
            "asnHeader": "CF-IPOrg",
        })),
        ["settings", "ratelimit"] => ok(json!({ "max": 30, "duration": 5000 })),
        ["settings", "cors"] => ok(json!({ "origins": ["example.com", "www.example.com"] })),
        ["settings", "filtering"] => ok(json!({
            "blockNonBrowserUA": true,
            "requiredHeaders": ["accept-language", "sec-ch-ua"],
        })),
        ["settings", "ipdb"] => ok(json!({
            "mode": "dbip",
            "provider": "dbip",
            "configured": true,
            "country": { "exists": true, "size": 8_300_000 },
            "asn": { "exists": true, "size": 9_600_000 },
            "loaded": { "country": true, "asn": true },
            "lastUpdated": null,
            "error": null,
            "progress": { "active": false, "file": "", "downloaded": 0, "total": 0 },
            "sources": { "maxmind": { "accountIdSet": false, "keySet": false }, "ipinfo": { "tokenSet": false } },
        })),
        ["settings", "ipdb", "progress"] => ok(json!({
            "active": false, "file": "", "downloaded": 0, "total": 0, "error": null,
        })),
        ["settings", "rsw"] => ok(json!({ "success": true, "exists": true, "bits": 2048, "created": util::now_ms() })),
        ["integrity"] => ok(json!({ "success": true, "baseline": null })),
        ["shares"] => ok(demo::shares("a1b2c3d4e5")),
        _ => return None,
    })
}

async fn dispatch(
    store: &AdminStore,
    cfg: &AdminConfig,
    req: &AdminRequest<'_>,
    method: &str,
    scope: &Option<Scope>,
    body: &Value,
) -> AdminResponse {
    let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let read = method == "GET" || method == "HEAD";

    match segs.as_slice() {
        ["keys"] => {
            if read {
                keys::list(store, scope).await
            } else if method == "POST" {
                keys::create(store, body).await
            } else {
                not_found()
            }
        }
        ["keys", sk] => {
            if read {
                let duration = query_param(req.query, "chartDuration").unwrap_or("today");
                keys::get_with_duration(store, sk, duration).await
            } else if method == "DELETE" {
                keys::delete(store, sk).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "config"] => {
            if method == "PUT" {
                keys::update(store, sk, body).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "shares"] => {
            if read {
                shares::list_for_key(store, sk).await
            } else if method == "POST" {
                shares::create_for_key(store, sk, body).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "shares", id] => {
            if method == "DELETE" {
                shares::delete_for_key(store, sk, id).await
            } else {
                not_found()
            }
        }
        ["support", "_"] => not_found(),
        ["keys", sk, "geo-stats"] => {
            if read {
                blocked::geo_stats(store, sk).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "blocked-ips"] => {
            if read {
                blocked::list(store, sk).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "block-ip"] => {
            if method == "POST" {
                blocked::block(store, sk, body).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "unblock-ip"] => {
            if method == "POST" {
                blocked::unblock(store, sk, body).await
            } else {
                not_found()
            }
        }
        ["keys", sk, "rotate-secret"] => {
            if method == "POST" {
                keys::rotate_secret(store, sk).await
            } else {
                not_found()
            }
        }
        ["integrity"] => {
            if read {
                settings::integrity_get(store).await
            } else if method == "POST" {
                settings::integrity_post(store, body).await
            } else {
                not_found()
            }
        }
        ["about"] => settings::about(cfg.demo),
        ["shares"] => {
            if read {
                shares::list(store, scope).await
            } else if method == "POST" {
                shares::create(store, body, scope).await
            } else {
                not_found()
            }
        }
        ["shares", id] => {
            // GET /shares/:id is served publicly in `handle` before auth.
            if method == "DELETE" {
                shares::delete(store, id, scope).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa", "setup"] => {
            if scope.is_some() {
                return resp(
                    403,
                    json!({ "success": false, "error": "Forbidden. Session token required." }),
                );
            }
            if method == "POST" {
                totp::setup(store).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa", "enable"] => {
            if scope.is_some() {
                return resp(
                    403,
                    json!({ "success": false, "error": "Forbidden. Session token required." }),
                );
            }
            if method == "POST" {
                totp::enable(store, body).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa", "disable"] => {
            if scope.is_some() {
                return resp(
                    403,
                    json!({ "success": false, "error": "Forbidden. Session token required." }),
                );
            }
            if method == "POST" {
                totp::disable(store, cfg, body).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa"] => {
            if scope.is_some() {
                return resp(
                    403,
                    json!({ "success": false, "error": "Forbidden. Session token required." }),
                );
            }
            if read {
                ok(totp::status(store).await)
            } else {
                not_found()
            }
        }
        ["logout"] => {
            if method == "POST" {
                settings::logout(store, req, body).await
            } else {
                not_found()
            }
        }
        ["settings", "sessions"] => {
            if read {
                settings::list_sessions(store).await
            } else {
                not_found()
            }
        }
        ["settings", "apikeys"] => {
            if read {
                settings::apikeys_list(store).await
            } else if method == "POST" {
                settings::apikeys_create(store, body).await
            } else {
                not_found()
            }
        }
        ["settings", "apikeys", id] => {
            if method == "DELETE" {
                settings::apikeys_delete(store, id).await
            } else {
                not_found()
            }
        }
        ["settings", "headers"] => {
            if read {
                settings::get_headers(store).await
            } else if method == "PUT" {
                settings::put_headers(store, body).await
            } else {
                not_found()
            }
        }
        ["settings", "ratelimit"] => {
            if read {
                settings::get_ratelimit(store).await
            } else if method == "PUT" {
                settings::put_ratelimit(store, body).await
            } else {
                not_found()
            }
        }
        ["settings", "cors"] => {
            if read {
                settings::get_cors(store).await
            } else if method == "PUT" {
                settings::put_cors(store, body).await
            } else {
                not_found()
            }
        }
        ["settings", "filtering"] => {
            if read {
                settings::get_filtering(store).await
            } else if method == "PUT" {
                settings::put_filtering(store, body).await
            } else {
                not_found()
            }
        }
        ["settings", "rsw"] => {
            if read {
                rsw::status(store).await
            } else {
                not_found()
            }
        }
        ["settings", "rsw", "ensure"] => {
            if method == "POST" {
                rsw::ensure(store).await
            } else {
                not_found()
            }
        }
        ["settings", "ipdb"] => {
            if read {
                ipdb::get(store).await
            } else if method == "PUT" {
                ipdb::put(store, body).await
            } else if method == "DELETE" {
                ipdb::delete(store).await
            } else {
                not_found()
            }
        }
        ["settings", "ipdb", "progress"] => {
            if read {
                ipdb::progress()
            } else {
                not_found()
            }
        }
        ["settings", "ipdb", "download"] => {
            if method == "POST" {
                ipdb::download()
            } else {
                not_found()
            }
        }
        _ => not_found(),
    }
}

#[cfg(test)]
mod tests {
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
        assert!(auth::scope_guard("GET", "/settings/headers", &global).is_none());
        // no scope (session)
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

    // --- pure: route parsing for the new paths ---------------------------

    #[test]
    fn route_parsing_new_paths() {
        assert_eq!(share_view_id("/shares/abc123"), Some("abc123"));
        assert_eq!(share_view_id("/shares"), None);
        assert_eq!(share_view_id("/shares/"), None);
        assert_eq!(share_view_id("/shares/a/b"), None);
        assert_eq!(share_view_id("/keys/abc"), None);

        // x-forwarded-for: first value only; absent/blank -> "unknown".
        let h = vec![(
            "X-Forwarded-For".to_string(),
            "203.0.113.7, 10.0.0.2".into(),
        )];
        assert_eq!(auth::client_ip(&h), "203.0.113.7");
        let h = vec![("x-forwarded-for".into(), "   ".into())];
        assert_eq!(auth::client_ip(&h), "unknown");
        assert_eq!(auth::client_ip(&[]), "unknown");
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
        let headers = vec![("X-Forwarded-For".to_string(), format!("{ip}, 10.0.0.1"))];

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

        // No x-forwarded-for -> "unknown" -> limiting skipped (never 429).
        for _ in 0..25 {
            let r = call(
                &store,
                &cfg,
                "POST",
                "/auth/login",
                vec![],
                json!({"admin_key": "wrong"}),
            )
            .await;
            assert_eq!(r.status, 401);
        }
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
}
