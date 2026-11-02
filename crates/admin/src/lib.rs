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
mod keys_stats;
mod keys_validate;
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
    /// Client address, already resolved by the host server with its
    /// proxy-trust rules. Rate limiting keys on this; the admin crate never
    /// reads forwarded headers itself.
    pub peer: &'a str,
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
    if cfg.demo
        && let Some(resp) = demo_dispatch(req, &method, &body)
    {
        return add_security_headers(resp);
    }
    let resp = dispatch(store, cfg, req, &method, &scope, &body).await;
    add_security_headers(resp)
}

/// Unforgeable, request-local authorization bound to the store and site.
/// No public constructor and no generic authorized dispatch endpoint.
pub struct AuthorizedSiteDelete<'a> {
    store: &'a AdminStore,
    site: String,
}

pub fn deletion_incomplete(training: &str) -> AdminResponse {
    resp(503, json!({"success": false,
        "error": "Deletion incomplete; changes may already be committed. Retry this DELETE.",
        "deletion": {"state": "incomplete", "retryable": true,
            "training": training, "scope": "local-instance"}}))
}

pub async fn authorize_site_delete<'a>(
    store: &'a AdminStore, req: &AdminRequest<'_>,
) -> Result<AuthorizedSiteDelete<'a>, AdminResponse> {
    let segments: Vec<_> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let ["keys", site] = segments.as_slice() else { return Err(not_found()); };
    if req.method != "DELETE" { return Err(not_found()); }
    let scope = auth::authenticate(store, req).await?;
    if let Some(response) = auth::scope_guard("DELETE", req.path, &scope) {
        return Err(response);
    }
    Ok(AuthorizedSiteDelete { store, site: (*site).into() })
}

impl AuthorizedSiteDelete<'_> {
    /// Persist intent before any local side effect. Missing keys need a receipt.
    pub async fn prepare(&self) -> Result<(), AdminResponse> {
        match self.store.begin_site_delete(&self.site).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(not_found()),
            Err(_) => Err(deletion_incomplete("unknown")),
        }
    }

    /// Caller must first commit local training retirement on this instance.
    pub async fn finish(self) -> AdminResponse {
        let mut response = keys::finish_delete(self.store, &self.site).await;
        response.body["deletion"]["training"] = json!("committed");
        response
    }
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
            if method == "POST" {
                totp::setup(store).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa", "enable"] => {
            if method == "POST" {
                totp::enable(store, body).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa", "disable"] => {
            if method == "POST" {
                totp::disable(store, cfg, body).await
            } else {
                not_found()
            }
        }
        ["auth", "2fa"] => {
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
mod tests;
