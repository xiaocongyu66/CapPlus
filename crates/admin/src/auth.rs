//! Login + request authentication + scope guard. Mirrors `auth.js` and the
//! `scopeGuard` in `server.js`.

use serde_json::{Value, json};

use crate::util;
use crate::{
    AdminConfig, AdminRequest, AdminResponse, AdminStore, Scope, header, internal, ok, resp,
};

const SESSION_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000; // 30 days

/// Fixed-window login rate limit: 200 attempts per 20 s (matches auth.js).
const LOGIN_MAX: i64 = 200;
const LOGIN_WINDOW_MS: i64 = 20_000;

/// Whether the client reached us over HTTPS (directly or via a proxy).
/// Drives the `Secure` cookie attribute: setting it on a plain-HTTP install
/// makes every browser drop the cookie, which leaves the panel stuck on the
/// login page.
fn request_is_https(headers: &[(String, String)]) -> bool {
    for name in ["x-forwarded-proto", "x-forwarded-scheme", "x-url-scheme"] {
        if let Some(v) = header(headers, name) {
            // The proxy's own hop is last when it appends, so a client cannot
            // prepend `http` to drop the Secure attribute.
            if v.rsplit(',')
                .map(|p| p.trim())
                .find(|p| !p.is_empty())
                .is_some_and(|p| p.eq_ignore_ascii_case("https"))
            {
                return true;
            }
        }
    }
    header(headers, "x-forwarded-ssl")
        .map(|v| v.eq_ignore_ascii_case("on"))
        .unwrap_or(false)
}

pub(crate) fn request_is_https_pub(headers: &[(String, String)]) -> bool {
    request_is_https(headers)
}

/// Redis key holding a cookie's session binding:
/// `cookiesess:<sha256(hashed_token)>` → `"1"`, TTL = session TTL.
pub fn cookie_session_key(value: &str) -> String {
    format!("cookiesess:{value}")
}

/// Opaque cookie value for a session (hash of the argon2 hash, so the cookie
/// is hex-only and never reveals the token).
pub(crate) fn cookie_value(hashed_token: &str) -> String {
    util::sha256_hex(hashed_token)
}

/// `cap_authed` cookie; `value = None` clears it.
pub(crate) fn auth_cookie(value: Option<&str>, expires: Option<i64>, https: bool) -> String {
    let secure = if https { "; Secure" } else { "" };
    match (value, expires) {
        (Some(v), Some(ms)) => format!(
            "cap_authed={v}; Expires={}; HttpOnly{secure}; SameSite=Lax; Path=/",
            util::http_date(ms)
        ),
        _ => format!(
            "cap_authed=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly{secure}; SameSite=Lax; Path=/"
        ),
    }
}

fn unauth(msg: &str) -> AdminResponse {
    resp(401, json!({ "success": false, "error": msg }))
}

/// `POST /auth/login` — verifies the admin key, mints a session token, stores
/// its argon2 hash in `session:<hash>` (TTL 30d) and registers it in `sessions`.
///
/// Rate limiting: fixed window per client IP ([`AdminRequest::peer`]), key
/// `rl:login:<ip>:<LOGIN_WINDOW_MS>:<window>`, allowed while
/// `count <= LOGIN_MAX`. It is never skipped.
pub(crate) async fn login(
    store: &AdminStore,
    cfg: &AdminConfig,
    req: &AdminRequest<'_>,
) -> AdminResponse {
    if cfg.demo {
        return ok(json!({ "success": true, "demo": true }));
    }

    let ip = req.peer;
    {
        let window = util::now_ms() / LOGIN_WINDOW_MS;
        let key = format!("rl:login:{ip}:{LOGIN_WINDOW_MS}:{window}");
        let count = match store.incr(&key).await {
            Ok(c) => c,
            Err(_) => return internal(),
        };
        if count == 1 {
            let _ = store.expire(&key, LOGIN_WINDOW_MS / 1000 + 1).await;
        }
        if count > LOGIN_MAX {
            return resp(
                429,
                json!({ "success": false, "error": "Too many attempts" }),
            );
        }
    }

    let body = crate::parse_body(req.body);
    let provided = body.get("admin_key").and_then(|v| v.as_str()).unwrap_or("");

    if !util::admin_key_eq(&cfg.admin_key, provided) {
        return resp(401, json!({ "success": false, "error": "Incorrect admin key" }));
    }

    match crate::totp::check_second_factor(store, &body).await {
        Ok(true) => {}
        Ok(false) => return internal(),
        Err(resp) => return resp,
    }

    let session_token = util::random_hex(30);
    let now = util::now_ms();
    let expires = now + SESSION_TTL_MS;
    let created = now;

    let hashed_token = match util::argon2_hash_async(&session_token).await {
        Ok(h) => h,
        Err(_) => return internal(),
    };
    let ttl_seconds = ((expires - now) as f64 / 1000.0).ceil() as i64;

    let payload = json!({ "created": created, "expires": expires }).to_string();
    if store
        .set_ex(&format!("session:{hashed_token}"), &payload, ttl_seconds)
        .await
        .is_err()
    {
        return internal();
    }
    if store.sadd("sessions", &hashed_token).await.is_err() {
        return internal();
    }

    let mut r = ok(json!({
        "success": true,
        "session_token": session_token,
        "hashed_token": hashed_token,
        "expires": expires,
    }));
    // Bind the cookie to this session in Redis: a cookie copied from another
    // install (same host, different service) resolves to nothing here, so the
    // panel shows the login page instead of a broken half-session.
    let cookie_value = cookie_value(&hashed_token);
    if store
        .set_ex(&cookie_session_key(&cookie_value), "1", ttl_seconds)
        .await
        .is_err()
    {
        return internal();
    }
    r.headers.push((
        "Set-Cookie".into(),
        auth_cookie(Some(&cookie_value), Some(expires), request_is_https(req.headers)),
    ));
    r
}

/// Resolve the request's credentials.
/// - `Ok(None)`      → a full session
/// - `Ok(Some(scope))` → a `Bot` API key with its scope
/// - `Err(response)` → 401 (or 500 on redis failure)
pub(crate) async fn authenticate(
    store: &AdminStore,
    req: &AdminRequest<'_>,
) -> Result<Option<Scope>, AdminResponse> {
    let authorization = header(req.headers, "authorization");

    if let Some(auth) = authorization.as_deref() {
        if let Some(rest) = auth.strip_prefix("Bot ") {
            return authenticate_bot(store, rest.trim()).await;
        }
    }

    // Bearer session
    let bearer = match authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
    {
        Some(t) => t.trim().to_string(),
        None => {
            return Err(unauth(
                "Unauthorized. An API key or session token is required to use this endpoint.",
            ));
        }
    };

    let decoded =
        match util::b64_decode(&bearer).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            Some(v) => v,
            None => return Err(unauth("Unauthorized. Malformed session token.")),
        };

    let token = decoded.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let hash = decoded.get("hash").and_then(|v| v.as_str()).unwrap_or("");
    if hash.is_empty() {
        return Err(unauth("Unauthorized. Malformed session token."));
    }

    let raw = match store.get(&format!("session:{hash}")).await {
        Ok(Some(d)) => d,
        Ok(None) => return Err(unauth("Unauthorized. An invalid session token was used.")),
        Err(_) => return Err(internal()),
    };

    let parsed: Value = serde_json::from_str(&raw).unwrap_or_else(|_| json!({}));
    let expires = parsed.get("expires").and_then(|v| v.as_i64()).unwrap_or(0);
    if expires <= util::now_ms() {
        let _ = store.del(&format!("session:{hash}")).await;
        let _ = store.srem("sessions", hash).await;
        return Err(unauth("Unauthorized. An invalid session token was used."));
    }

    if !util::argon2_verify_async(token, hash).await {
        return Err(unauth("Unauthorized. An invalid session token was used."));
    }

    Ok(None)
}

async fn authenticate_bot(
    store: &AdminStore,
    bot_token: &str,
) -> Result<Option<Scope>, AdminResponse> {
    let (id, token) = match bot_token.split_once('_') {
        Some(pair) => pair,
        None => return Err(unauth("Unauthorized. Invalid bot token.")),
    };
    if id.is_empty() || token.is_empty() {
        return Err(unauth("Unauthorized. Invalid bot token."));
    }

    let fields = match store
        .hmget(
            &format!("apikey:{id}"),
            &["tokenHash", "siteKeys", "readonly"],
        )
        .await
    {
        Ok(f) => f,
        Err(_) => return Err(internal()),
    };
    let token_hash = match fields.first().and_then(|v| v.clone()) {
        Some(h) if !h.is_empty() => h,
        _ => return Err(unauth("Unauthorized. Deleted or non-existent bot token.")),
    };

    if !util::argon2_verify_async(token, &token_hash).await {
        return Err(unauth("Unauthorized. Invalid bot token."));
    }

    let site_keys = fields
        .get(1)
        .and_then(|v| v.clone())
        .map(|s| serde_json::from_str::<Vec<String>>(&s).unwrap_or_default());
    let readonly = fields.get(2).and_then(|v| v.as_deref()) == Some("true");

    Ok(Some(Scope {
        site_keys,
        readonly,
    }))
}

/// Authorise a non-JSON request (multipart/zip upload, file download) as an
/// admin session. Bot API keys are rejected: publishing the front-end is a
/// global action.
pub async fn require_session(
    store: &AdminStore,
    headers: &[(String, String)],
) -> Result<(), AdminResponse> {
    let req = AdminRequest {
        peer: "127.0.0.1",
        method: "POST",
        path: "/releases",
        query: "",
        headers,
        body: b"",
    };
    match authenticate(store, &req).await {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(resp(
            403,
            json!({ "success": false, "error": "Forbidden. A session token is required." }),
        )),
        Err(r) => Err(r),
    }
}

/// `scopeGuard`: readonly ⇒ only GET/HEAD; a scoped key may only touch
/// `/keys/:siteKey` whose key is in its list, plus `GET /keys`.
pub(crate) fn scope_guard(
    method: &str,
    path: &str,
    scope: &Option<Scope>,
) -> Option<AdminResponse> {
    let scope = scope.as_ref()?;
    let is_read = method == "GET" || method == "HEAD";
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // API keys manage site data only. Everything global (settings, other API
    // keys, sessions, 2FA, integrity baseline, ipdb) needs an admin session:
    // otherwise a leaked unscoped key could mint new keys or rewrite CORS and
    // rate limits.
    if !matches!(segs.first().copied(), Some("keys" | "shares" | "about")) {
        return Some(resp(
            403,
            json!({ "success": false, "error": "Forbidden. Session token required." }),
        ));
    }

    if scope.readonly && !is_read {
        return Some(resp(
            403,
            json!({ "success": false, "error": "Forbidden. This API key is read-only." }),
        ));
    }

    let site_keys = scope.site_keys.as_ref()?;

    // Share routes are passed through here; the fine-grained site-key check
    // (body.siteKey on create, share owner on delete, per-key filtering on
    // list) lives in `shares.rs` because it needs the body / stored hash.
    if segs.first().copied() == Some("shares") {
        return None;
    }

    if segs.len() >= 2 && segs[0] == "keys" {
        if site_keys.iter().any(|k| k == segs[1]) {
            return None;
        }
    } else if is_read && path == "/keys" {
        return None;
    }

    Some(resp(
        403,
        json!({ "success": false, "error": "Forbidden. This API key is not scoped to this site key." }),
    ))
}
