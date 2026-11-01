//! Dashboard shell: pages, static files and the login-gated admin panel.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::{settings, AppState, PUBLIC_UNAUTHED};

/// The dashboard frontend, served from the configured directory, deployed
/// assets, or the repository's `frontend/` during development.
/// `ADMIN_LEGACY_DIR` (or `dashboard_dir` in config.toml) overrides the directory.
pub(crate) fn dashboard_root() -> std::path::PathBuf {
    if let Some(dir) = &settings().dashboard_dir {
        return dir.clone();
    }
    let mut candidates: Vec<std::path::PathBuf> = vec![
        // Inside the data directory, for self-contained deployments.
        settings().data_dir.join("dashboard"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("dashboard"));
        }
    }
    // Repository frontend for development builds.
    candidates.push(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frontend"));
    candidates.push("./static/admin".into());

    for p in candidates {
        if p.join("index.html").is_file() {
            return p;
        }
    }
    std::path::PathBuf::from("dashboard")
}

pub(crate) fn is_unauthed_public(rel: &str) -> bool {
    PUBLIC_UNAUTHED.contains(&rel)
        || rel == "js/i18n.js"
        || rel.starts_with("assets/flags/")
}

pub(crate) fn content_type_for(rel: &str) -> &'static str {
    match rel.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

/// The `cap_authed` cookie's value, if the request carries one.
pub(crate) fn auth_cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())?;
    raw.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == "cap_authed").then(|| v.trim().to_string())
    })
}

/// A cookie only counts when its session binding still exists in *this*
/// install's Redis. A stale `cap_authed=yes` (from the JS server or an
/// earlier build) resolves to nothing, so the visitor gets the login page
/// instead of a dashboard that cannot load any data.
pub(crate) async fn cookie_authed(st: &AppState, headers: &HeaderMap) -> bool {
    let Some(value) = auth_cookie_value(headers) else {
        return false;
    };
    if value.is_empty() {
        return false;
    }
    let Some(admin) = st.admin.as_ref() else {
        return false;
    };
    admin
        .kv_exists(&cap_admin::cookie_session_key(&value))
        .await
        .unwrap_or(false)
}

pub(crate) async fn serve_dashboard_file(rel: &str, cache: &'static str) -> Response {
    let root = dashboard_root();
    // Resolve inside the root only; `.` and `..` are rejected outright, as in
    // `static.js`.
    let safe = !rel.is_empty()
        && !rel.contains('\0')
        && !rel.split('/').any(|seg| seg == ".." || seg == ".");
    if !safe {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let candidate = root.join(rel);
    let ok = match (std::fs::canonicalize(&root), std::fs::canonicalize(&candidate)) {
        (Ok(base), Ok(path)) => path.starts_with(&base),
        _ => false,
    };
    if !ok {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let bytes = match tokio::fs::read(&candidate).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let mut out = HeaderMap::new();
    out.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type_for(rel)),
    );
    out.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if rel.ends_with(".html") {
        out.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        out.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors 'none'"),
        );
        out.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        );
    }
    (StatusCode::OK, out, bytes).into_response()
}

/// `GET /` — the dashboard when `cap_authed=yes`, the login page otherwise
/// (the same switch `standalone/src/index.js` makes).
pub(crate) async fn root_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let page = if st.admin_cfg.demo || cookie_authed(&st, &headers).await {
        "index.html"
    } else {
        "login.html"
    };
    serve_dashboard_file(page, "no-cache").await
}

pub(crate) async fn login_page() -> Response {
    serve_dashboard_file("login.html", "no-cache").await
}

/// `GET /tester` — the challenge tester: solve against a site key and watch
/// the solver log (progress, timing, token, siteverify result).
pub(crate) async fn tester_page() -> Response {
    serve_dashboard_file("tester.html", "no-cache").await
}

/// `GET /public/*` — assets behind the same authentication gate as the JS
/// server: unauthenticated visitors only get the login page's own files.
pub(crate) async fn public_asset(State(st): State<AppState>, Path(rel): Path<String>, headers: HeaderMap) -> Response {
    let rel = rel.trim_start_matches('/').to_string();
    let allowed = is_unauthed_public(&rel)
        || st.admin_cfg.demo
        || cookie_authed(&st, &headers).await;
    if !allowed {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    // Revalidate on every load: the panel ships inside the binary, so a
    // stale cached script after an upgrade would break the UI.
    let cache = "no-cache";
    serve_dashboard_file(&rel, cache).await
}

/// `GET /share/:token` — the public share page (its token lives in the URL hash).
pub(crate) async fn share_page() -> Response {
    serve_dashboard_file("share.html", "no-cache").await
}
