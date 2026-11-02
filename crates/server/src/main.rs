//! cap-server — axum wiring for the verified-embed-only Cap architecture.
//!
//!   GET  /health
//!   POST /:siteKey/challenge
//!   POST /:siteKey/redeem            (only accepts requests from the Cap origin)
//!   POST /:siteKey/siteverify        (Turnstile-compatible, consume-once)
//!   POST /turnstile/v0/siteverify    (alias; site key from the token prefix)
//!   POST /:siteKey/validate          (non-consuming)
//!   GET  /embed.js                   (parent loader, Cap origin)
//!   GET  /embed/:siteKey             (cross-origin verification iframe)
//!
//! Protocols: `sha256-pow` (v1), `hashwx` and `rsw` (v2), with optional
//! instrumentation probes.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

mod cache;
mod config;
mod http_util;
mod integrity;
mod admin_routes;
mod assets;
mod challenge;
mod demo;
mod pages;
mod redeem;
mod siteverify;
mod metrics_buf;
mod ratelimit;

use admin_routes::{
    ipdb_delete, ipdb_download, ipdb_progress, ipdb_put, ipdb_status, release_activate,
    release_archive, release_delete, release_upload, releases_list,
};
use assets::{asset_handler, embed_js, embed_page};
use challenge::challenge;
use demo::{demo_page, demo_verify};
use http_util::{cidr_match, client_ip, proxy_trusted};
use pages::{login_page, public_asset, root_page, share_page, tester_page};
use redeem::redeem;
use siteverify::{siteverify, siteverify_alias, validate};
mod v2;

// mimalloc: per-thread heaps cut allocator contention on the request path
// (short-lived Json/header/Bytes allocations dominate). Falls back to the
// system allocator only if this line is removed.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use cap_store::{now_ms, Store};

const CHALLENGE_TTL_MS: i64 = 15 * 60 * 1000;
const TOKEN_TTL_MS: i64 = 2 * 60 * 60 * 1000;
const DEFAULT_RL_MAX: i64 = 30;
const DEFAULT_RL_WINDOW_MS: i64 = 5_000;
/// `/redeem` per IP: generous for real users (one redeem per challenge) but it
/// caps how much verification work one client can request.
const REDEEM_RL_MAX: i64 = 60;
const REDEEM_RL_WINDOW_MS: i64 = 10_000;
/// Wrong answers allowed per challenge token before it is refused outright.
const REDEEM_MAX_FAILS: i64 = 5;

static SETTINGS: std::sync::OnceLock<config::Settings> = std::sync::OnceLock::new();


fn settings() -> &'static config::Settings {
    SETTINGS.get().expect("settings initialised in main")
}

#[derive(Clone)]
struct AppState {
    store: Store,
    embed_widget_url: String,
    admin: Option<cap_admin::AdminStore>,
    admin_cfg: Arc<cap_admin::AdminConfig>,
    releases: Arc<cap_assets::ReleaseStore>,
    kv: cap_kv::Kv,
    ipdb: Arc<cap_ipdb::IpDb>,
    cache: Arc<cache::ConfigCache>,
    limiter: Arc<ratelimit::LocalLimiter>,
    metrics: Arc<metrics_buf::MetricsBuffer>,
    /// `CAP_RL_MODE=redis` forces the shared Redis limiter.
    redis_ratelimit: bool,
    /// Built RSW minters keyed by (keypair fingerprint, t). Building one costs
    /// two full-size modpows; the keypair changes only when an admin
    /// regenerates it, so the fingerprint check is enough to stay correct.
    rsw_minters: Arc<std::sync::Mutex<std::collections::HashMap<(String, u64), Arc<cap_proto::RswMinter>>>>,
    /// Serialises first-use keypair generation so concurrent requests do not
    /// each generate (and overwrite) their own keypair.
    rsw_keygen: Arc<tokio::sync::Mutex<()>>,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------








// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// Readiness probe: the storage backend must answer within 2 seconds.
async fn health_check(State(st): State<AppState>) -> Response {
    match tokio::time::timeout(std::time::Duration::from_secs(2), st.kv.get("__health__")).await {
        Ok(Ok(_)) => (StatusCode::OK, Json(json!({"status": "ok"}))).into_response(),
        Ok(Err(e)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            { eprintln!("[health] storage error: {e}"); Json(json!({ "status": "degraded", "error": "storage unavailable" })) }
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded", "error": "storage timeout" })),
        )
            .into_response(),
    }
}

/// Drop credentials from a URL before it reaches the logs.
fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<invalid url>".into();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    format!("{scheme}://{host}{}", &rest[authority_end..])
}

/// Liveness probe: the process is up.
async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}
















/// Files an unauthenticated visitor may fetch: the login page needs its
/// stylesheet, fonts and the i18n script, and the flag sprites are public.
/// Mirrors `UNAUTHED_ALLOWLIST` in `standalone/src/static.js`.
const PUBLIC_UNAUTHED: [&str; 7] = [
    "logo-small.webp",
    "assets/ibm-plex-sans.woff2",
    "assets/lilex-regular.woff2",
    "assets/style.css",
    "assets/chart.js@4.5.0.min.js",
    "js/geo.js",
    "js/share.js",
];






















/// Permissive CORS for the challenge endpoints: the widget may run from a
/// different origin, and the JS server's CORS layer allows it by default.
/// Authentication still applies to the real (non-preflight) request.
async fn cors_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if req.method() == axum::http::Method::OPTIONS {
        let mut resp = Response::new(axum::body::Body::empty());
        *resp.status_mut() = StatusCode::NO_CONTENT;
        if let Some(origin) = &origin {
            if let Ok(v) = HeaderValue::from_str(origin) {
                let h = resp.headers_mut();
                h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
                h.insert(
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("GET, POST, OPTIONS"),
                );
                h.insert(
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    HeaderValue::from_static(
                        "content-type, authorization, x-requested-with, x-cap-client-ua, x-cap-client-host",
                    ),
                );
                h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("3600"));
                h.insert(header::VARY, HeaderValue::from_static("Origin"));
            }
        }
        return resp;
    }

    let mut resp = next.run(req).await;
    if let Some(origin) = origin {
        if let Ok(v) = HeaderValue::from_str(&origin) {
            resp.headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            resp.headers_mut()
                .insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
    resp
}


/// Check `blocked:<siteKey>` for an exact IP, a CIDR, or a country/ASN match
/// (the latter resolved through the local database or proxy headers).
async fn is_blocked(
    st: &AppState,
    site_key: &str,
    ip: &str,
    headers: &HeaderMap,
    headers_trusted: bool,
) -> Result<bool, ()> {
    let Some(list) = st.cache.blocked(&st.kv, site_key).await else {
        return Err(());
    };
    if list.is_empty() {
        if !list.expired.is_empty() {
            let refs: Vec<&str> = list.expired.iter().map(String::as_str).collect();
            let _ = st.kv.hdel_fields(&format!("blocked:{site_key}"), &refs).await;
        }
        return Ok(false);
    }
    if !list.expired.is_empty() {
        let refs: Vec<&str> = list.expired.iter().map(String::as_str).collect();
        let _ = st.kv.hdel_fields(&format!("blocked:{site_key}"), &refs).await;
    }
    // O(1) for an exact IP; CIDRs are usually a handful of entries.
    if list.ips.contains(ip) {
        return Ok(true);
    }
    if list.cidrs.iter().any(|net| cidr_match(net, ip)) {
        return Ok(true);
    }
    if list.countries.is_empty() && list.asns.is_empty() {
        return Ok(false);
    }

    // Header-configured values win, then the local database.
    let cfg = st.cache.setting_checked(&st.kv, "settings:headers").await.map_err(|_| ())?;
    let header_val = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let country = if headers_trusted {
        header_val(cfg.get("countryHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };
    let asn = if headers_trusted {
        header_val(cfg.get("asnHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };
    let (db_country, db_asn) = match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => cap_ipdb::lookup(&st.ipdb, addr),
        Err(_) => (None, None),
    };
    let country = country.or(db_country);
    let asn = asn.or(db_asn.map(|n| n.to_string()));

    if let Some(c) = country {
        if list.countries.contains(&c) {
            return Ok(true);
        }
    }
    if let Some(a) = asn {
        if list.asns.contains(&a) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Load the RSW keypair, generating it on first use (the JS server does the
/// same at key creation and at challenge time). Read through the 1 s config
/// cache path would be wrong here (it is a hash, not JSON), so it is one
/// HGETALL per call; the expensive part, the minter, is cached separately.
async fn ensure_rsw_keypair(st: &AppState) -> Result<std::collections::HashMap<String, String>, String> {
    let load = || async {
        st.store
            .hgetall("settings:rsw_keypair")
            .await
            .map_err(|e| e.to_string())
    };
    let fields = load().await?;
    if !fields.is_empty() {
        return Ok(fields);
    }
    let _guard = st.rsw_keygen.lock().await;
    // Another request may have generated it while we waited.
    let fields = load().await?;
    if !fields.is_empty() {
        return Ok(fields);
    }
    let bits = settings().rsw_bits.max(512) & !1; // even, at least 512
    let pair = tokio::task::spawn_blocking(move || cap_proto::generate_keypair(bits))
        .await
        .map_err(|e| e.to_string())?;
    let pairs = [
        ("N", pair.n.to_str_radix(10)),
        ("p", pair.p.to_str_radix(10)),
        ("q", pair.q.to_str_radix(10)),
        ("bits", pair.bits.to_string()),
        ("created", now_ms().to_string()),
    ];
    st.kv
        .hset_pairs("settings:rsw_keypair", &pairs)
        .await
        .map_err(|e| e.to_string())?;
    eprintln!("[cap] generated the RSW keypair on first use");
    load().await
}

/// Cached minter for the current keypair and `t`; built on the blocking pool
/// on a miss.
async fn rsw_minter(
    st: &AppState,
    fields: std::collections::HashMap<String, String>,
    t: u64,
) -> Option<Arc<cap_proto::RswMinter>> {
    let fp = format!(
        "{}:{}",
        fields.get("created").map(String::as_str).unwrap_or(""),
        cap_core::sha256_hex(fields.get("N").map(String::as_str).unwrap_or(""))
    );
    let key = (fp, t);
    if let Some(m) = st.rsw_minters.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return Some(m.clone());
    }
    let minter = tokio::task::spawn_blocking(move || v2::rsw_minter(&fields, t))
        .await
        .ok()
        .flatten()
        .map(Arc::new)?;
    let mut map = st.rsw_minters.lock().unwrap_or_else(|e| e.into_inner());
    // A regenerated keypair makes every old entry dead; t values are clamped
    // to a small range, so this map stays tiny.
    map.retain(|(fp, _), _| *fp == key.0);
    map.insert(key, minter.clone());
    Some(minter)
}

/// Attribute a successful solve to a country / ASN. Explicit proxy headers
/// (configured in Settings → IP data) win over the local database.
async fn record_geo(st: &AppState, site_key: &str, headers: &HeaderMap, addr: &SocketAddr) {
    let ip = client_ip(headers, &addr.ip().to_string());
    let header = |name: &str| -> Option<String> {
        if name.is_empty() {
            return None;
        }
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let cfg = st.cache.setting(&st.kv, "settings:headers").await;

    // Geo headers are only trusted from a declared proxy: otherwise a client
    // could claim any country/ASN and dodge a country blocklist.
    let trusted = proxy_trusted(headers, &addr.ip().to_string());
    let country = if trusted {
        header(cfg.get("countryHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };
    let asn = if trusted {
        header(cfg.get("asnHeader").and_then(Value::as_str).unwrap_or(""))
    } else {
        None
    };

    let (db_country, db_asn) = match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => cap_ipdb::lookup(&st.ipdb, addr),
        Err(_) => (None, None),
    };

    if let Some(code) = country.or(db_country) {
        st.metrics
            .incr(&format!("metrics:country:{site_key}"), &code, 1);
    }
    if let Some(net) = asn.or(db_asn.map(|n| n.to_string())) {
        st.metrics
            .incr(&format!("metrics:asn:{site_key}"), &net, 1);
    }
}

// ---------------------------------------------------------------------------
// IP database settings (download, progress, delete)
// ---------------------------------------------------------------------------






// ---------------------------------------------------------------------------
// Front-end releases (upload a zip / list / activate / delete / download)
// ---------------------------------------------------------------------------









/// Fixed-window limiter in whichever mode is configured. A Redis error falls
/// back to the in-process limiter instead of letting the request through.
async fn rate_allowed(st: &AppState, scope: &str, ip: &str, window_ms: i64, max: i64) -> bool {
    if st.redis_ratelimit {
        if let Ok(ok) = st.store.rate_hit(scope, ip, window_ms, max).await {
            return ok;
        }
    }
    st.limiter.hit(scope, ip, window_ms, max)
}

async fn admin_handler(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(admin) = st.admin.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"success": false, "error": "admin API disabled (ADMIN_KEY unset)"})),
        )
            .into_response();
    };
    let path = uri.path();
    let admin_path = if let Some(rest) = path.strip_prefix("/server") {
        if rest.is_empty() {
            "/".to_string()
        } else {
            rest.to_string()
        }
    } else {
        path.to_string()
    };
    let header_pairs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
        .collect();
    // Resolved with the same proxy-trust rules as the public API, so the
    // admin login limiter cannot be dodged by spoofing forwarded headers.
    let peer_ip = client_ip(&headers, &peer.ip().to_string());
    let req = cap_admin::AdminRequest {
        method: method.as_str(),
        path: &admin_path,
        query: uri.query().unwrap_or(""),
        headers: &header_pairs,
        body: &body,
        peer: &peer_ip,
    };
    let resp = cap_admin::handle(admin, st.admin_cfg.as_ref(), &req).await;
    // A successful admin write must be visible immediately on this instance;
    // otherwise a revoked key keeps redeeming (and a new one 404s) for up to
    // the cache TTL.
    if resp.status < 300
        && !matches!(
            method,
            axum::http::Method::GET
                | axum::http::Method::HEAD
                | axum::http::Method::OPTIONS
        )
    {
        st.cache.clear();
    }
    let mut out_headers = HeaderMap::new();
    for (k, v) in &resp.headers {
        if let (Ok(name), Ok(value)) = (
            axum::http::header::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            out_headers.insert(name, value);
        }
    }
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, out_headers, Json(resp.body)).into_response()
}




#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::init()?;
    eprintln!("[cap] data directory: {}", cfg.data_dir.display());

    let kv = cap_kv::Kv::connect_redis(&cfg.redis_url).await?;
    eprintln!("[cap] storage: {} ({})", kv.backend_name(), redact_url(&cfg.redis_url));
    if !cfg.trust_proxy {
        eprintln!(
            "[cap] forwarding headers are ignored; behind a reverse proxy set CAP_TRUST_PROXY=true and CAP_PROXY_SECRET so per-IP limits and blocking work"
        );
    }

    let store = Store::new(kv.clone());
    let admin_cfg = cap_admin::AdminConfig {
        admin_key: cfg.admin_key.clone(),
        demo: cfg.demo,
    };
    let admin_store = if cfg.admin_key.is_empty() {
        None
    } else {
        Some(cap_admin::AdminStore::new(kv.clone()))
    };

    if cfg.cdn_fallback {
        eprintln!("[cap] ENABLE_ASSETS_SERVER/CDN fallback is deprecated and ignored; assets use the selected release or the embedded bundle");
    }

    let ipdb = Arc::new(
        cap_ipdb::IpDb::open(&cfg.data_dir.join("ipdb"), &cfg.tmp_dir())
            .map_err(|e| format!("cannot open ip database directory: {e}"))?,
    );
    if let Ok(Some(raw)) = kv.get("settings:ipdb").await {
        if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&raw) {
            let provider = doc
                .get("provider")
                .or_else(|| doc.get("mode"))
                .and_then(|v| v.as_str())
                .unwrap_or("none");
            if let Some(mode) = cap_ipdb::Mode::parse(provider) {
                ipdb.set_mode(mode);
            }
        }
    }
    eprintln!(
        "[cap] ip database: mode={}, country={}, asn={}",
        ipdb.mode().as_str(),
        ipdb.country_exists(),
        ipdb.asn_exists()
    );

    let releases = Arc::new(
        cap_assets::ReleaseStore::open(&cfg.data_dir)
            .map_err(|e| format!("cannot open releases directory: {e}"))?,
    );
    // Ship the compiled-in widget as the default release, so a fresh install
    // serves /assets/* locally instead of depending on the CDN.
    match releases.publish_builtin(config::builtin_widget_zip(), config::WIDGET_ID.trim()) {
        Ok(meta) => eprintln!(
            "[cap] built-in widget release: {} file(s), {} protected, active={}",
            meta.files, meta.protected, meta.active
        ),
        Err(e) => eprintln!("[cap] could not publish the built-in widget: {e}"),
    }

    let embed_widget_url = cfg.embed_widget_url.clone();
    let port = cfg.port;
    let _ = SETTINGS.set(cfg);

    let state = AppState {
        store,
        embed_widget_url,
        admin: admin_store,
        admin_cfg: Arc::new(admin_cfg),
        releases,
        kv,
        ipdb,
        cache: Arc::new(cache::ConfigCache::new()),
        limiter: Arc::new(ratelimit::LocalLimiter::new()),
        metrics: Arc::new(metrics_buf::MetricsBuffer::new()),
        rsw_minters: Default::default(),
        rsw_keygen: Default::default(),
        redis_ratelimit: std::env::var("CAP_RL_MODE")
            .map(|v| v.eq_ignore_ascii_case("redis"))
            .unwrap_or(false),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(health))
        .route("/embed.js", get(embed_js))
        .route("/embed/:siteKey", get(embed_page))
        .route("/assets/:name", get(asset_handler))
        .route("/", get(root_page))
        .route("/login", get(login_page))
        .route("/public/*rest", get(public_asset))
        .route("/demo", get(demo_page))
        .route(
            "/demo/verify",
            post(demo_verify).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/tester", get(tester_page))
        .route("/share", get(share_page))
        .route("/share/:token", get(admin_handler))
        .route("/share/:token/geo-stats", get(admin_handler))
        .route(
            "/server/settings/ipdb",
            get(ipdb_status)
                .put(ipdb_put)
                .post(ipdb_download)
                .delete(ipdb_delete),
        )
        .route("/server/settings/ipdb/download", post(ipdb_download))
        .route("/server/settings/ipdb/progress", get(ipdb_progress))
        .route(
            "/server/releases",
            get(releases_list).post(release_upload),
        )
        .route("/server/releases/:id/activate", post(release_activate))
        .route("/server/releases/:id/archive", get(release_archive))
        .route("/server/releases/:id", axum::routing::delete(release_delete))
        // Admin/JSON endpoints are small; capping them keeps an unauthenticated
        // caller from buffering the 64 MB upload allowance before auth runs.
        .route(
            "/auth/login",
            axum::routing::any(admin_handler)
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/server",
            axum::routing::any(admin_handler)
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/server/*rest",
            axum::routing::any(admin_handler)
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        // Public share links (no auth) live outside /server.
        .route(
            "/shares",
            axum::routing::any(admin_handler)
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/shares/:id",
            axum::routing::any(admin_handler)
                .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/turnstile/v0/siteverify",
            post(siteverify_alias).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/:siteKey/challenge",
            post(challenge).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/:siteKey/redeem",
            post(redeem).layer(axum::extract::DefaultBodyLimit::max(1024 * 1024)),
        )
        .route(
            "/:siteKey/siteverify",
            post(siteverify).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/:siteKey/validate",
            post(validate).layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        .layer(axum::middleware::from_fn(cors_layer))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024));

    // Flush buffered metric counters once per second, in one pipeline.
    {
        let metrics = state.metrics.clone();
        let kv = state.kv.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                let _ = metrics.flush(&kv).await;
            }
        });
    }

    // Expire stale rate-limit windows so the map cannot grow with the IP count.
    {
        let limiter = state.limiter.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                limiter.sweep();
            }
        });
    }

    let app = app.with_state(state);

    let host = settings().hostname.clone();
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|e| format!("invalid SERVER_HOSTNAME {host}: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("cap-server (rust) listening on http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
