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
mod business;
mod demo;
mod pages;
mod redeem;
mod siteverify;
mod metrics_buf;
mod ratelimit;
mod training;
mod training_capture;
mod training_routes;

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
    training: Option<training::TrainingService>,
    /// `CAP_RL_MODE=redis` forces the shared Redis limiter.
    redis_ratelimit: bool,
    /// Capacity-32, singleflight CRT minters keyed by the complete canonical
    /// keypair, time parameter and algorithm domain. Never cache minted proofs.
    rsw_minters: moka::future::Cache<String, Arc<cap_proto::RswMinter>>,
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
    let segments: Vec<_> = req.uri().path().split('/').filter(|s| !s.is_empty()).collect();
    if matches!(segments.as_slice(), ["server", "keys", _, "training", ..]) {
        // Same-origin management only. Apply even to routing/extraction errors,
        // trailing/repeated slashes, and OPTIONS intercepted by this outer layer.
        let mut response = if req.method() == axum::http::Method::OPTIONS {
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        } else {
            next.run(req).await
        };
        response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
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
    // Expired snapshots are CAS-cleaned once in the cache loader.
    if list.is_empty() {
        return Ok(false);
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
    // No unbounded async lock queue. At most one coordinator exists per process.
    let guard = st.rsw_keygen.clone().try_lock_owned().map_err(|_| "cpu_busy".to_string())?;
    let bits = settings().rsw_bits.max(512) & !1;
    let kv = st.kv.clone();
    let (mut tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = async {
            let fields = kv.hgetall("settings:rsw_keypair").await.map_err(|e| e.to_string())?;
            if !fields.is_empty() { return Ok(fields); }
            if tx.is_closed() { return Err("cpu_cancelled".to_string()); }
            // The blocking closure owns the guard too: runtime shutdown cannot
            // release it while prime generation is still running.
            let (pair, _guard) = tokio::select! {
                biased;
                _ = tx.closed() => return Err("cpu_cancelled".to_string()),
                result = cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::General, move || {
                    (cap_proto::generate_keypair(bits), guard)
                }) => result.map_err(|e| cpu_error_code(e).to_string())?,
            };
            if tx.is_closed() { return Err("cpu_cancelled".to_string()); }
            let pairs = [
                ("N", pair.n.to_str_radix(10)),
                ("p", pair.p.to_str_radix(10)),
                ("q", pair.q.to_str_radix(10)),
                ("bits", pair.bits.to_string()),
                ("created", now_ms().to_string()),
            ];
            // Atomic absent-only publication never overwrites an admin rotation.
            // Reuse the existing Redis 7 ACL-preflight primitive; the auxiliary
            // index has exactly one member, not one member per generation.
            kv.hcreate_indexed("settings:rsw_keypair", &pairs,
                "settings:generated-keypairs", "settings:rsw_keypair")
                .await.map_err(|e| e.to_string())?;
            kv.hgetall("settings:rsw_keypair").await.map_err(|e| e.to_string())
        }.await;
        let _ = tx.send(result);
    });
    rx.await.map_err(|_| "cpu_unavailable".to_string())?
}

/// Cached minter for the current keypair and `t`; built on the blocking pool
/// on a miss.
async fn rsw_minter(
    st: &AppState,
    fields: std::collections::HashMap<String, String>,
    t: u64,
) -> Result<Arc<cap_proto::RswMinter>, Arc<String>> {
    let key = rsw_cache_key(&fields, t).map_err(Arc::new)?;
    bounded_cache_get(&st.rsw_minters, key, async move {
        cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::General, move || v2::rsw_minter(&fields, t))
            .await.map_err(|e| cpu_error_code(e).to_string())?
            .map(Arc::new).ok_or_else(|| "rsw_keypair_unavailable".to_string())
    }).await
}

async fn bounded_cache_get<T: Send + Sync + 'static>(
    cache: &moka::future::Cache<String, Arc<T>>,
    key: String,
    build: impl std::future::Future<Output = Result<Arc<T>, String>>,
) -> Result<Arc<T>, Arc<String>> {
    if let Some(value) = cache.get(&key).await { return Ok(value); }
    // Bound singleflight followers too, not just CPU jobs on distinct misses.
    static ADMISSION: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(20);
    let _permit = ADMISSION.try_acquire().map_err(|_| Arc::new("cpu_busy".to_string()))?;
    cache.try_get_with(key, build).await
}

#[cfg(test)]
mod cpu_wiring_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn cpu_overload_is_not_an_invalid_proof() {
        assert_eq!(cpu_error_code(cap_kv::cpu::CpuError::Busy), "cpu_busy");
        assert_eq!(cpu_error_response(cap_kv::cpu::CpuError::Busy).status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(cpu_error_response(cap_kv::cpu::CpuError::WorkerFailed).status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn cache_key_covers_all_parameters_and_canonicalizes() {
        let fields: std::collections::HashMap<String, String> =
            [("N", "15"), ("p", "3"), ("q", "5"), ("bits", "4"), ("created", "1")]
                .into_iter().map(|(k,v)| (k.into(), v.into())).collect();
        let key = rsw_cache_key(&fields, 10).unwrap();
        for name in ["N", "p", "q", "bits", "created"] {
            let mut changed = fields.clone();
            changed.insert(name.into(), "99".into());
            assert_ne!(key, rsw_cache_key(&changed, 10).unwrap());
            changed.insert(name.into(), format!("00{}", fields[name]));
            assert_eq!(key, rsw_cache_key(&changed, 10).unwrap());
        }
        assert_ne!(key, rsw_cache_key(&fields, 11).unwrap());
    }

    #[tokio::test]
    async fn cache_singleflight_failure_retry_and_capacity() {
        let cache = moka::future::Cache::new(32);
        let builds = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let (cache, builds, gate) = (cache.clone(), builds.clone(), gate.clone());
            jobs.push(tokio::spawn(async move {
                bounded_cache_get(&cache, "same".into(), async {
                    builds.fetch_add(1, Ordering::SeqCst);
                    gate.notified().await;
                    Ok(Arc::new(7usize))
                }).await.unwrap()
            }));
        }
        while builds.load(Ordering::SeqCst) == 0 { tokio::task::yield_now().await; }
        gate.notify_one();
        for job in jobs { assert_eq!(*job.await.unwrap(), 7); }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        for _ in 0..2 {
            assert!(bounded_cache_get(&cache, "bad".into(), async {
                builds.fetch_add(1, Ordering::SeqCst);
                Err("failure".into())
            }).await.is_err());
        }
        assert_eq!(builds.load(Ordering::SeqCst), 3);
        assert!(cache.get(&"bad".to_string()).await.is_none());
        for i in 0..100 {
            bounded_cache_get(&cache, i.to_string(), async { Ok(Arc::new(i)) }).await.unwrap();
        }
        cache.run_pending_tasks().await;
        assert!(cache.entry_count() <= 32);
    }

    #[tokio::test]
    async fn old_cache_completion_does_not_remove_new_generation() {
        use std::{future::Future, task::Poll};
        let cache = moka::future::Cache::new(32);
        let (release, wait) = tokio::sync::oneshot::channel();
        let mut old = Box::pin(bounded_cache_get(&cache, "old".into(), async {
            wait.await.unwrap();
            Ok(Arc::new(1usize))
        }));
        std::future::poll_fn(|cx| {
            assert!(old.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        bounded_cache_get(&cache, "new".into(), async { Ok(Arc::new(2)) }).await.unwrap();
        release.send(()).unwrap();
        assert_eq!(*old.await.unwrap(), 1);
        assert_eq!(*cache.get(&"new".to_string()).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn cancelled_keygen_keeps_lock_and_cpu_budget_until_worker_finishes() {
        let scheduler = Arc::new(cap_kv::cpu::CpuScheduler::new(cap_kv::cpu::CpuConfig {
            total: 1, argon: 1, waiters: 0, ..Default::default()
        }).unwrap());
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let guard = lock.clone().try_lock_owned().unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_scheduler = scheduler.clone();
        let job = tokio::spawn(async move {
            worker_scheduler.run(cap_kv::cpu::CpuClass::General, move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                guard
            }).await
        });
        started_rx.await.unwrap();
        job.abort();
        let _ = job.await;
        assert!(lock.clone().try_lock_owned().is_err());
        assert_eq!(scheduler.run(cap_kv::cpu::CpuClass::General, || ()).await,
            Err(cap_kv::cpu::CpuError::Busy));
        release_tx.send(()).unwrap();
        let _done = lock.lock().await;
    }
}

fn cpu_error_code(error: cap_kv::cpu::CpuError) -> &'static str {
    match error {
        cap_kv::cpu::CpuError::Busy => "cpu_busy",
        _ => "cpu_unavailable",
    }
}

fn cpu_error_response(error: cap_kv::cpu::CpuError) -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({"error": cpu_error_code(error)}))).into_response()
}

/// Canonical unsigned decimal fields, length-delimited JSON and algorithm
/// domain separation. Never log this preimage (it contains private factors).
fn rsw_cache_key(fields: &std::collections::HashMap<String, String>, t: u64) -> Result<String, String> {
    let mut parts = vec!["cap-rsw-crt-v1".to_string()];
    for name in ["N", "p", "q", "bits", "created"] {
        let value = fields.get(name).ok_or("rsw_keypair_unavailable")?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("rsw_keypair_unavailable".into());
        }
        let canonical = value.trim_start_matches('0');
        parts.push(if canonical.is_empty() { "0" } else { canonical }.to_string());
    }
    parts.push(t.to_string());
    Ok(cap_core::sha256_hex(&serde_json::to_string(&parts).expect("string serialization")))
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
    let segments: Vec<_> = admin_path.split('/').filter(|s| !s.is_empty()).collect();
    let site_delete = method == axum::http::Method::DELETE
        && matches!(segments.as_slice(), ["keys", _]) && !st.admin_cfg.demo;
    let resp = if site_delete {
        match cap_admin::authorize_site_delete(admin, &req).await {
            Err(response) => response,
            Ok(authorized) => {
                // Authentication precedes both intent and local side effects.
                // Completion covers this instance only, not other processes with
                // independent in-memory writers (even with a shared directory).
                if let Some(training) = st.training.as_ref() {
                    match authorized.prepare().await {
                        Err(response) => response,
                        Ok(()) => match training.delete_site(segments[1]).await {
                            Ok(_) => authorized.finish().await,
                            Err(_) => {
                                let phase = match training.status(segments[1]).await {
                                    Ok(status) if status.tombstoned => "committed",
                                    _ => "unknown",
                                };
                                cap_admin::deletion_incomplete(phase)
                            },
                        },
                    }
                } else {
                    cap_admin::deletion_incomplete("unknown")
                }
            }
        }
    } else {
        cap_admin::handle(admin, st.admin_cfg.as_ref(), &req).await
    };
    // Includes lost replies / partial commits, not just successful writes.
    if site_delete && resp.body.get("deletion").is_some() {
        st.cache.clear();
    }
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
    cap_kv::cpu::init_from_env()?;
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

    // Recovery and the exclusive local file lock must not block the executor.
    let training_dir = cfg.data_dir.join("training");
    let training = match tokio::task::spawn_blocking(move || training::TrainingService::open(training_dir)).await {
        Ok(Ok(service)) => Some(service),
        result => {
            eprintln!("[cap] training storage unavailable; collection disabled: {}",
                match result { Ok(Err(e)) => e.to_string(), Err(e) => e.to_string(), _ => unreachable!() });
            None
        }
    };

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
        training,
        rsw_minters: moka::future::Cache::new(32),
        rsw_keygen: Default::default(),
        redis_ratelimit: std::env::var("CAP_RL_MODE")
            .map(|v| v.eq_ignore_ascii_case("redis"))
            .unwrap_or(false),
    };

    let app = Router::new()
        .merge(training_routes::router())
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
            "/demo/credential",
            post(demo::demo_credential).layer(axum::extract::DefaultBodyLimit::max(16 * 1024)),
        )
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
            "/:siteKey/business-credential",
            post(business::issue).layer(axum::extract::DefaultBodyLimit::max(16 * 1024)),
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

    // 回收只发生在后台，避免满表请求反复触发持锁全表扫描。
    {
        let limiter = state.limiter.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut rounds = 0u8;
            let mut previous = (0, 0);
            loop {
                tick.tick().await;
                limiter.sweep();
                rounds += 1;
                if rounds == 60 {
                    let current = limiter.rejection_counts();
                    if current.0 != previous.0 {
                        eprintln!("[cap] local limiter rejections: capacity={}, quota={}",
                            current.0.saturating_sub(previous.0),
                            current.1.saturating_sub(previous.1));
                    }
                    previous = current;
                    rounds = 0;
                }
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
