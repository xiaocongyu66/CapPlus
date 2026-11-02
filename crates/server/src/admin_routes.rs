//! Admin-facing routes that are implemented in this crate rather than
//! proxied to `cap-admin`: IP database management and release uploads.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::AppState;

pub(crate) async fn ipdb_status(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let stored = st
        .kv
        .get("settings:ipdb")
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);
    let mode = st.ipdb.mode();
    let progress = st.ipdb.progress();
    json_resp(
        StatusCode::OK,
        json!({
            "mode": mode.as_str(),
            "provider": mode.as_str(),
            "configured": mode != cap_ipdb::Mode::None,
            "country": if st.ipdb.country_exists() {
                json!({ "exists": true, "size": st.ipdb.country_size() })
            } else {
                json!({ "exists": false })
            },
            "asn": if st.ipdb.asn_exists() {
                json!({ "exists": true, "size": st.ipdb.asn_size() })
            } else {
                json!({ "exists": false })
            },
            "loaded": {
                "country": st.ipdb.country_exists(),
                "asn": st.ipdb.asn_exists(),
            },
            "lastUpdated": stored.get("updatedAt").cloned().unwrap_or(Value::Null),
            "error": progress.error,
            "progress": {
                "active": progress.active,
                "file": progress.file,
                "downloaded": progress.downloaded,
                "total": progress.total,
            },
            "sources": {
                "maxmind": {
                    "accountIdSet": stored.get("maxmindAccountId").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false),
                    "keySet": stored.get("maxmindKey").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false),
                },
                "ipinfo": {
                    "tokenSet": stored.get("ipinfoToken").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false),
                },
            },
        }),
    )
}

pub(crate) async fn ipdb_put(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "Invalid body" }),
        );
    };
    let provider = payload
        .get("provider")
        .or_else(|| payload.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or("none");
    let Some(mode) = cap_ipdb::Mode::parse(provider) else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "provider must be none, dbip, maxmind or ipinfo" }),
        );
    };

    let mut doc = serde_json::Map::new();
    doc.insert("provider".into(), json!(mode.as_str()));
    doc.insert("mode".into(), json!(mode.as_str()));
    for field in ["maxmindAccountId", "maxmindKey", "ipinfoToken"] {
        if let Some(v) = payload.get(field)
            && let Some(s) = v.as_str()
        {
            doc.insert(field.into(), json!(s));
        }
    }
    doc.insert(
        "updatedAt".into(),
        json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
    );
    let raw = Value::Object(doc).to_string();
    if st.kv.set("settings:ipdb", &raw).await.is_err() {
        return json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "storage error" }),
        );
    }
    json_resp(StatusCode::OK, json!({ "success": true }))
}

pub(crate) async fn ipdb_download(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let payload: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let stored = st
        .kv
        .get("settings:ipdb")
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or(Value::Null);

    let provider = payload
        .get("provider")
        .or_else(|| payload.get("mode"))
        .and_then(Value::as_str)
        .or_else(|| stored.get("provider").and_then(Value::as_str))
        .unwrap_or("none");
    let Some(mode) = cap_ipdb::Mode::parse(provider) else {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "unknown provider" }),
        );
    };
    if mode == cap_ipdb::Mode::None {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "pick a provider first" }),
        );
    }

    let pick = |name: &str| -> String {
        payload
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .or_else(|| {
                stored
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default()
    };
    let creds = cap_ipdb::Credentials {
        maxmind_account_id: pick("maxmindAccountId"),
        maxmind_key: pick("maxmindKey"),
        ipinfo_token: pick("ipinfoToken"),
    };

    // Persist credentials alongside the provider.
    if let Value::Object(obj) = &payload {
        let mut doc = stored.as_object().cloned().unwrap_or_default();
        for (k, v) in obj {
            if matches!(k.as_str(), "maxmindAccountId" | "maxmindKey" | "ipinfoToken") {
                doc.insert(k.clone(), v.clone());
            }
        }
        doc.insert("provider".into(), json!(mode.as_str()));
        doc.insert("mode".into(), json!(mode.as_str()));
        let _ = st.kv.set("settings:ipdb", &Value::Object(doc).to_string()).await;
    }

    if !st.ipdb.start_download(mode, creds) {
        return json_resp(
            StatusCode::CONFLICT,
            json!({ "success": false, "error": "A download is already running" }),
        );
    }
    json_resp(StatusCode::OK, json!({ "success": true, "started": true }))
}

pub(crate) async fn ipdb_progress(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let p = st.ipdb.progress();
    json_resp(
        StatusCode::OK,
        json!({
            "active": p.active,
            "file": p.file,
            "downloaded": p.downloaded,
            "total": p.total,
            "error": p.error,
        }),
    )
}

pub(crate) async fn ipdb_delete(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let _ = st.kv.del("settings:ipdb").await;
    let _ = std::fs::remove_file(st.ipdb.country_path());
    let _ = std::fs::remove_file(st.ipdb.asn_path());
    st.ipdb.reload();
    st.ipdb.set_mode(cap_ipdb::Mode::None);
    json_resp(StatusCode::OK, json!({ "success": true }))
}

pub(crate) fn json_resp(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

pub(crate) fn admin_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
        .collect()
}

pub(crate) async fn require_admin(st: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(admin) = st.admin.as_ref() else {
        return Err(Box::new(json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "success": false, "error": "Admin API is not configured" }),
        )));
    };
    match cap_admin::require_session(admin, &admin_headers(headers)).await {
        Ok(()) => Ok(()),
        Err(r) => Err(Box::new(json_resp(
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::UNAUTHORIZED),
            r.body,
        ))),
    }
}

/// `GET /server/releases` — published bundles, newest first.
pub(crate) async fn releases_list(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    json_resp(
        StatusCode::OK,
        json!({
            "releases": st.releases.list(),
            "active": st.releases.active_release_id(),
        }),
    )
}

/// `POST /server/releases` — body is the zip archive itself
/// (`Content-Type: application/zip`, or anything else: the bytes are sniffed).
pub(crate) async fn release_upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    if body.is_empty() {
        return json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": "Empty upload" }),
        );
    }
    let store = Arc::clone(&st.releases);
    match tokio::task::spawn_blocking(move || store.publish(&body)).await {
        Ok(Ok(meta)) => json_resp(StatusCode::OK, json!({ "success": true, "release": meta })),
        Ok(Err(e)) => json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "success": false, "error": e }),
        ),
        Err(_) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "publish task failed" }),
        ),
    }
}

/// `POST /server/releases/:id/activate` — switch (or roll back) to a release.
pub(crate) async fn release_activate(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let store = Arc::clone(&st.releases);
    let id_for_task = id.clone();
    match tokio::task::spawn_blocking(move || store.activate(&id_for_task)).await {
        Ok(Ok(())) => json_resp(StatusCode::OK, json!({ "success": true, "active": id })),
        Ok(Err(e)) => json_resp(StatusCode::BAD_REQUEST, json!({ "success": false, "error": e })),
        Err(_) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "activate task failed" }),
        ),
    }
}

/// `DELETE /server/releases/:id`
pub(crate) async fn release_delete(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    let store = Arc::clone(&st.releases);
    let id_for_task = id.clone();
    match tokio::task::spawn_blocking(move || store.delete(&id_for_task)).await {
        Ok(Ok(())) => json_resp(StatusCode::OK, json!({ "success": true })),
        Ok(Err(e)) => json_resp(StatusCode::BAD_REQUEST, json!({ "success": false, "error": e })),
        Err(_) => json_resp(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "success": false, "error": "delete task failed" }),
        ),
    }
}

/// `GET /server/releases/:id/archive` — the original uploaded zip.
pub(crate) async fn release_archive(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin(&st, &headers).await {
        return *r;
    }
    match st.releases.source_zip(&id) {
        Some(bytes) => {
            let mut out = HeaderMap::new();
            out.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            let safe_id: String = id
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(64)
                .collect();
            out.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{safe_id}.zip\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            (StatusCode::OK, out, bytes).into_response()
        }
        None => json_resp(
            StatusCode::NOT_FOUND,
            json!({ "success": false, "error": "archive not found" }),
        ),
    }
}
