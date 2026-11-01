//! Asset serving (published releases and the CDN cache) and the verified
//! embed loader (`/embed.js` + the iframe page).

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cap_core::jwt_sign;
use cap_store::now_ms;
use serde_json::json;

use crate::http_util::{cors_origins, html_response};
use crate::{AppState, CHALLENGE_TTL_MS};

pub(crate) async fn asset_handler(
    State(st): State<AppState>,
    Path(name): Path<String>,
    req_headers: HeaderMap,
) -> Response {
    // A published release always wins over the CDN cache.
    if let Some(file) = st.releases.get(&name) {
        let accepts_gzip = req_headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("gzip"))
            .unwrap_or(false);
        let (body, encoded) = match (accepts_gzip, file.gzip) {
            (true, Some(gz)) => (gz, true),
            _ => (file.plain, false),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(file.content_type),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        if encoded {
            headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_static("gzip"),
            );
        }
        return (StatusCode::OK, headers, body).into_response();
    }
    let Some((bytes, content_type)) = st.assets.get(&name) else {
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain; charset=utf-8")],
            "asset not cached yet (set ENABLE_ASSETS_SERVER=true and wait for the first refresh)",
        )
            .into_response();
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    (StatusCode::OK, headers, bytes).into_response()
}

pub(crate) async fn embed_js() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    (StatusCode::OK, headers, cap_embed::loader_js()).into_response()
}

pub(crate) async fn embed_page(
    State(st): State<AppState>,
    Path(site_key): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    if !cap_embed::validate_site_key(&site_key) {
        return (StatusCode::BAD_REQUEST, "invalid site key").into_response();
    }
    let key = match st.cache.key(&st.store, &site_key).await {
        Some(k) => Arc::unwrap_or_clone(k),
        None => return (StatusCode::NOT_FOUND, "unknown site key").into_response(),
    };
    let parent = query
        .unwrap_or_default()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "parent")
        .map(|(_, v)| {
            form_urlencoded::parse(v.as_bytes())
                .map(|(_, val)| val.to_string())
                .collect::<String>()
        })
        .unwrap_or_default();

    let policy = cap_embed::frame_policy(&cors_origins(&key.config), &parent);
    let (frame_ancestors, parent_origin) = match policy {
        // Use the canonical origin for postMessage as well, never the raw
        // query value.
        cap_embed::FramePolicy::Allow(origin) => (origin.clone(), origin),
        cap_embed::FramePolicy::Deny => {
            return html_response(
                StatusCode::FORBIDDEN,
                Some("frame-ancestors 'none'"),
                "embedding not allowed for this origin".into(),
            )
        }
    };

    let context = jwt_sign(
        &json!({
            "typ": "embed", "sk": site_key, "parent": parent_origin,
            "exp": now_ms() + CHALLENGE_TTL_MS,
        }),
        &key.jwt_secret,
    );
    let html = cap_embed::embed_page_with_context(
        &site_key, &parent_origin, &st.embed_widget_url, &context,
    );
    html_response(
        StatusCode::OK,
        Some(&format!("frame-ancestors {frame_ancestors}")),
        html,
    )
}
