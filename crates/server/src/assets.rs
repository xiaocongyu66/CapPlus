//! Asset serving (published releases and the CDN cache) and the verified
//! embed loader (`/embed.js` + the iframe page).

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cap_core::{jwt_sign, random_hex};
use cap_store::now_ms;
use serde_json::json;

use crate::http_util::{cors_origins, html_response};
use crate::AppState;

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
            // `v` is already the (still encoded) value: decoding it as a
            // query string would treat the whole thing as a key and yield an
            // empty value, so wrap it in a pair before parsing.
            form_urlencoded::parse(format!("v={v}").as_bytes())
                .next()
                .map(|(_, val)| val.into_owned())
                .unwrap_or_default()
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

    // The context carries a random session id: challenge and redeem both
    // present it, so a token solved in one embed session cannot be redeemed
    // from another. Two hours covers a long-open page; after it expires the
    // iframe gets a fresh one on the next load. It only ever names a session,
    // never grants anything by itself.
    let context = jwt_sign(
        &json!({
            "typ": "embed", "sk": site_key, "parent": parent_origin,
            "sid": random_hex(32),
            "exp": now_ms() + 2 * 60 * 60 * 1000,
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
