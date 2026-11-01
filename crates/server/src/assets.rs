//! Asset serving (exclusive release or binary default) and the verified
//! embed loader (`/embed.js` + the iframe page).

use std::sync::Arc;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use cap_core::{jwt_sign, random_hex};
use cap_store::now_ms;
use serde_json::json;

use crate::http_util::{client_ip, cors_origins, html_response};
use crate::{rate_allowed, AppState, DEFAULT_RL_MAX, DEFAULT_RL_WINDOW_MS};

pub(crate) async fn asset_handler(
    State(st): State<AppState>,
    Path(name): Path<String>,
    req_headers: HeaderMap,
) -> Response {
    release_response(&st.releases, &name, &req_headers)
}

fn release_response(releases: &cap_assets::ReleaseStore, name: &str, req_headers: &HeaderMap) -> Response {
    // Never mix an explicit release with cached CDN or other-version assets.
    let file = match releases.resolve(name) {
        Ok(Some(file)) => file,
        Ok(None) => return (StatusCode::NOT_FOUND, "asset not found in selected release").into_response(),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "active asset configuration is unavailable").into_response(),
    };
    {
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
        (StatusCode::OK, headers, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_response_uses_one_source_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("cap-asset-route-{}", random_hex(16)));
        let releases = cap_assets::ReleaseStore::open(&dir).unwrap();
        releases.publish_builtin(crate::config::builtin_widget_zip(), "route-test").unwrap();
        let headers = HeaderMap::new();
        for name in ["widget.js", "cap_wasm_bg.wasm", "hashwx.wasm"] {
            assert_eq!(release_response(&releases, name, &headers).status(), StatusCode::OK, "{name}");
        }
        assert_eq!(release_response(&releases, "absent.wasm", &headers).status(), StatusCode::NOT_FOUND);
        // A configured partial release must not borrow widget.js from builtin.
        std::fs::create_dir_all(dir.join("releases/test-partial/dist")).unwrap();
        std::fs::write(dir.join("releases/test-partial/dist/only.txt"), b"only").unwrap();
        releases.activate("test-partial").unwrap();
        assert_eq!(release_response(&releases, "widget.js", &headers).status(), StatusCode::NOT_FOUND);
        assert_eq!(release_response(&releases, "only.txt", &headers).status(), StatusCode::OK);
        std::fs::write(dir.join("releases/active"), "missing-release").unwrap();
        let broken = cap_assets::ReleaseStore::open(&dir).unwrap();
        broken.publish_builtin(crate::config::builtin_widget_zip(), "route-test").unwrap();
        assert_eq!(release_response(&broken, "widget.js", &headers).status(), StatusCode::SERVICE_UNAVAILABLE);
        std::fs::remove_dir_all(dir).unwrap();
    }
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
    req_headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if !cap_embed::validate_site_key(&site_key) {
        return (StatusCode::BAD_REQUEST, "invalid site key").into_response();
    }
    // Each request either reads a key from Redis or mints a signed context, so
    // an unauthenticated loop over random site keys must be rate limited per
    // client like the challenge endpoint is.
    let ip = client_ip(&req_headers, &addr.ip().to_string());
    if !rate_allowed(&st, "embed", &ip, DEFAULT_RL_WINDOW_MS, DEFAULT_RL_MAX).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded",
        )
            .into_response();
    }
    let key = match st.cache.key(&st.store, &site_key).await {
        Some(k) => Arc::unwrap_or_clone(k),
        None => return (StatusCode::NOT_FOUND, "unknown site key").into_response(),
    };
    let query = query.unwrap_or_default();
    let parent = query
        .as_str()
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
    // The framing page may declare its theme; only the two known values are
    // passed through, anything else falls back to the default dark palette.
    let theme = query
        .as_str()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == "theme")
        .map(|(_, v)| {
            form_urlencoded::parse(format!("v={v}").as_bytes())
                .next()
                .map(|(_, val)| val.into_owned())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let theme = if theme == "light" { "light" } else { "dark" };

    let context = jwt_sign(
        &json!({
            "typ": "embed", "sk": site_key, "parent": parent_origin,
            "sid": random_hex(32),
            "exp": now_ms() + 2 * 60 * 60 * 1000,
        }),
        &key.jwt_secret,
    );
    let html = cap_embed::embed_page_with_context(
        &site_key, &parent_origin, &st.embed_widget_url, &context, theme,
    );
    html_response(
        StatusCode::OK,
        Some(&format!("frame-ancestors {frame_ancestors}")),
        html,
    )
}
