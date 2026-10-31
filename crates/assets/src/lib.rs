//! Static asset cache for the Cap widget bundle.
//!
//! The Cap server serves the widget bundle itself so the embed iframe can load
//! `/assets/widget.js` from the Cap origin. The JS implementation fetches the
//! bundle from a CDN once and caches it in Redis; this crate provides the same
//! behaviour as a pure library: an in-memory cache plus a background refresher.
//!
//! It deliberately has no HTTP server dependency (no axum). The HTTP fetch is
//! abstracted behind a plain `Fn(&str) -> Result<Vec<u8>, String>` so the whole
//! crate can be tested offline.
//!
//! Mirrors `standalone/src/assets.js`:
//!   widget.js        <- {CACHE_HOST}/npm/@cap.js/widget@{WIDGET_VERSION}
//!   cap_wasm.js      <- {CACHE_HOST}/npm/@cap.js/wasm@{WASM_VERSION}/browser/cap_wasm.min.js
//!   cap_wasm_bg.wasm <- {CACHE_HOST}/npm/@cap.js/wasm@{WASM_VERSION}/browser/cap_wasm_bg.wasm
//!   hashwx.wasm      <- {CACHE_HOST}/npm/@cap.js/wasm@{WASM_VERSION}/browser/hashwx.wasm

mod cache;
mod protect;
mod release;
mod zip;
mod fetch;
mod refresh;
mod runtime;

use std::time::{SystemTime, UNIX_EPOCH};

pub use cache::AssetCache;
pub use protect::{is_protected, protect_js, MARKER as PROTECT_MARKER};
pub use release::{ReleaseMeta, ReleaseStore, ServedFile};
pub use zip::{read_zip, sanitize_path, ZipEntry};
pub use fetch::{http_fetcher, read_capped, MAX_BODY_BYTES};
pub use refresh::{refresh_blocking, refresh_with_config, OPTIONAL_ASSETS};
pub use runtime::{spawn_refresher, CACHE_CONFIG_KEY, DEFAULT_REFRESH_INTERVAL};

/// Default CDN used when `CACHE_HOST` is not set.
pub const DEFAULT_CACHE_HOST: &str = "https://cdn.jsdelivr.net";
/// Default widget/wasm version when the env vars are not set.
pub const DEFAULT_VERSION: &str = "latest";

const CONTENT_TYPE_JS: &str = "application/javascript";
const CONTENT_TYPE_WASM: &str = "application/wasm";
const CONTENT_TYPE_FALLBACK: &str = "application/octet-stream";

/// One servable asset: the name it is cached/served under, the CDN path
/// template (relative to the cache host) and the content type to send.
///
/// `path_template` uses `{widget}` / `{wasm}` placeholders that are substituted
/// with the widget and wasm versions respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetSpec {
    pub name: &'static str,
    pub path_template: &'static str,
    pub content_type: &'static str,
}

impl AssetSpec {
    /// Build the full upstream URL for this asset.
    pub fn url(&self, cache_host: &str, widget_version: &str, wasm_version: &str) -> String {
        let host = cache_host.trim_end_matches('/');
        let path = self
            .path_template
            .replace("{widget}", widget_version)
            .replace("{wasm}", wasm_version);
        format!("{host}{path}")
    }
}

/// The assets served under `/assets/*`, mirroring the JS asset server
/// (`widget.js`, `cap_wasm.js`, `cap_wasm_bg.wasm`, `hashwx.wasm`).
pub const ASSETS: &[AssetSpec] = &[
    AssetSpec {
        name: "widget.js",
        path_template: "/npm/@cap.js/widget@{widget}",
        content_type: CONTENT_TYPE_JS,
    },
    AssetSpec {
        name: "cap_wasm.js",
        path_template: "/npm/@cap.js/wasm@{wasm}/browser/cap_wasm.min.js",
        content_type: CONTENT_TYPE_JS,
    },
    AssetSpec {
        name: "cap_wasm_bg.wasm",
        path_template: "/npm/@cap.js/wasm@{wasm}/browser/cap_wasm_bg.wasm",
        content_type: CONTENT_TYPE_WASM,
    },
    AssetSpec {
        name: "hashwx.wasm",
        path_template: "/npm/@cap.js/wasm@{wasm}/browser/hashwx.wasm",
        content_type: CONTENT_TYPE_WASM,
    },
];

/// Configuration for where assets come from. Mirrors the env-driven config of
/// the JS server (`CACHE_HOST`, `WIDGET_VERSION`, `WASM_VERSION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetConfig {
    pub cache_host: String,
    pub widget_version: String,
    pub wasm_version: String,
}

impl Default for AssetConfig {
    fn default() -> Self {
        Self {
            cache_host: DEFAULT_CACHE_HOST.to_string(),
            widget_version: DEFAULT_VERSION.to_string(),
            wasm_version: DEFAULT_VERSION.to_string(),
        }
    }
}

impl AssetConfig {
    /// Read the configuration from the environment, falling back to the same
    /// defaults as the JS server. Warns (stderr) when a `latest` version is in
    /// use, exactly like the JS server does.
    pub fn from_env() -> Self {
        let cfg = Self {
            cache_host: env_or("CACHE_HOST", DEFAULT_CACHE_HOST),
            widget_version: env_or("WIDGET_VERSION", DEFAULT_VERSION),
            wasm_version: env_or("WASM_VERSION", DEFAULT_VERSION),
        };
        cfg.warn_on_latest();
        cfg
    }

    /// Emit the same production warning the JS server emits for `latest`.
    pub fn warn_on_latest(&self) {
        if self.widget_version == "latest" || self.wasm_version == "latest" {
            eprintln!(
                "📦 [asset server] using 'latest' version for assets is not recommended for production!\n   \
                 make sure to pin it to a set version using the WIDGET_VERSION and WASM_VERSION env variables."
            );
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Build the `(name, url)` pairs for every known asset.
pub fn asset_urls(
    cache_host: &str,
    widget_version: &str,
    wasm_version: &str,
) -> Vec<(&'static str, String)> {
    ASSETS
        .iter()
        .map(|spec| (spec.name, spec.url(cache_host, widget_version, wasm_version)))
        .collect()
}

/// Look up the spec for an asset by name.
pub fn asset_spec(name: &str) -> Option<&'static AssetSpec> {
    ASSETS.iter().find(|s| s.name == name)
}

/// Content type for a served asset name, including the `floating.js` widget
/// variant that the JS server also serves.
pub fn content_type_for(name: &str) -> Option<&'static str> {
    if let Some(spec) = asset_spec(name) {
        return Some(spec.content_type);
    }
    match name {
        "floating.js" => Some(CONTENT_TYPE_JS),
        n if n.ends_with(".wasm") => Some(CONTENT_TYPE_WASM),
        n if n.ends_with(".js") || n.ends_with(".mjs") => Some(CONTENT_TYPE_JS),
        _ => None,
    }
}

pub(crate) fn content_type_or_default(name: &str) -> &'static str {
    content_type_for(name).unwrap_or(CONTENT_TYPE_FALLBACK)
}

/// Current UNIX time in milliseconds (0 if the clock is before the epoch).
/// Short random hex suffix for release ids.
pub(crate) fn random_suffix() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn default_config_matches_js_defaults() {
        let cfg = AssetConfig::default();
        assert_eq!(cfg.cache_host, "https://cdn.jsdelivr.net");
        assert_eq!(cfg.widget_version, "latest");
        assert_eq!(cfg.wasm_version, "latest");
    }

    #[test]
    fn assets_cover_all_served_endpoints() {
        let names: Vec<_> = ASSETS.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec!["widget.js", "cap_wasm.js", "cap_wasm_bg.wasm", "hashwx.wasm"]
        );
    }

    #[test]
    fn unset_env_key_falls_back() {
        assert_eq!(env_or("CAP_ASSETS_TEST_UNSET_KEY_XYZ", "fallback"), "fallback");
    }
}
