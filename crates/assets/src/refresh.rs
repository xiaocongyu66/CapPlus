use crate::{asset_urls, now_ms, AssetCache, AssetConfig, MAX_BODY_BYTES};

/// Assets whose absence upstream is tolerated (the JS server merely logs a
/// warning for these instead of failing the whole refresh).
pub const OPTIONAL_ASSETS: &[&str] = &["hashwx.wasm"];

/// Fetch every asset into `cache`, using the configuration from the
/// environment (`CACHE_HOST`, `WIDGET_VERSION`, `WASM_VERSION`).
///
/// Returns `(updated, errors)` where `updated` is the number of assets stored
/// and `errors` holds `(asset_name, message)` for every failed fetch. Network
/// failures never panic; a missing asset is simply reported and left uncached.
pub fn refresh_blocking(
    cache: &AssetCache,
    fetcher: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> (usize, Vec<(String, String)>) {
    let cfg = AssetConfig::from_env();
    refresh_with_config(cache, &cfg, fetcher)
}

/// Like [`refresh_blocking`] but with an explicit configuration, so callers
/// (and tests) do not depend on process environment.
pub fn refresh_with_config(
    cache: &AssetCache,
    cfg: &AssetConfig,
    fetcher: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> (usize, Vec<(String, String)>) {
    let mut updated = 0usize;
    let mut errors: Vec<(String, String)> = Vec::new();
    let started_ms = now_ms();

    for (name, url) in asset_urls(&cfg.cache_host, &cfg.widget_version, &cfg.wasm_version) {
        match fetcher(&url) {
            Ok(bytes) if bytes.len() > MAX_BODY_BYTES => {
                errors.push((
                    name.to_string(),
                    format!(
                        "{url} returned {} bytes, exceeding the {MAX_BODY_BYTES} byte cap",
                        bytes.len()
                    ),
                ));
            }
            Ok(bytes) => {
                cache.set(name, bytes);
                updated += 1;
            }
            Err(err) => {
                errors.push((name.to_string(), err));
            }
        }
    }

    // Record the versions we attempted, and only bump last_update when we
    // actually stored something (mirrors the JS server, which keeps retrying
    // until a refresh succeeds).
    cache.set_versions(cfg.widget_version.clone(), cfg.wasm_version.clone());
    if updated > 0 {
        cache.set_last_update_ms(started_ms);
    }
    (updated, errors)
}
