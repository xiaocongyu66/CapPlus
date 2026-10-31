use std::collections::HashMap;

use cap_assets::{
    asset_urls, content_type_for, refresh_with_config, AssetCache, AssetConfig, ASSETS, MAX_BODY_BYTES,
};

fn cfg(host: &str, widget: &str, wasm: &str) -> AssetConfig {
    AssetConfig {
        cache_host: host.to_string(),
        widget_version: widget.to_string(),
        wasm_version: wasm.to_string(),
    }
}

fn urls_by_name(cfg: &AssetConfig) -> HashMap<&'static str, String> {
    asset_urls(&cfg.cache_host, &cfg.widget_version, &cfg.wasm_version)
        .into_iter()
        .collect()
}

/// A fake fetcher: returns canned bytes for known URLs, errors otherwise.
fn fake(
    bodies: HashMap<String, Result<Vec<u8>, String>>,
) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    move |url: &str| match bodies.get(url) {
        Some(Ok(bytes)) => Ok(bytes.clone()),
        Some(Err(err)) => Err(err.clone()),
        None => Err(format!("unexpected url in test: {url}")),
    }
}

fn ok_bodies(cfg: &AssetConfig) -> HashMap<String, Result<Vec<u8>, String>> {
    urls_by_name(cfg)
        .into_iter()
        .map(|(name, url)| {
            let body = format!("/* fake {name} */").into_bytes();
            (url, Ok(body))
        })
        .collect()
}

#[test]
fn url_matrix_pinned_versions_default_host() {
    let urls = urls_by_name(&cfg("https://cdn.jsdelivr.net", "1.2.3", "0.4.5"));
    assert_eq!(
        urls["widget.js"],
        "https://cdn.jsdelivr.net/npm/@cap.js/widget@1.2.3"
    );
    assert_eq!(
        urls["cap_wasm.js"],
        "https://cdn.jsdelivr.net/npm/@cap.js/wasm@0.4.5/browser/cap_wasm.min.js"
    );
    assert_eq!(
        urls["cap_wasm_bg.wasm"],
        "https://cdn.jsdelivr.net/npm/@cap.js/wasm@0.4.5/browser/cap_wasm_bg.wasm"
    );
    assert_eq!(
        urls["hashwx.wasm"],
        "https://cdn.jsdelivr.net/npm/@cap.js/wasm@0.4.5/browser/hashwx.wasm"
    );
}

#[test]
fn url_matrix_latest_versions_and_custom_host() {
    let urls = urls_by_name(&cfg("https://cdn.example.test/edge", "latest", "latest"));
    assert_eq!(
        urls["widget.js"],
        "https://cdn.example.test/edge/npm/@cap.js/widget@latest"
    );
    assert_eq!(
        urls["cap_wasm_bg.wasm"],
        "https://cdn.example.test/edge/npm/@cap.js/wasm@latest/browser/cap_wasm_bg.wasm"
    );
}

#[test]
fn trailing_slash_in_host_is_normalized() {
    let a = urls_by_name(&cfg("https://cdn.example.test/", "1.0.0", "1.0.0"));
    let b = urls_by_name(&cfg("https://cdn.example.test", "1.0.0", "1.0.0"));
    assert_eq!(a, b);
    assert!(!a["widget.js"].contains("test//"));
}

#[test]
fn asset_urls_covers_every_asset_in_order() {
    let names: Vec<_> = asset_urls("h", "w", "m").into_iter().map(|(n, _)| n).collect();
    let expected: Vec<_> = ASSETS.iter().map(|s| s.name).collect();
    assert_eq!(names, expected);
    assert_eq!(names.len(), 4);
}

#[test]
fn content_type_mapping() {
    for spec in ASSETS {
        assert_eq!(content_type_for(spec.name), Some(spec.content_type));
        let expected = if spec.name.ends_with(".wasm") {
            "application/wasm"
        } else {
            "application/javascript"
        };
        assert_eq!(spec.content_type, expected, "bad type for {}", spec.name);
    }
    assert_eq!(content_type_for("widget.js"), Some("application/javascript"));
    assert_eq!(content_type_for("floating.js"), Some("application/javascript"));
    assert_eq!(content_type_for("hashwx.wasm"), Some("application/wasm"));
    assert_eq!(content_type_for("nope.bin"), None);
}

#[test]
fn cache_get_set_len_remove() {
    let cache = AssetCache::new();
    assert!(cache.is_empty());
    assert!(cache.get("widget.js").is_none());

    cache.set("widget.js", b"console.log(1)".to_vec());
    let (bytes, ctype) = cache.get("widget.js").expect("cached");
    assert_eq!(bytes, b"console.log(1)");
    assert_eq!(ctype, "application/javascript");

    cache.set("cap_wasm_bg.wasm", vec![0, 1, 2, 3]);
    assert_eq!(cache.len(), 2);
    let (_, wasm_type) = cache.get("cap_wasm_bg.wasm").unwrap();
    assert_eq!(wasm_type, "application/wasm");

    assert!(cache.remove("widget.js"));
    assert!(!cache.remove("widget.js"));
    assert_eq!(cache.len(), 1);
}

#[test]
fn cache_rejects_oversized_body_without_panicking() {
    let cache = AssetCache::new();
    cache.set("widget.js", vec![0u8; MAX_BODY_BYTES + 1]);
    assert!(cache.get("widget.js").is_none());
    assert_eq!(cache.len(), 0);
}

#[test]
fn refresh_success_populates_every_asset() {
    let cfg = cfg("https://cdn.jsdelivr.net", "1.2.3", "0.4.5");
    let bodies = ok_bodies(&cfg);
    let cache = AssetCache::new();

    let (updated, errors) = refresh_with_config(&cache, &cfg, &fake(bodies));
    assert_eq!(updated, 4);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    assert_eq!(cache.len(), 4);

    let (widget, ctype) = cache.get("widget.js").unwrap();
    assert_eq!(widget, b"/* fake widget.js */");
    assert_eq!(ctype, "application/javascript");
    assert_eq!(cache.versions(), Some(("1.2.3".to_string(), "0.4.5".to_string())));
    assert!(cache.last_update_ms() > 0);
}

#[test]
fn refresh_partial_failure_reports_errors_and_keeps_good_assets() {
    let cfg = cfg("https://cdn.jsdelivr.net", "1.0.0", "1.0.0");
    let mut bodies = ok_bodies(&cfg);
    let hashwx_url = urls_by_name(&cfg)["hashwx.wasm"].clone();
    bodies.insert(hashwx_url, Err("404 not found".to_string()));

    let cache = AssetCache::new();
    let (updated, errors) = refresh_with_config(&cache, &cfg, &fake(bodies));

    assert_eq!(updated, 3);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, "hashwx.wasm");
    assert!(errors[0].1.contains("404"));
    assert!(cache.get("widget.js").is_some());
    assert!(cache.get("hashwx.wasm").is_none());
}

#[test]
fn refresh_total_failure_does_not_panic_or_bump_timestamp() {
    let cfg = cfg("https://cdn.jsdelivr.net", "1.0.0", "1.0.0");
    let cache = AssetCache::new();
    let (updated, errors) =
        refresh_with_config(&cache, &cfg, &|url: &str| Err(format!("boom: {url}")));
    assert_eq!(updated, 0);
    assert_eq!(errors.len(), 4);
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.last_update_ms(), 0);
}

#[test]
fn refresh_rejects_oversized_asset_offline() {
    // 33MB body served for widget.js: rejected, other assets still cached.
    let cfg = cfg("https://cdn.jsdelivr.net", "1.0.0", "1.0.0");
    let mut bodies = ok_bodies(&cfg);
    let widget_url = urls_by_name(&cfg)["widget.js"].clone();
    bodies.insert(widget_url, Ok(vec![9u8; 33 * 1024 * 1024]));

    let cache = AssetCache::new();
    let (updated, errors) = refresh_with_config(&cache, &cfg, &fake(bodies));

    assert_eq!(updated, 3);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, "widget.js");
    assert!(errors[0].1.contains("cap"), "unexpected error: {}", errors[0].1);
    assert!(cache.get("widget.js").is_none());
    assert!(cache.total_bytes() < MAX_BODY_BYTES);
}

#[test]
fn refresh_keeps_previous_body_when_a_later_fetch_fails() {
    let cfg = cfg("https://cdn.jsdelivr.net", "1.0.0", "1.0.0");
    let cache = AssetCache::new();
    let bodies = ok_bodies(&cfg);
    let (updated, _) = refresh_with_config(&cache, &cfg, &fake(bodies));
    assert_eq!(updated, 4);

    // Second refresh where widget.js fails but others succeed.
    let mut bodies = ok_bodies(&cfg);
    let widget_url = urls_by_name(&cfg)["widget.js"].clone();
    bodies.insert(widget_url, Err("timeout".to_string()));
    let (updated, errors) = refresh_with_config(&cache, &cfg, &fake(bodies));
    assert_eq!(updated, 3);
    assert_eq!(errors.len(), 1);
    assert_eq!(cache.get("widget.js").unwrap().0, b"/* fake widget.js */");
}
