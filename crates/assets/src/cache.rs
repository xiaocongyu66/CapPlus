use std::collections::HashMap;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::{content_type_or_default, MAX_BODY_BYTES};

/// Metadata about the last successful refresh.
#[derive(Debug, Clone, Default)]
struct Meta {
    last_update_ms: u64,
    widget_version: Option<String>,
    wasm_version: Option<String>,
}

/// In-memory cache of fetched asset bytes.
///
/// A missing asset returns `None`; the server is expected to answer 404 in
/// that case. Poisoned locks are recovered instead of panicking, so a panicking
/// reader can never take down asset serving.
#[derive(Debug)]
pub struct AssetCache {
    assets: RwLock<HashMap<&'static str, Vec<u8>>>,
    meta: RwLock<Meta>,
}

impl AssetCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn read_assets(&self) -> RwLockReadGuard<'_, HashMap<&'static str, Vec<u8>>> {
        self.assets.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_assets(&self) -> RwLockWriteGuard<'_, HashMap<&'static str, Vec<u8>>> {
        self.assets.write().unwrap_or_else(|e| e.into_inner())
    }

    fn read_meta(&self) -> RwLockReadGuard<'_, Meta> {
        self.meta.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_meta(&self) -> RwLockWriteGuard<'_, Meta> {
        self.meta.write().unwrap_or_else(|e| e.into_inner())
    }

    /// Fetch a cached asset with its content type. `None` means "not cached"
    /// (the server answers 404).
    pub fn get(&self, name: &str) -> Option<(Vec<u8>, &'static str)> {
        let assets = self.read_assets();
        let bytes = assets.get(name)?;
        Some((bytes.clone(), content_type_or_default(name)))
    }

    /// Cache an asset. Oversized bodies (> 32MB) are rejected (logged to
    /// stderr) rather than stored; this never panics.
    pub fn set(&self, name: &'static str, bytes: Vec<u8>) {
        if bytes.len() > MAX_BODY_BYTES {
            eprintln!(
                "📦 [asset server] refusing to cache {name}: {} bytes exceeds the {} byte cap",
                bytes.len(),
                MAX_BODY_BYTES
            );
            return;
        }
        self.write_assets().insert(name, bytes);
    }

    /// Drop a cached asset (e.g. one that is no longer servable upstream).
    pub fn remove(&self, name: &str) -> bool {
        self.write_assets().remove(name).is_some()
    }

    /// Whether the asset is currently cached.
    pub fn contains(&self, name: &str) -> bool {
        self.read_assets().contains_key(name)
    }

    /// Number of cached assets.
    pub fn len(&self) -> usize {
        self.read_assets().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total number of cached bytes across all assets.
    pub fn total_bytes(&self) -> usize {
        self.read_assets().values().map(|b| b.len()).sum()
    }

    /// UNIX milliseconds of the last refresh that stored at least one asset.
    pub fn last_update_ms(&self) -> u64 {
        self.read_meta().last_update_ms
    }

    /// The `(widget, wasm)` versions of the last successful refresh.
    pub fn versions(&self) -> Option<(String, String)> {
        let meta = self.read_meta();
        Some((meta.widget_version.clone()?, meta.wasm_version.clone()?))
    }

    pub(crate) fn set_last_update_ms(&self, ms: u64) {
        self.write_meta().last_update_ms = ms;
    }

    pub(crate) fn set_versions(&self, widget: String, wasm: String) {
        let mut meta = self.write_meta();
        meta.widget_version = Some(widget);
        meta.wasm_version = Some(wasm);
    }
}

impl Default for AssetCache {
    fn default() -> Self {
        Self {
            assets: RwLock::new(HashMap::new()),
            meta: RwLock::new(Meta::default()),
        }
    }
}
