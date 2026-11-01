//! Widget front-end releases.
//!
//! Each published bundle lives in `<data>/releases/<id>/`:
//!
//! ```text
//! releases/
//! ├── active                    id of the served release
//! ├── <id>/
//! │   ├── source.zip            the uploaded archive, kept for re-deploys
//! │   ├── raw/                  files exactly as uploaded
//! │   └── dist/                 files as served (JS protected automatically)
//! ```
//!
//! Older releases stay on disk, so publishing keeps a rollback history:
//! activating a previous id serves it again instantly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use std::io::Write;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::protect::{is_protected, protect_js};
use crate::zip::{read_zip, ZipError};
use crate::{content_type_for, now_ms};

const ACTIVE_FILE: &str = "active";
/// Fixed id of the bundle compiled into the binary.
pub const BUILTIN_ID: &str = "builtin";
const META_FILE: &str = "meta.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseMeta {
    pub id: String,
    pub created: i64,
    /// Number of files in the bundle.
    pub files: usize,
    /// Uncompressed size of the served files.
    pub bytes: usize,
    /// How many files were obfuscated + encrypted on publish.
    pub protected: usize,
    pub active: bool,
    /// Bundled with the binary; cannot be deleted.
    #[serde(default)]
    pub builtin: bool,
    /// Fingerprint of the bundled payload, so an upgrade re-publishes it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build_id: String,
    /// Public URL of the widget entry point, when one is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
}

/// One served file: the original bytes plus a precompressed variant.
#[derive(Debug, Clone)]
pub struct ServedFile {
    pub plain: Bytes,
    pub gzip: Option<Bytes>,
    pub content_type: &'static str,
}

/// Defence in depth: even though `zip::read_zip` sanitises names, a release
/// store must never build a path from archive input without checking it.
fn safe_rel(name: &str) -> Option<std::path::PathBuf> {
    if name.is_empty() || name.contains('\0') || name.contains('\\') {
        return None;
    }
    let p = std::path::Path::new(name);
    if p.is_absolute() {
        return None;
    }
    if p.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(p.to_path_buf())
}

/// Files of the active release, ready to serve.
#[derive(Debug, Default)]
struct ActiveFiles {
    id: String,
    files: HashMap<String, ServedFile>,
    error: Option<String>,
}

/// Compressible types worth a gzip variant (already-encrypted JS is not: its
/// payload is base64 of ciphertext and gzip would make it larger).
fn should_gzip(name: &str, data: &[u8]) -> bool {
    if data.len() < 1024 || is_protected(data) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    [".wasm", ".js", ".mjs", ".css", ".json", ".html", ".svg", ".txt", ".map"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

fn gzip_bytes(data: &[u8]) -> Option<Bytes> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(data).ok()?;
    let out = encoder.finish().ok()?;
    // Only keep it when it actually helps.
    (out.len() < data.len()).then(|| Bytes::from(out))
}

#[derive(Debug)]
pub struct ReleaseStore {
    root: PathBuf,
    active: RwLock<ActiveFiles>,
    builtin: RwLock<HashMap<String, ServedFile>>,
}

impl ReleaseStore {
    /// Open `<data_dir>/releases`, creating it, and load the active release.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let root = data_dir.join("releases");
        std::fs::create_dir_all(&root)
            .map_err(|e| format!("cannot create {}: {e}", root.display()))?;
        let store = Self {
            root,
            active: RwLock::new(ActiveFiles::default()),
            builtin: RwLock::new(HashMap::new()),
        };
        if let Err(e) = store.reload_active() {
            eprintln!("[cap] could not load the active release: {e}");
            store.active.write().unwrap_or_else(|e| e.into_inner()).error = Some(e);
        }
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn active_id(&self) -> Result<Option<String>, String> {
        let path = self.root.join(ACTIVE_FILE);
        match std::fs::read_to_string(&path) {
            Ok(s) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
            Ok(_) => Err("active release marker is empty".into()),
            // A dangling symlink is configured, not an absent marker.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
                && matches!(std::fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) => Ok(None),
            Err(e) => Err(format!("cannot read active release marker: {e}")),
        }
    }

    /// Resolve a release directory, rejecting anything that is not a plain
    /// release id. Axum percent-decodes `:id`, so `..%2F..%2Ftmp` would
    /// otherwise escape `releases/` (read arbitrary files, delete outside).
    fn release_dir(&self, id: &str) -> PathBuf {
        let valid = id == BUILTIN_ID
            || (id.len() <= 64
                && id
                    .chars()
                    .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == '-')
                && id.split_once('-').is_some());
        if valid {
            self.root.join(id)
        } else {
            // A non-existent, private path: callers treat it as "no such id".
            self.root.join("__invalid__")
        }
    }

    /// Load `<id>/dist` into memory and mark it active.
    fn reload_active(&self) -> Result<(), String> {
        let Some(id) = self.active_id()? else {
            *self.active.write().unwrap_or_else(|e| e.into_inner()) = ActiveFiles::default();
            return Ok(());
        };
        let loaded = self.load_release(&id)?;
        *self.active.write().unwrap_or_else(|e| e.into_inner()) = loaded;
        Ok(())
    }

    fn load_release(&self, id: &str) -> Result<ActiveFiles, String> {
        if id == "__invalid__" || self.release_dir(id).file_name().and_then(|s| s.to_str()) != Some(id) {
            return Err("invalid active release id".into());
        }
        let dist = self.release_dir(id).join("dist");
        let mut files = HashMap::new();
        let mut stack = vec![dist.clone()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .map_err(|e| format!("cannot load release {id}: {e}"))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let path = entry.path();
                if entry.file_type().map_err(|e| e.to_string())?.is_symlink() {
                    return Err(format!("release {id} contains a symlink"));
                }
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let Ok(rel) = path.strip_prefix(&dist) else {
                    continue;
                };
                let key = rel.to_string_lossy().replace('\\', "/");
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("cannot read release {id} file {}: {e}", path.display()))?;
                let ct = content_type_for(&key).unwrap_or("application/octet-stream");
                let gzip = if should_gzip(&key, &bytes) {
                    gzip_bytes(&bytes)
                } else {
                    None
                };
                files.insert(
                    key,
                    ServedFile {
                        plain: Bytes::from(bytes),
                        gzip,
                        content_type: ct,
                    },
                );
            }
        }
        let entry = if files.contains_key("widget.js") {
            Some("widget.js".to_string())
        } else if files.contains_key("cap.min.js") {
            Some("cap.min.js".to_string())
        } else {
            None
        };
        if let Some(entry) = entry {
            eprintln!("[cap] release loaded: widget entry /assets/{entry}");
        }
        Ok(ActiveFiles { id: id.to_string(), files, error: None })
    }

    /// A file from the active release. Names are exact relative paths; a bare
    /// basename also resolves when it is unambiguous.
    pub fn get(&self, name: &str) -> Option<ServedFile> {
        self.resolve(name).ok().flatten()
    }

    /// Resolve exclusively within one release. Only an absent configuration
    /// selects the current binary's complete in-memory bundle.
    pub fn resolve(&self, name: &str) -> Result<Option<ServedFile>, String> {
        let active = self.active.read().unwrap_or_else(|e| e.into_inner());
        if let Some(error) = &active.error {
            return Err(error.clone());
        }
        let builtin = self.builtin.read().unwrap_or_else(|e| e.into_inner());
        let files = if active.id.is_empty() {
            if builtin.is_empty() {
                return Err("built-in assets are unavailable".into());
            }
            &*builtin
        } else {
            &active.files
        };
        Ok(Self::find_file(files, name))
    }

    fn find_file(files: &HashMap<String, ServedFile>, name: &str) -> Option<ServedFile> {
        if let Some(hit) = files.get(name) {
            return Some(hit.clone());
        }
        if name.contains('/') {
            return None;
        }
        let mut found = None;
        for (key, value) in files {
            if key.rsplit('/').next() == Some(name) {
                if found.is_some() {
                    return None; // ambiguous
                }
                found = Some(value.clone());
            }
        }
        found
    }

    pub fn active_release_id(&self) -> Option<String> {
        let active = self.active.read().unwrap_or_else(|e| e.into_inner());
        (!active.id.is_empty()).then(|| active.id.clone())
    }

    /// Publish an uploaded archive. Returns the new release's metadata; the
    /// new release becomes active unless another one was activated first.
    pub fn publish(&self, archive: &[u8]) -> Result<ReleaseMeta, String> {
        let entries = read_zip(archive).map_err(|e: ZipError| e.0)?;
        let id = format!("{}-{}", now_ms(), &crate::random_suffix());
        let dir = self.release_dir(&id);
        let (raw_dir, dist_dir) = (dir.join("raw"), dir.join("dist"));
        std::fs::create_dir_all(&raw_dir).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&dist_dir).map_err(|e| e.to_string())?;

        // Keep the archive so the release can be re-deployed or downloaded.
        std::fs::write(dir.join("source.zip"), archive).map_err(|e| e.to_string())?;

        let mut files = 0usize;
        let mut bytes = 0usize;
        let mut protected = 0usize;
        let mut entry = None;

        for item in entries {
            let Some(rel) = safe_rel(&item.name) else {
                return Err(format!("unsafe archive entry: {}", item.name));
            };
            let raw_path = raw_dir.join(&rel);
            if let Some(parent) = raw_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&raw_path, &item.data).map_err(|e| e.to_string())?;

            let served = protect_js(&item.name, &item.data);
            if is_protected(&served) && !is_protected(&item.data) {
                protected += 1;
            }
            let dist_path = dist_dir.join(&rel);
            if let Some(parent) = dist_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&dist_path, &served).map_err(|e| e.to_string())?;

            files += 1;
            bytes += served.len();
            if item.name == "widget.js" || (entry.is_none() && item.name == "cap.min.js") {
                entry = Some(item.name.clone());
            }
        }

        let meta = ReleaseMeta {
            id: id.clone(),
            created: now_ms() as i64,
            files,
            bytes,
            protected,
            active: false,
            builtin: false,
            build_id: String::new(),
            entry,
        };
        std::fs::write(
            dir.join(META_FILE),
            serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

        // An upload is meant to go live; the previous release stays on disk
        // for rollback.
        self.activate(&id)?;
        Ok(meta)
    }

    /// Install the binary's default in memory, without creating an active
    /// setting. Preserve existing on-disk releases, including builtin rollback
    /// targets and broken explicit configurations, rather than repairing them
    /// by silently substituting another version.
    pub fn publish_builtin(&self, archive: &[u8], build_id: &str) -> Result<ReleaseMeta, String> {
        let entries = read_zip(archive).map_err(|e: ZipError| e.0)?;
        let mut bundled = HashMap::new();
        for item in &entries {
            safe_rel(&item.name).ok_or_else(|| format!("unsafe archive entry: {}", item.name))?;
            let served = protect_js(&item.name, &item.data);
            let gzip = if should_gzip(&item.name, &served) { gzip_bytes(&served) } else { None };
            bundled.insert(item.name.clone(), ServedFile {
                plain: Bytes::from(served), gzip,
                content_type: content_type_for(&item.name).unwrap_or("application/octet-stream"),
            });
        }
        *self.builtin.write().unwrap_or_else(|e| e.into_inner()) = bundled;
        let dir = self.release_dir(BUILTIN_ID);
        if std::fs::symlink_metadata(&dir).is_ok() {
            let mut meta = self
                .list()
                .into_iter()
                .find(|m| m.id == BUILTIN_ID)
                .unwrap_or_else(|| ReleaseMeta {
                    id: BUILTIN_ID.to_string(),
                    created: 0,
                    files: 0,
                    bytes: 0,
                    protected: 0,
                    active: false,
                    builtin: true,
                    build_id: String::new(),
                    entry: None,
                });
            meta.active = self.active_id().ok().flatten().as_deref() == Some(BUILTIN_ID);
            return Ok(meta);
        }
        if self.active_id().ok().flatten().as_deref() == Some(BUILTIN_ID) {
            return Err("configured built-in release is missing".into());
        }

        let (raw_dir, dist_dir) = (dir.join("raw"), dir.join("dist"));
        std::fs::create_dir_all(&raw_dir).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&dist_dir).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("source.zip"), archive).map_err(|e| e.to_string())?;

        let (mut files, mut bytes, mut protected, mut entry) = (0usize, 0usize, 0usize, None);
        for item in entries {
            let Some(rel) = safe_rel(&item.name) else {
                return Err(format!("unsafe archive entry: {}", item.name));
            };
            if let Some(parent) = raw_dir.join(&rel).parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(raw_dir.join(&rel), &item.data).map_err(|e| e.to_string())?;

            let served = protect_js(&item.name, &item.data);
            if is_protected(&served) && !is_protected(&item.data) {
                protected += 1;
            }
            if let Some(parent) = dist_dir.join(&rel).parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(dist_dir.join(&rel), &served).map_err(|e| e.to_string())?;

            files += 1;
            bytes += served.len();
            if item.name == "widget.js" || (entry.is_none() && item.name == "cap.min.js") {
                entry = Some(item.name.clone());
            }
        }

        let meta = ReleaseMeta {
            id: BUILTIN_ID.to_string(),
            created: now_ms() as i64,
            files,
            bytes,
            protected,
            active: false,
            builtin: true,
            build_id: build_id.to_string(),
            entry,
        };
        std::fs::write(
            dir.join(META_FILE),
            serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

        Ok(meta)
    }

    pub fn list(&self) -> Vec<ReleaseMeta> {
        let active = self.active_id().ok().flatten();
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(id) = path.file_name().map(|s| s.to_string_lossy().to_string()) else {
                continue;
            };
            let meta_path = path.join(META_FILE);
            let mut meta = std::fs::read_to_string(&meta_path)
                .ok()
                .and_then(|s| serde_json::from_str::<ReleaseMeta>(&s).ok())
                .unwrap_or_else(|| ReleaseMeta {
                    id: id.clone(),
                    created: 0,
                    files: 0,
                    bytes: 0,
                    protected: 0,
                    active: false,
                    builtin: id == BUILTIN_ID,
                    build_id: String::new(),
                    entry: None,
                });
            meta.active = active.as_deref() == Some(id.as_str());
            out.push(meta);
        }
        out.sort_by(|a, b| b.created.cmp(&a.created));
        out
    }

    pub fn activate(&self, id: &str) -> Result<(), String> {
        // Validate before changing either the durable marker or served snapshot.
        let loaded = self.load_release(id)?;
        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        let pending = self.root.join("active.tmp");
        std::fs::write(&pending, id).map_err(|e| e.to_string())?;
        std::fs::rename(&pending, self.root.join(ACTIVE_FILE)).map_err(|e| e.to_string())?;
        *active = loaded;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        if id == BUILTIN_ID {
            return Err("the built-in release cannot be deleted".into());
        }
        if self.active_id().ok().flatten().as_deref() == Some(id) {
            return Err("cannot delete the active release; activate another first".into());
        }
        let dir = self.release_dir(id);
        if !dir.is_dir() {
            return Err(format!("release {id} does not exist"));
        }
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())
    }

    /// The archived zip of a release (for download / re-deploy).
    pub fn source_zip(&self, id: &str) -> Option<Vec<u8>> {
        std::fs::read(self.release_dir(id).join("source.zip")).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal stored-only zip builder for tests.
    fn zip_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut central = Vec::new();
        for (name, data) in files {
            let offset = body.len() as u32;
            body.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            body.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(data);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = body.len() as u32;
        let cd_size = central.len() as u32;
        body.extend_from_slice(&central);
        body.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 0]);
        body.extend_from_slice(&(files.len() as u16).to_le_bytes());
        body.extend_from_slice(&(files.len() as u16).to_le_bytes());
        body.extend_from_slice(&cd_size.to_le_bytes());
        body.extend_from_slice(&cd_offset.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cap-rel-{tag}-{}", crate::random_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn publish_protects_js_and_serves_files() {
        let dir = temp_dir("pub");
        let store = ReleaseStore::open(&dir).unwrap();
        let zip = zip_of(&[
            ("widget.js", b"var a = 1; // hi\n"),
            ("cap_wasm_bg.wasm", b"\0asm\x01\x00\x00\x00"),
        ]);
        let meta = store.publish(&zip).unwrap();
        assert_eq!(meta.files, 2);
        assert_eq!(meta.protected, 1, "only the .js is protected");
        assert_eq!(meta.entry.as_deref(), Some("widget.js"));

        // Active because it was the first release.
        assert_eq!(store.active_release_id().as_deref(), Some(meta.id.as_str()));
        let js = store.get("widget.js").unwrap();
        assert!(js.content_type.starts_with("application/javascript"));
        assert!(crate::is_protected(&js.plain), "served JS is protected");
        assert!(js.gzip.is_none(), "encrypted JS is not precompressed");
        let raw = store.get("cap_wasm_bg.wasm").unwrap();
        assert_eq!(&raw.plain[..], b"\0asm\x01\x00\x00\x00", "wasm untouched");
        // Raw copy is preserved unmodified.
        let raw_js = std::fs::read(dir.join("releases").join(&meta.id).join("raw/widget.js")).unwrap();
        assert_eq!(raw_js, b"var a = 1; // hi\n");
        // Basename lookup works for nested files.
        assert!(store.get("widget.js").is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn keeps_history_and_switches_active() {
        let dir = temp_dir("hist");
        let store = ReleaseStore::open(&dir).unwrap();
        let first = store
            .publish(&zip_of(&[("widget.js", b"var v = 1;")]))
            .unwrap();
        let second = store
            .publish(&zip_of(&[("widget.js", b"var v = 2;")]))
            .unwrap();
        assert_eq!(store.list().len(), 2);
        // An upload goes live immediately.
        assert_eq!(store.active_release_id().as_deref(), Some(second.id.as_str()));

        store.activate(&first.id).unwrap();
        assert_eq!(store.active_release_id().as_deref(), Some(first.id.as_str()));

        // The active flag is serialized for the dashboard.
        let active = store.list().into_iter().find(|m| m.active).unwrap();
        assert_eq!(active.id, first.id);

        // The active one cannot be deleted; the other can.
        assert!(store.delete(&first.id).is_err());
        store.delete(&second.id).unwrap();
        assert_eq!(store.list().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn binary_default_is_complete_and_does_not_configure_or_replace_history() {
        let dir = temp_dir("default");
        let store = ReleaseStore::open(&dir).unwrap();
        let bundle = zip_of(&[("widget.js", b"var x=1;"), ("a.wasm", b"old"), ("b.wasm", b"two")]);
        store.publish_builtin(&bundle, "one").unwrap();
        assert!(!store.root().join(ACTIVE_FILE).exists());
        for name in ["widget.js", "a.wasm", "b.wasm"] {
            assert!(store.resolve(name).unwrap().is_some());
        }
        store.publish_builtin(&zip_of(&[("a.wasm", b"new")]), "two").unwrap();
        assert_eq!(store.resolve("a.wasm").unwrap().unwrap().plain.as_ref(), b"new");
        store.activate(BUILTIN_ID).unwrap();
        assert_eq!(store.resolve("a.wasm").unwrap().unwrap().plain.as_ref(), b"old");
        let user = store.publish(&zip_of(&[("custom.js", b"var x=3;")])).unwrap();
        assert!(store.resolve("widget.js").unwrap().is_none());
        assert!(store.resolve("a.wasm").unwrap().is_none());
        assert!(store.activate("missing-release").is_err());
        assert_eq!(store.active_release_id().as_deref(), Some(user.id.as_str()));
        store.activate(BUILTIN_ID).unwrap();
        assert!(store.resolve("widget.js").unwrap().is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn broken_configuration_is_not_defaulted_or_overwritten() {
        for marker in ["", "../escape", "missing-release", "builtin"] {
            let dir = temp_dir("broken");
            std::fs::create_dir_all(dir.join("releases")).unwrap();
            std::fs::write(dir.join("releases/active"), marker).unwrap();
            let store = ReleaseStore::open(&dir).unwrap();
            assert!(store.resolve("widget.js").is_err());
            let result = store.publish_builtin(&zip_of(&[("widget.js", b"var x=1;")]), "one");
            assert_eq!(result.is_err(), marker == BUILTIN_ID);
            assert!(store.resolve("widget.js").is_err());
            assert_eq!(std::fs::read_to_string(dir.join("releases/active")).unwrap(), marker);
            let published = store.publish(&zip_of(&[("custom.js", b"var x=2;")])).unwrap();
            assert_eq!(store.active_release_id(), Some(published.id));
            assert!(store.resolve("widget.js").unwrap().is_none());
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn rejects_bad_archive() {
        let dir = temp_dir("bad");
        let store = ReleaseStore::open(&dir).unwrap();
        assert!(store.publish(b"not a zip").is_err());
        assert!(store.list().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn reopening_restores_active_release() {
        let dir = temp_dir("reopen");
        let id = {
            let store = ReleaseStore::open(&dir).unwrap();
            store.publish(&zip_of(&[("widget.js", b"var q=1;")])).unwrap().id
        };
        let store = ReleaseStore::open(&dir).unwrap();
        assert_eq!(store.active_release_id().as_deref(), Some(id.as_str()));
        assert!(store.get("widget.js").is_some());
        std::fs::remove_dir_all(dir).ok();
    }
}
