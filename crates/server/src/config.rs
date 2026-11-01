//! The `cappro` data directory and its `config.toml`.
//!
//! Layout (created on first start):
//!
//! ```text
//! cappro/
//! ├── config.toml     settings; environment variables still override
//! ├── releases/       published widget front-end bundles
//! └── tmp/            scratch space for uploads
//! ```
//!
//! Location: `CAPPRO_DIR`, else `cappro/` next to the executable. In Docker,
//! mount a volume there (or set `CAPPRO_DIR=/data`).
//!
//! Precedence for every setting: environment variable > config.toml > default.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub server: ServerSection,
    pub admin: AdminSection,
    pub storage: StorageSection,
    pub assets: AssetsSection,
    pub proxy: ProxySection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSection {
    /// Bind address (`SERVER_HOSTNAME`).
    pub hostname: String,
    pub port: u16,
    /// Directory of the official dashboard (`cap/standalone/public`). Empty =
    /// auto-discover.
    pub dashboard_dir: String,
    pub demo: bool,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            hostname: "0.0.0.0".into(),
            port: 3000,
            dashboard_dir: String::new(),
            demo: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminSection {
    pub admin_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageSection {
    /// Redis connection string. Empty falls back to `REDIS_URL`, then
    /// `redis://127.0.0.1:6379`.
    pub redis_url: String,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self { redis_url: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AssetsSection {
    /// Fetch widget/wasm from the CDN when no release is published.
    pub cdn_fallback: bool,
    pub cache_host: String,
    pub widget_version: String,
    pub wasm_version: String,
    pub embed_widget_url: String,
}

impl Default for AssetsSection {
    fn default() -> Self {
        Self {
            cdn_fallback: true,
            cache_host: "https://cdn.jsdelivr.net".into(),
            widget_version: "latest".into(),
            wasm_version: "latest".into(),
            embed_widget_url: "/assets/widget.js".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxySection {
    pub trust_proxy: bool,
    pub proxy_secret: String,
    /// Header carrying the real client IP (`RATELIMIT_IP_HEADER`).
    pub ip_header: String,
}

/// Resolved runtime configuration.
#[derive(Debug, Clone)]
pub struct Settings {
    pub data_dir: PathBuf,
    pub hostname: String,
    pub port: u16,
    pub ip_header: String,
    pub rsw_bits: usize,
    pub admin_key: String,
    pub demo: bool,
    pub redis_url: String,
    pub dashboard_dir: Option<PathBuf>,
    pub cdn_fallback: bool,
    pub cache_host: String,
    pub widget_version: String,
    pub wasm_version: String,
    pub embed_widget_url: String,
    pub trust_proxy: bool,
    pub proxy_secret: String,
}

impl Settings {
    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }
}

/// The dashboard bundled by `build.rs`.
static DASHBOARD_ZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dashboard.zip"));

/// The default widget bundle (widget.js + wasm), published on first start.
pub static WIDGET_ZIP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/widget.zip"));

/// Content fingerprint of the compiled-in dashboard bundle.
pub static DASHBOARD_ID: &str = include_str!(concat!(env!("OUT_DIR"), "/dashboard-id.txt"));

/// Content fingerprint of the compiled-in widget bundle.
pub static WIDGET_ID: &str = include_str!(concat!(env!("OUT_DIR"), "/widget-id.txt"));

/// The prebuilt widget bundle, ready for [`cap_assets::ReleaseStore::publish_builtin`].
pub fn builtin_widget_zip() -> &'static [u8] {
    WIDGET_ZIP
}

/// Extract the bundled dashboard into `target` (idempotent).
fn unpack_embedded_dashboard(target: &std::path::Path) -> Result<usize, String> {
    let entries = cap_assets::read_zip(DASHBOARD_ZIP).map_err(|e| e.0)?;
    std::fs::create_dir_all(target).map_err(|e| e.to_string())?;
    let mut count = 0;
    for entry in entries {
        let path = target.join(&entry.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, &entry.data).map_err(|e| e.to_string())?;
        count += 1;
    }
    Ok(count)
}

/// `CAPPRO_DIR`, else `<dir of the executable>/cappro`, else `./cappro`.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CAPPRO_DIR") {
        let dir = dir.trim();
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("cappro")))
        .unwrap_or_else(|| PathBuf::from("cappro"))
}

fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn env_bool(name: &str) -> Option<bool> {
    env_str(name).map(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn random_key() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create the data directory, write a default `config.toml` on first run, and
/// resolve the effective settings.
pub fn init() -> Result<Settings, String> {
    let dir = data_dir();
    for sub in ["", "releases", "tmp"] {
        let p = dir.join(sub);
        std::fs::create_dir_all(&p)
            .map_err(|e| format!("cannot create data directory {}: {e}", p.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    // Unpack the embedded dashboard so a single-binary install still has a
    // login page and the admin panel. Re-unpack when the embedded bundle
    // changed, so files removed in a new build do not linger and keep being
    // served. The directory is generated (not user-edited), so clearing it is
    // safe.
    let dashboard_dir = dir.join("dashboard");
    let stamp = dashboard_dir.join(".bundle-id");
    let current = DASHBOARD_ID.trim();
    let installed = std::fs::read_to_string(&stamp).unwrap_or_default();
    if !dashboard_dir.join("index.html").is_file() || installed.trim() != current {
        let _ = std::fs::remove_dir_all(&dashboard_dir);
        match unpack_embedded_dashboard(&dashboard_dir) {
            Ok(n) => {
                let _ = std::fs::write(&stamp, current);
                eprintln!(
                    "[cap] dashboard unpacked: {n} files → {}",
                    dashboard_dir.display()
                );
            }
            Err(e) => eprintln!("[cap] could not unpack the embedded dashboard: {e}"),
        }
    }

    let cfg_path = dir.join("config.toml");
    let mut file: FileConfig = if cfg_path.is_file() {
        let raw = std::fs::read_to_string(&cfg_path)
            .map_err(|e| format!("cannot read {}: {e}", cfg_path.display()))?;
        toml::from_str(&raw).map_err(|e| format!("invalid {}: {e}", cfg_path.display()))?
    } else {
        FileConfig::default()
    };

    // First run without ADMIN_KEY: generate one so the panel works out of the
    // box, and keep it in config.toml (mode 0600).
    let mut generated_key = None;
    let fresh = !cfg_path.is_file();
    if file.admin.admin_key.is_empty() && env_str("ADMIN_KEY").is_none() {
        let key = random_key();
        file.admin.admin_key = key.clone();
        generated_key = Some(key);
    }
    if fresh || generated_key.is_some() {
        let body = toml::to_string_pretty(&file).map_err(|e| e.to_string())?;
        let header = "# Cap server configuration. Environment variables override these values.\n\n";
        write_private(&cfg_path, &format!("{header}{body}"))
            .map_err(|e| format!("cannot write {}: {e}", cfg_path.display()))?;
    }
    if let Some(key) = &generated_key {
        eprintln!("[cap] generated an admin key and saved it to {}", cfg_path.display());
        eprintln!("[cap] admin key: {key}");
    }

    let dashboard = env_str("ADMIN_LEGACY_DIR").or_else(|| {
        Some(file.server.dashboard_dir.clone()).filter(|d| !d.is_empty())
    });

    Ok(Settings {
        hostname: env_str("SERVER_HOSTNAME").unwrap_or(file.server.hostname),
        port: env_str("SERVER_PORT")
            .and_then(|p| match p.trim().parse() {
                Ok(port) => Some(port),
                Err(_) => {
                    eprintln!("[cap] SERVER_PORT={p:?} is not a number; using {}", file.server.port);
                    None
                }
            })
            .unwrap_or(file.server.port),
        admin_key: env_str("ADMIN_KEY").unwrap_or(file.admin.admin_key),
        demo: env_bool("DEMO_MODE").unwrap_or(file.server.demo),
        redis_url: env_str("REDIS_URL")
            .or_else(|| Some(file.storage.redis_url.clone()).filter(|u| !u.is_empty()))
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string()),
        dashboard_dir: dashboard.map(PathBuf::from),
        cdn_fallback: env_bool("ENABLE_ASSETS_SERVER").unwrap_or(file.assets.cdn_fallback),
        cache_host: env_str("CACHE_HOST").unwrap_or(file.assets.cache_host),
        widget_version: env_str("WIDGET_VERSION").unwrap_or(file.assets.widget_version),
        wasm_version: env_str("WASM_VERSION").unwrap_or(file.assets.wasm_version),
        embed_widget_url: env_str("EMBED_WIDGET_URL").unwrap_or(file.assets.embed_widget_url),
        ip_header: env_str("RATELIMIT_IP_HEADER").unwrap_or(file.proxy.ip_header),
        rsw_bits: env_str("RSW_BITS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2048),
        trust_proxy: env_bool("CAP_TRUST_PROXY").unwrap_or(file.proxy.trust_proxy),
        proxy_secret: env_str("CAP_PROXY_SECRET").unwrap_or(file.proxy.proxy_secret),
        data_dir: dir,
    })
}
