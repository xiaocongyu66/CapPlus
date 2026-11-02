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
    /// Trusted demo embedding domains, independent of the IP listen address.
    /// None disables demo credential issuance; an explicit invalid list is fatal.
    pub demo_allowed_domains: Option<Vec<String>>,
    /// Require the redeem to come from the same signed embed session that
    /// fetched the challenge (`CAP_REQUIRE_VSESS`, default on). Set `false`
    /// for clients that call the API directly without the embed iframe.
    pub verify_session: Option<bool>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            hostname: "0.0.0.0".into(),
            port: 3000,
            dashboard_dir: String::new(),
            demo: false,
            demo_allowed_domains: None,
            verify_session: None,
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
        Self {
            redis_url: String::new(),
        }
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
#[serde(default, deny_unknown_fields)]
pub struct ProxySection {
    pub trust_proxy: bool,
    pub proxy_secret: String,
    /// Reject redeem without an authenticated fingerprint (CAP_REQUIRE_NETWORK_FINGERPRINT).
    pub require_network_fingerprint: bool,
    /// Intermediate proxy hops to peel from XFF (CAP_TRUSTED_PROXY_CIDRS).
    /// Does not grant trust to the immediate peer or bypass the proxy secret.
    pub trusted_proxy_cidrs: Vec<String>,
    /// Direct peers allowed without a secret (CAP_TRUSTED_PEER_CIDRS).
    /// Does not authorize intermediate XFF hops or bypass a configured secret.
    pub trusted_peer_cidrs: Vec<String>,
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
    pub demo_allowed_domains: Option<Vec<String>>,
    pub redis_url: String,
    pub dashboard_dir: Option<PathBuf>,
    pub cdn_fallback: bool,
    pub cache_host: String,
    pub widget_version: String,
    pub wasm_version: String,
    pub embed_widget_url: String,
    pub trust_proxy: bool,
    pub proxy_secret: String,
    /// Reject redeem without an authenticated fingerprint (CAP_REQUIRE_NETWORK_FINGERPRINT).
    pub require_network_fingerprint: bool,
    /// Intermediate proxy hops to peel from XFF (CAP_TRUSTED_PROXY_CIDRS).
    /// Does not grant trust to the immediate peer or bypass the proxy secret.
    pub trusted_proxy_cidrs: Vec<String>,
    /// Direct peers allowed without a secret (CAP_TRUSTED_PEER_CIDRS).
    /// Does not authorize intermediate XFF hops or bypass a configured secret.
    pub trusted_peer_cidrs: Vec<String>,
    pub require_verify_session: bool,
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

fn strict_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(format!("{name} must be valid Unicode")),
    }
}

fn parse_proxy_bool(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err("expected an explicit boolean".into()),
    }
}

fn proxy_env_bool(name: &str, fallback: bool) -> Result<bool, String> {
    strict_env(name)?
        .map(|v| parse_proxy_bool(&v).map_err(|e| format!("{name}: {e}")))
        .unwrap_or(Ok(fallback))
}

fn validate_proxy(proxy: &ProxySection) -> Result<(), String> {
    if proxy.require_network_fingerprint
        && (!proxy.trust_proxy || proxy.proxy_secret.trim().is_empty())
    {
        return Err(
            "require_network_fingerprint requires trust_proxy and a nonempty proxy_secret".into(),
        );
    }
    if !proxy.ip_header.is_empty() {
        axum::http::HeaderName::from_bytes(proxy.ip_header.as_bytes())
            .map_err(|_| "invalid RATELIMIT_IP_HEADER / proxy.ip_header".to_string())?;
    }
    validate_proxy_cidrs("trusted_proxy_cidrs", &proxy.trusted_proxy_cidrs)?;
    validate_proxy_cidrs("trusted_peer_cidrs", &proxy.trusted_peer_cidrs)?;
    if proxy.trust_proxy && proxy.proxy_secret.is_empty() && proxy.trusted_peer_cidrs.is_empty() {
        return Err("trust_proxy requires proxy_secret or explicit trusted_peer_cidrs".into());
    }
    if !proxy.proxy_secret.is_empty() && proxy.proxy_secret.trim().is_empty() {
        return Err("proxy_secret must not contain only whitespace".into());
    }
    Ok(())
}

fn validate_proxy_cidrs(name: &str, cidrs: &[String]) -> Result<(), String> {
    for net in cidrs {
        let base = net.split('/').next().unwrap_or("");
        let valid_prefix = net.split_once('/').is_none_or(|(_, prefix)| {
            !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_digit())
        });
        if !valid_prefix || !crate::http_util::cidr_match(net, base) {
            return Err(format!("invalid {name} CIDR: {net:?}"));
        }
    }
    Ok(())
}

fn parse_proxy_cidrs(name: &str, value: &str) -> Result<Vec<String>, String> {
    // An explicitly empty env or empty element is an error, not a fallback.
    let cidrs: Vec<_> = value.split(',').map(|s| s.trim().to_string()).collect();
    validate_proxy_cidrs(name, &cidrs)?;
    Ok(cidrs)
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    // Create with the final mode so there is no window where the generated
    // admin key is world-readable.
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        // mode 只影响新文件；既有文件必须先收紧权限再覆盖秘密。
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.set_len(0)?;
        f.write_all(contents.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
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
        // Existing secrets must not stay world-readable merely because no
        // rewrite is necessary. Tighten through the same handle we read.
        let mut handle = std::fs::File::open(&cfg_path)
            .map_err(|e| format!("cannot open {}: {e}", cfg_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            handle
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("cannot secure {}: {e}", cfg_path.display()))?;
        }
        use std::io::Read as _;
        let mut raw = String::new();
        handle
            .read_to_string(&mut raw)
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
    if generated_key.is_some() {
        eprintln!(
            "[cap] generated an admin key and saved it (0600) to {}; read it from the file",
            cfg_path.display()
        );
    }

    let dashboard = env_str("ADMIN_LEGACY_DIR")
        .or_else(|| Some(file.server.dashboard_dir.clone()).filter(|d| !d.is_empty()));

    let mut proxy = file.proxy;
    proxy.trust_proxy = proxy_env_bool("CAP_TRUST_PROXY", proxy.trust_proxy)?;
    proxy.require_network_fingerprint = proxy_env_bool(
        "CAP_REQUIRE_NETWORK_FINGERPRINT",
        proxy.require_network_fingerprint,
    )?;
    if let Some(secret) = strict_env("CAP_PROXY_SECRET")? {
        if secret.trim().is_empty() {
            return Err("CAP_PROXY_SECRET must not be empty; unset it to use config.toml".into());
        }
        proxy.proxy_secret = secret;
    }
    if let Some(header) = strict_env("RATELIMIT_IP_HEADER")? {
        if header.is_empty() {
            return Err(
                "RATELIMIT_IP_HEADER must not be empty; unset it to use config.toml".into(),
            );
        }
        proxy.ip_header = header;
    }
    if let Some(value) = strict_env("CAP_TRUSTED_PROXY_CIDRS")? {
        proxy.trusted_proxy_cidrs = parse_proxy_cidrs("CAP_TRUSTED_PROXY_CIDRS", &value)?;
    }
    if let Some(value) = strict_env("CAP_TRUSTED_PEER_CIDRS")? {
        proxy.trusted_peer_cidrs = parse_proxy_cidrs("CAP_TRUSTED_PEER_CIDRS", &value)?;
    }
    validate_proxy(&proxy)?;
    let demo_allowed_domains = resolve_demo_domains(
        strict_env("CAP_DEMO_ALLOWED_DOMAINS")?.as_deref(),
        file.server.demo_allowed_domains.as_deref(),
    )?;

    Ok(Settings {
        demo_allowed_domains,
        hostname: env_str("SERVER_HOSTNAME").unwrap_or(file.server.hostname),
        port: env_str("SERVER_PORT")
            .and_then(|p| match p.trim().parse() {
                Ok(port) => Some(port),
                Err(_) => {
                    eprintln!(
                        "[cap] SERVER_PORT={p:?} is not a number; using {}",
                        file.server.port
                    );
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
        ip_header: proxy.ip_header,
        rsw_bits: env_str("RSW_BITS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2048),
        trust_proxy: proxy.trust_proxy,
        proxy_secret: proxy.proxy_secret,
        require_network_fingerprint: proxy.require_network_fingerprint,
        trusted_proxy_cidrs: proxy.trusted_proxy_cidrs,
        trusted_peer_cidrs: proxy.trusted_peer_cidrs,
        require_verify_session: proxy_env_bool(
            "CAP_REQUIRE_VSESS",
            file.server.verify_session.unwrap_or(true),
        )?,
        data_dir: dir,
    })
}

/// Comma-separated environment override, or TOML array; missing is deliberately
/// distinct from an explicitly empty/invalid value. Never infer this from Host,
/// Origin, or the server's IP listen address.
fn resolve_demo_domains(
    env: Option<&str>,
    file: Option<&[String]>,
) -> Result<Option<Vec<String>>, String> {
    let override_domains;
    let domains = if let Some(raw) = env {
        if raw.len() > 12_750 {
            return Err("CAP_DEMO_ALLOWED_DOMAINS exceeds bounded domain list size".into());
        }
        override_domains = raw
            .split(',')
            .map(|s| s.trim().to_owned())
            .collect::<Vec<_>>();
        Some(override_domains.as_slice())
    } else {
        file
    };
    domains.map(|domains| {
        // Demo authorization intentionally permits exact domains only.
        if domains.iter().any(|s| s.contains('*')) {
            return Err("CAP_DEMO_ALLOWED_DOMAINS / server.demo_allowed_domains requires exact domains, no wildcards".into());
        }
        let mut domains = cap_embed::normalize_domains(domains).map_err(|e|
            format!("CAP_DEMO_ALLOWED_DOMAINS / server.demo_allowed_domains: {e}"))?;
        domains.sort();
        domains.dedup();
        Ok(domains)
    }).transpose()
}

#[cfg(test)]
mod tests {
    #[test]
    fn demo_domains_are_explicit_bounded_and_independent_of_listen_ip() {
        use super::*;
        assert_eq!(resolve_demo_domains(None, None).unwrap(), None);
        assert_eq!(
            resolve_demo_domains(Some("Demo.Example.test,other.example.test"), None).unwrap(),
            Some(vec![
                "demo.example.test".into(),
                "other.example.test".into()
            ])
        );
        for raw in [
            "",
            " ",
            "*",
            "*.example.test",
            "127.0.0.1",
            "0.0.0.0",
            "https://example.test",
            "example.test:443",
            "example.test,",
            "a.test,,b.test",
        ] {
            assert!(resolve_demo_domains(Some(raw), None).is_err(), "{raw}");
        }
        assert!(resolve_demo_domains(None, Some(&[])).is_err());
        assert!(resolve_demo_domains(None, Some(&vec!["example.test".into(); 51])).is_err());
        let file: FileConfig =
            toml::from_str("[server]\nhostname='127.0.0.1'\ndemo_allowed_domains=['example.test']")
                .unwrap();
        assert_eq!(file.server.hostname, "127.0.0.1");
        assert_eq!(
            resolve_demo_domains(None, file.server.demo_allowed_domains.as_deref()).unwrap(),
            Some(vec!["example.test".into()])
        );
        assert!(
            resolve_demo_domains(Some(""), file.server.demo_allowed_domains.as_deref()).is_err()
        );
        assert_eq!(
            resolve_demo_domains(
                Some("override.test"),
                file.server.demo_allowed_domains.as_deref()
            )
            .unwrap(),
            Some(vec!["override.test".into()])
        );
    }

    use super::*;

    #[test]
    fn proxy_configuration_fails_closed() {
        for value in ["", "tru", "2", "enabled"] {
            assert!(parse_proxy_bool(value).is_err());
        }
        assert_eq!(parse_proxy_bool(" TRUE "), Ok(true));
        assert_eq!(parse_proxy_bool("off"), Ok(false));
        let mut proxy = ProxySection::default();
        assert!(validate_proxy(&proxy).is_ok());
        proxy.require_network_fingerprint = true;
        assert!(validate_proxy(&proxy).is_err());
        proxy.trust_proxy = true;
        assert!(validate_proxy(&proxy).is_err());
        proxy.proxy_secret = "secret".into();
        assert!(validate_proxy(&proxy).is_ok());
        for net in ["", "bad", "10.0.0.0/33", "::/129", "10.0.0.0/24/1"] {
            proxy.trusted_proxy_cidrs = vec![net.into()];
            assert!(validate_proxy(&proxy).is_err(), "{net}");
        }
        proxy.trusted_proxy_cidrs = vec!["10.0.0.0/24".into(), "2001:db8::/32".into()];
        assert!(validate_proxy(&proxy).is_ok());
        proxy.ip_header = "bad header".into();
        assert!(validate_proxy(&proxy).is_err());
        assert!(
            toml::from_str::<FileConfig>("[proxy]\nrequire_network_fingerprit = true").is_err()
        );
        assert!(
            toml::from_str::<FileConfig>("[proxy]\nrequire_network_fingerprint = 'true'").is_err()
        );
    }

    #[test]
    fn peer_allowlist_is_required_only_without_secret() {
        let mut proxy = ProxySection::default();
        assert!(!proxy.trust_proxy);
        assert!(validate_proxy(&proxy).is_ok());
        proxy.trust_proxy = true;
        assert!(validate_proxy(&proxy).is_err());
        proxy.trusted_proxy_cidrs = vec!["10.0.0.0/8".into()];
        assert!(validate_proxy(&proxy).is_err());
        proxy.trusted_peer_cidrs = vec!["127.0.0.1/32".into(), "::ffff:10.0.0.1/128".into()];
        assert!(validate_proxy(&proxy).is_ok());
        proxy.require_network_fingerprint = true;
        assert!(validate_proxy(&proxy).is_err());
        proxy.proxy_secret = "secret".into();
        assert!(validate_proxy(&proxy).is_ok());
        proxy.trusted_peer_cidrs.clear();
        assert!(validate_proxy(&proxy).is_ok());
        proxy.require_network_fingerprint = false;
        proxy.proxy_secret = "  ".into();
        assert!(validate_proxy(&proxy).is_err());
    }

    #[test]
    fn peer_and_hop_cidr_configuration_is_strict() {
        for name in ["CAP_TRUSTED_PEER_CIDRS", "CAP_TRUSTED_PROXY_CIDRS"] {
            for value in [
                "",
                " ",
                ",",
                "127.0.0.1,",
                ",::1",
                "::1,,127.0.0.1",
                "bad",
                "10.0.0.0/33",
                "::/129",
                "10.0.0.0/24/1",
                "::1/",
                "::1/-1",
                "::1/+128",
                "10.0.0.1/+32",
            ] {
                assert!(parse_proxy_cidrs(name, value).is_err(), "{name}: {value:?}");
            }
            assert_eq!(
                parse_proxy_cidrs(name, " 127.0.0.1/32 , ::1/128 ").unwrap(),
                vec!["127.0.0.1/32", "::1/128"]
            );
        }
        for field in ["trusted_peer_cidrs", "trusted_proxy_cidrs"] {
            for value in ["['']", "['bad']", "['::/129']", "[' 127.0.0.1 ']"] {
                let file: FileConfig =
                    toml::from_str(&format!("[proxy]\n{field} = {value}")).unwrap();
                assert!(validate_proxy(&file.proxy).is_err());
            }
            for value in ["'127.0.0.1'", "[1]", "false"] {
                assert!(
                    toml::from_str::<FileConfig>(&format!("[proxy]\n{field} = {value}")).is_err()
                );
            }
        }
        let file: FileConfig = toml::from_str(
            "[proxy]\ntrust_proxy = true\ntrusted_peer_cidrs = ['127.0.0.1', '::1/128']",
        )
        .unwrap();
        assert!(validate_proxy(&file.proxy).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn private_writes_create_and_tighten_before_truncation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "cap-private-{}-{}",
            std::process::id(),
            random_key()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("config.toml");
        write_private(&path, "long secret contents").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, "short").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "short");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
