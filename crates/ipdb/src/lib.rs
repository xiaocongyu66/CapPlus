//! IP geolocation: MMDB parsing, database download and lookups.
//!
//! Databases live in `<data>/ipdb/` as `country.mmdb` and `asn.mmdb`. Sources:
//! - **DB-IP Lite** (free, no key): `dbip-country-lite-YYYY-MM.mmdb.gz`
//! - **MaxMind GeoLite2** (license key): tarball with an `.mmdb` inside
//! - **IPInfo** — API mode, no local database

pub mod mmdb;

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

pub use mmdb::{asn_number, country_code, Mmdb, Value};

/// What the geolocation backend should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    None,
    DbIp,
    MaxMind,
    IpInfo,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "" | "none" => Mode::None,
            "dbip" => Mode::DbIp,
            "maxmind" | "maxmind_lite" => Mode::MaxMind,
            "ipinfo" => Mode::IpInfo,
            _ => return None,
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::None => "none",
            Mode::DbIp => "dbip",
            Mode::MaxMind => "maxmind",
            Mode::IpInfo => "ipinfo",
        }
    }
}

/// Credentials for the paid sources.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub maxmind_account_id: String,
    pub maxmind_key: String,
    pub ipinfo_token: String,
}

/// Download progress, polled by the dashboard.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub active: bool,
    pub file: String,
    pub downloaded: u64,
    pub total: u64,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct IpDb {
    dir: PathBuf,
    mode: RwLock<Mode>,
    country: RwLock<Option<Arc<Mmdb>>>,
    asn: RwLock<Option<Arc<Mmdb>>>,
    progress: RwLock<Progress>,
    busy: AtomicBool,
}

impl IpDb {
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let db = Self {
            dir: dir.to_path_buf(),
            mode: RwLock::new(Mode::None),
            country: RwLock::new(None),
            asn: RwLock::new(None),
            progress: RwLock::new(Progress::default()),
            busy: AtomicBool::new(false),
        };
        db.reload();
        Ok(db)
    }

    pub fn country_path(&self) -> PathBuf {
        self.dir.join("country.mmdb")
    }
    pub fn asn_path(&self) -> PathBuf {
        self.dir.join("asn.mmdb")
    }

    /// Load whatever database files exist.
    pub fn reload(&self) {
        let load = |p: PathBuf| -> Option<Arc<Mmdb>> {
            let bytes = std::fs::read(&p).ok()?;
            Mmdb::open(bytes).map(Arc::new)
        };
        *self.country.write().unwrap_or_else(|e| e.into_inner()) = load(self.country_path());
        *self.asn.write().unwrap_or_else(|e| e.into_inner()) = load(self.asn_path());
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.write().unwrap_or_else(|e| e.into_inner()) = mode;
    }
    pub fn mode(&self) -> Mode {
        *self.mode.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn country_exists(&self) -> bool {
        self.country.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }
    pub fn asn_exists(&self) -> bool {
        self.asn.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }
    pub fn country_size(&self) -> u64 {
        std::fs::metadata(self.country_path()).map(|m| m.len()).unwrap_or(0)
    }
    pub fn asn_size(&self) -> u64 {
        std::fs::metadata(self.asn_path()).map(|m| m.len()).unwrap_or(0)
    }

    pub fn progress(&self) -> Progress {
        self.progress.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_progress(&self, p: Progress) {
        *self.progress.write().unwrap_or_else(|e| e.into_inner()) = p;
    }

    /// Run a download in the background. Returns `false` when one is already
    /// running.
    pub fn start_download(self: &Arc<Self>, mode: Mode, creds: Credentials) -> bool {
        if self.busy.swap(true, Ordering::SeqCst) {
            return false;
        }
        let db = Arc::clone(self);
        std::thread::spawn(move || {
            let result = db.download_blocking(mode, &creds);
            if let Err(e) = &result {
                db.set_progress(Progress {
                    active: false,
                    file: String::new(),
                    downloaded: 0,
                    total: 0,
                    error: Some(e.clone()),
                });
            } else {
                db.set_progress(Progress::default());
            }
            db.busy.store(false, Ordering::SeqCst);
        });
        true
    }

    fn download_blocking(&self, mode: Mode, creds: &Credentials) -> Result<(), String> {
        match mode {
            Mode::None => {
                self.remove_files();
                self.set_mode(Mode::None);
                Ok(())
            }
            Mode::IpInfo => {
                // API mode: no files to fetch.
                self.set_mode(Mode::IpInfo);
                Ok(())
            }
            Mode::DbIp => {
                let country = self.fetch_dbip("country")?;
                let asn = self.fetch_dbip("asn")?;
                self.install(country, self.country_path())?;
                self.install(asn, self.asn_path())?;
                self.set_mode(Mode::DbIp);
                self.reload();
                Ok(())
            }
            Mode::MaxMind => {
                if creds.maxmind_account_id.is_empty() || creds.maxmind_key.is_empty() {
                    return Err("MaxMind account ID and license key are required".into());
                }
                let country = self.fetch_maxmind("GeoLite2-Country", creds)?;
                let asn = self.fetch_maxmind("GeoLite2-ASN", creds)?;
                self.install(country, self.country_path())?;
                self.install(asn, self.asn_path())?;
                self.set_mode(Mode::MaxMind);
                self.reload();
                Ok(())
            }
        }
    }

    fn install(&self, data: Vec<u8>, path: PathBuf) -> Result<(), String> {
        // Verify before replacing: a corrupt download must not clobber a
        // working database.
        if Mmdb::open(data.clone()).is_none() {
            return Err(format!("downloaded file is not a valid MMDB: {}", path.display()));
        }
        std::fs::write(&path, data).map_err(|e| e.to_string())
    }

    fn remove_files(&self) {
        let _ = std::fs::remove_file(self.country_path());
        let _ = std::fs::remove_file(self.asn_path());
        self.reload();
    }

    /// DB-IP publishes monthly files; try the current and two previous months.
    fn fetch_dbip(&self, kind: &str) -> Result<Vec<u8>, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (year, month) = civil_from_days((now / 86_400) as i64);
        let mut errors = Vec::new();
        for back in 0..3 {
            let (y, m) = prev_month(year, month, back);
            let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{y}-{m:02}.mmdb.gz");
            match self.get(&url, None, kind) {
                Ok(gz) => return gunzip(&gz).map_err(|e| format!("{url}: {e}")),
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        Err(errors.join("; "))
    }

    fn fetch_maxmind(&self, edition: &str, creds: &Credentials) -> Result<Vec<u8>, String> {
        let url = format!(
            "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
        );
        let auth = format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{}:{}", creds.maxmind_account_id, creds.maxmind_key)
            )
        );
        let tar_gz = self.get(&url, Some(&auth), edition)?;
        let tar = gunzip(&tar_gz).map_err(|e| format!("{edition}: {e}"))?;
        extract_mmdb_from_tar(&tar).ok_or_else(|| format!("no .mmdb inside {edition} tarball"))
    }

    fn get(&self, url: &str, auth: Option<&str>, label: &str) -> Result<Vec<u8>, String> {
        self.set_progress(Progress {
            active: true,
            file: label.to_string(),
            downloaded: 0,
            total: 0,
            error: None,
        });
        let agent = ureq::AgentBuilder::new()
            .timeout_read(std::time::Duration::from_secs(120))
            .timeout_connect(std::time::Duration::from_secs(20))
            .user_agent("CapPlus/ipdb")
            .build();
        let mut req = agent.get(url);
        if let Some(auth) = auth {
            req = req.set("Authorization", auth);
        }
        let resp = req.call().map_err(|e| e.to_string())?;
        let total = resp
            .header("Content-Length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        let mut buf = Vec::new();
        let mut reader = resp.into_reader();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            self.set_progress(Progress {
                active: true,
                file: label.to_string(),
                downloaded: buf.len() as u64,
                total,
                error: None,
            });
        }
        Ok(buf)
    }
}

/// `GET /keys/:sk/geo-stats`-style lookup: `(country, asn)` for an address.
pub fn lookup(db: &IpDb, ip: IpAddr) -> (Option<String>, Option<u64>) {
    let country = db
        .country
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|mmdb| mmdb.lookup(ip))
        .and_then(|v| country_code(&v));
    let asn = db
        .asn
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|mmdb| mmdb.lookup(ip))
        .and_then(|v| asn_number(&v));
    (country, asn)
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Pull the first `.mmdb` member out of an uncompressed tar archive.
fn extract_mmdb_from_tar(tar: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    while pos + 512 <= tar.len() {
        let header = &tar[pos..pos + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name_end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name = String::from_utf8_lossy(&header[..name_end]);
        let size_field = &header[124..136];
        let size_str = std::str::from_utf8(size_field)
            .ok()?
            .trim_matches(|c: char| c == '\0' || c == ' ')
            .trim();
        let size = usize::from_str_radix(size_str, 8).ok()?;
        pos += 512;
        if name.ends_with(".mmdb") && size > 0 && pos + size <= tar.len() {
            return Some(tar[pos..pos + size].to_vec());
        }
        pos += size.div_ceil(512) * 512;
    }
    None
}

/// `(year, month)` from days since the epoch (civil-from-days, Howard Hinnant).
fn civil_from_days(days: i64) -> (i64, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if m <= 2 {
        y += 1;
    }
    (y, m)
}

fn prev_month(year: i64, month: u32, back: u32) -> (i64, u32) {
    let total = year * 12 + (month as i64 - 1) - back as i64;
    (total.div_euclid(12), (total.rem_euclid(12) + 1) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_arithmetic() {
        assert_eq!(prev_month(2026, 1, 1), (2025, 12));
        assert_eq!(prev_month(2026, 3, 2), (2026, 1));
        assert_eq!(prev_month(2026, 10, 0), (2026, 10));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10));
    }

    #[test]
    fn tar_extraction_picks_mmdb() {
        let payload = b"\x00asm-test";
        let mut tar = vec![0u8; 512];
        tar[..11].copy_from_slice(b"dir/db.mmdb");
        tar[124..135].copy_from_slice(b"00000000011");
        tar.extend_from_slice(payload);
        tar.resize(512 * 3, 0);
        assert_eq!(extract_mmdb_from_tar(&tar).as_deref(), Some(&payload[..]));
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(Mode::parse("dbip"), Some(Mode::DbIp));
        assert_eq!(Mode::parse("maxmind_lite"), Some(Mode::MaxMind));
        assert_eq!(Mode::parse("ipinfo"), Some(Mode::IpInfo));
        assert_eq!(Mode::parse(""), Some(Mode::None));
        assert_eq!(Mode::parse("bogus"), None);
    }
}
