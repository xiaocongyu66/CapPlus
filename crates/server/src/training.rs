//! Opt-in, local-only observation storage. No upload, training, or inferred labels.
//! Call `open` off the async executor (it performs bounded recovery). Administrative
//! calls are bounded and return Busy instead of awaiting queue capacity. Handler
//! authentication/authorization and mapping errors to HTTP belong to the caller.
//! Linux/Unix private data directory, exclusively owned by this service; do not put
//! unrelated files here. A held OS file lock rejects a second process or instance.
//! Ancestors must be trusted: this does not defend against same-UID directory writers.
//! Budgets count logical bytes, not allocated filesystem blocks. There are at most
//! 64 active directories plus 256 retired directories, 128 segments per active site,
//! and five root files (including the manifest replacement); retired sites have no data.
//! Retirement is permanent and bounded to 256 IDs; further retirements return Capacity.
//! Commands cancelled before execution may be skipped. Once executing they may commit
//! even if the reply is lost: query status (config/epoch/tombstone/healthy) afterwards.
//! Storage errors around atomic commit can mean an unknown outcome, not guaranteed abort.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};

pub const SCHEMA_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;
pub const QUEUE_CAPACITY: usize = 256;
pub const MAX_SAMPLE_BYTES: usize = 1024;
/// Logical file-length budget, NOT a physical block or filesystem quota.
pub const GLOBAL_DISK_CAP_BYTES: u64 = 32 * 1024 * 1024;
// Reserve covers manifests (including atomic replacement), audit pair, and lock.
const DATA_CAP: u64 = GLOBAL_DISK_CAP_BYTES - 1024 * 1024;
const MAX_SITES: usize = 64;
const MAX_RETIRED: usize = 256;
// Fixed across config changes, so recovery can validate older segments too.
// Seven-day retention needs at most 127 time-rotated segments (plus boundary).
const SEGMENT_SECS: u64 = 604_800u64.div_ceil((MAX_FILES - 1) as u64);
const MAX_FILES: usize = 128;
const SEGMENT_BYTES: u64 = 64 * 1024;
const CONTROL_CAPACITY: usize = 8;
const MANIFEST_BYTES: u64 = 128 * 1024;
const AUDIT_BYTES: u64 = 32 * 1024;
const MAX_PAGE: usize = 128;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Challenge,
    Deny,
    Error,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasonId {
    None,
    Policy,
    RateLimit,
    ProofInvalid,
    ProofValid,
    Expired,
    Internal,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Truth {
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Chromium,
    Firefox,
    Safari,
    Other,
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Macos,
    Linux,
    Android,
    Ios,
    Other,
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TimingBucket {
    Under10Ms,
    Under100Ms,
    Under1Sec,
    Under10Sec,
    Over10Sec,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientSource {
    ClientReported,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxySource {
    TrustedProxy,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFeatures {
    pub source: ClientSource,
    pub browser: BrowserFamily,
    pub os: OsFamily,
    pub hardware_concurrency: Option<u16>,
    pub software_renderer: Option<bool>,
    pub timing: Option<TimingBucket>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyFeatures {
    pub source: ProxySource,
    pub tls: Option<bool>,
    pub ja4_browser: Option<bool>,
    pub ja3_browser: Option<bool>,
    pub http2_browser: Option<bool>,
    pub ua_mismatch: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Unknown,
    Redeem,
    Challenge,
    Validate,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    Unknown,
    V1,
    V2,
}
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    #[default]
    Unknown,
    Allow,
    Challenge,
    Deny,
}

/// Fixed whitelist: never add strings, maps, raw probes, identifiers, or JSON Value.
/// Versions/truth are stamped by `new` and checked again at ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub schema_version: u16,
    pub policy_version: u16,
    pub decision: Decision,
    pub reason: ReasonId,
    pub truth: Truth,
    #[serde(default)]
    pub phase: Phase,
    #[serde(default)]
    pub protocol: Protocol,
    #[serde(default)]
    pub recommended_action: RecommendedAction,
    #[serde(default)]
    pub level: Option<u8>,
    /// At most 16 static reason identifiers, checked again at ingestion/recovery.
    #[serde(default)]
    pub reasons: Vec<ReasonId>,
    pub elapsed_ms: u32,
    pub risk_score: u16,
    pub proof_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientFeatures>,
    /// None means proxy observations are absent, not false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyFeatures>,
}
impl Sample {
    pub fn new(
        decision: Decision,
        reason: ReasonId,
        elapsed_ms: u32,
        risk_score: u16,
        proof_valid: bool,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            policy_version: POLICY_VERSION,
            decision,
            reason,
            truth: Truth::Unknown,
            phase: Phase::Unknown,
            protocol: Protocol::Unknown,
            recommended_action: RecommendedAction::Unknown,
            level: None,
            reasons: Vec::new(),
            elapsed_ms,
            risk_score,
            proof_valid,
            client: None,
            proxy: None,
        }
    }
    fn valid(&self) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.policy_version == POLICY_VERSION
            && self.elapsed_ms <= 3_600_000
            && self.risk_score <= 100
            && self.reasons.len() <= 16
            && self
                .client
                .as_ref()
                .and_then(|c| c.hardware_concurrency)
                .is_none_or(|n| (1..=256).contains(&n))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub enabled: bool,
    /// Server-side random sampling in millionths, 0..=1_000_000.
    pub sample_rate_ppm: u32,
    /// 60 seconds through seven days. Segments span at most 4,763 seconds;
    /// expiry may remove records up to min(retention, 4,763) seconds early.
    /// Expired records are never exported. Byte/128-segment exhaustion drops new
    /// records; it does not extend retention or allocate unbounded files.
    pub retention_secs: u64,
    /// 64 KiB through 8 MiB. Exhaustion drops new observations, not validation.
    pub cap_bytes: u64,
}
impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate_ppm: 10_000,
            retention_secs: 86_400,
            cap_bytes: 1024 * 1024,
        }
    }
}
impl SiteConfig {
    fn validate(&self) -> Result<()> {
        if self.sample_rate_ppm > 1_000_000
            || !(60..=604_800).contains(&self.retention_secs)
            || !(SEGMENT_BYTES..=8 * 1024 * 1024).contains(&self.cap_bytes)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidSite,
    InvalidConfig,
    InvalidCursor,
    InvalidLimit,
    Busy,
    Unavailable,
    Storage,
    Locked,
    Capacity,
    Deleted,
}
pub type Result<T> = std::result::Result<T, Error>;
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "training storage: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::Storage
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Error::Storage
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    Queued,
    Disabled,
    SampledOut,
    Dropped,
    Invalid,
    Unavailable,
}
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub config: SiteConfig,
    pub epoch: u64,
    pub bytes: u64,
    /// Live logical JSONL bytes only, not filesystem blocks. The logical budget
    /// reserves 1 MiB for manifests, audit files, and partial-write headroom.
    pub global_bytes: u64,
    pub queue_capacity: usize,
    pub queued: usize,
    pub dropped: u64,
    /// Process-lifetime global subsets of dropped, never per untrusted site ID.
    pub segment_cap_dropped: u64,
    pub byte_cap_dropped: u64,
    pub invalid_dropped: u64,
    pub expired_dropped: u64,
    /// Live segments; bounded by 128 per site and 64 * 128 globally.
    pub segments: usize,
    pub global_segments: usize,
    pub written: u64,
    pub write_errors: u64,
    pub healthy: bool,
    pub tombstoned: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSample {
    pub recorded_at: u64,
    pub sample: Sample,
}
#[derive(Debug, Serialize)]
pub struct ExportPage {
    pub samples: Vec<StoredSample>,
    pub next_cursor: Option<String>,
    pub epoch: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteMeta {
    config: SiteConfig,
    epoch: u64,
    tombstoned: bool,
    /// A persisted but uncommitted configure always recovers disabled.
    #[serde(default)]
    configuring: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    id: u64,
    action: String,
    site: String,
    epoch: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u16,
    cursor_key: [u8; 32],
    next_sequence: u64,
    sites: BTreeMap<String, SiteMeta>,
    // The single writer finishes this slot before accepting another mutation.
    #[serde(default)]
    pending_operation: Option<Operation>,
}
#[derive(Clone)]
struct Gate {
    meta: SiteMeta,
    revision: u64,
}
struct Shared {
    gates: Mutex<BTreeMap<String, Gate>>,
    healthy: AtomicBool,
    dropped: AtomicU64,
    written: AtomicU64,
    write_errors: AtomicU64,
    segment_cap_dropped: AtomicU64,
    byte_cap_dropped: AtomicU64,
    invalid_dropped: AtomicU64,
    expired_dropped: AtomicU64,
}
struct Pending {
    site: String,
    epoch: u64,
    revision: u64,
    bytes: Vec<u8>,
    at: u64,
}
enum Control {
    Configure(String, SiteConfig, oneshot::Sender<Result<()>>),
    Status(String, oneshot::Sender<Result<Status>>),
    Export(
        String,
        Option<String>,
        usize,
        oneshot::Sender<Result<ExportPage>>,
    ),
    Delete(String, bool, oneshot::Sender<Result<u64>>),
}
#[derive(Clone)]
pub struct TrainingService {
    data: mpsc::Sender<Pending>,
    controls: mpsc::Sender<Control>,
    shared: Arc<Shared>,
}

fn site_key(site: &str) -> Result<String> {
    // Site identifiers, not URLs. No separators, control bytes, unicode, or dots.
    if site.is_empty()
        || site.len() > 128
        || !site
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Error::InvalidSite);
    }
    Ok(Sha256::digest(site.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        Ok(_) => return Err(Error::Storage),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(_) => return Err(Error::Storage),
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn file(path: &Path, create: bool) -> Result<File> {
    if let Ok(m) = fs::symlink_metadata(path)
        && (!m.is_file() || m.file_type().is_symlink())
    {
        return Err(Error::Storage);
    }
    // O_NOFOLLOW is Linux-specific; the server targets Linux. Prevent final-path
    // symlink following even if another same-uid process races the metadata check.
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(0x20000)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(f)
}
fn bounded_entries(path: &Path, max: usize) -> Result<Vec<fs::DirEntry>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(path)?.take(max + 1) {
        out.push(entry?);
    }
    if out.len() > max {
        return Err(Error::Capacity);
    }
    Ok(out)
}

impl TrainingService {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let root = data_dir.as_ref().to_path_buf();
        private_dir(&root)?;
        let lock = file(&root.join("writer.lock"), true)?;
        lock.try_lock().map_err(|_| Error::Locked)?;
        lock.set_len(0)?;
        // Bounded namespace: only known service files and hashed site directories.
        for e in bounded_entries(&root, MAX_SITES + MAX_RETIRED + 6)? {
            let n = e.file_name().to_string_lossy().into_owned();
            if ![
                "writer.lock",
                "manifest.json",
                "manifest.tmp",
                "audit.jsonl",
                "audit.previous",
            ]
            .contains(&n.as_str())
                && !(n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(Error::Storage);
            }
            let kind = e.file_type()?;
            let hashed = n.len() == 64 && n.bytes().all(|b| b.is_ascii_hexdigit());
            if kind.is_symlink() || (hashed && !kind.is_dir()) || (!hashed && !kind.is_file()) {
                return Err(Error::Storage);
            }
        }
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let f = file(&manifest_path, false)?;
            if f.metadata()?.len() > MANIFEST_BYTES {
                return Err(Error::Capacity);
            }
            let mut m: Manifest = serde_json::from_reader(f)?;
            if m.version != 1
                || m.next_sequence == 0
                || m.sites.values().filter(|s| !s.tombstoned).count() > MAX_SITES
                || m.sites.values().filter(|s| s.tombstoned).count() > MAX_RETIRED
            {
                return Err(Error::Storage);
            }
            if let Some(op) = &m.pending_operation
                && (op.id == 0
                    || op.id >= m.next_sequence
                    || !matches!(op.action.as_str(), "site_data_delete" | "site_retire")
                    || !m.sites.get(&op.site).is_some_and(|s| {
                        s.epoch == op.epoch && (op.action != "site_retire" || s.tombstoned)
                    }))
            {
                return Err(Error::Storage);
            }
            for (key, meta) in &mut m.sites {
                if meta.configuring {
                    meta.config.enabled = false;
                    meta.configuring = false;
                }
                if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) || meta.epoch == 0
                {
                    return Err(Error::Storage);
                }
                meta.config.validate()?;
                if meta.tombstoned && meta.config.enabled {
                    return Err(Error::Storage);
                }
            }
            m
        } else {
            // Never reconstruct consent from sample files if metadata is absent.
            if bounded_entries(&root, MAX_SITES + MAX_RETIRED + 6)?
                .iter()
                .any(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(true))
            {
                return Err(Error::Storage);
            }
            let mut cursor_key = [0; 32];
            OsRng.fill_bytes(&mut cursor_key);
            Manifest {
                version: 1,
                cursor_key,
                next_sequence: 1,
                sites: BTreeMap::new(),
                pending_operation: None,
            }
        };
        let shared = Arc::new(Shared {
            gates: Mutex::new(
                manifest
                    .sites
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            Gate {
                                meta: v.clone(),
                                revision: 0,
                            },
                        )
                    })
                    .collect(),
            ),
            healthy: AtomicBool::new(true),
            dropped: AtomicU64::new(0),
            written: AtomicU64::new(0),
            write_errors: AtomicU64::new(0),
            segment_cap_dropped: AtomicU64::new(0),
            byte_cap_dropped: AtomicU64::new(0),
            invalid_dropped: AtomicU64::new(0),
            expired_dropped: AtomicU64::new(0),
        });
        let (data, rx) = mpsc::channel(QUEUE_CAPACITY);
        let (controls, crx) = mpsc::channel(CONTROL_CAPACITY);
        let mut worker = Worker {
            root,
            _lock: lock,
            manifest,
            shared: shared.clone(),
            segments: BTreeMap::new(),
            total: 0,
        };
        worker.persist()?;
        worker.recover()?;
        thread::Builder::new()
            .name("training-writer".into())
            .spawn(move || worker.run(rx, crx))
            .map_err(|_| Error::Storage)?;
        Ok(Self {
            data,
            controls,
            shared,
        })
    }
    /// Nonblocking memory-only hint, not an authorization or admission guarantee.
    pub fn enabled(&self, site: &str) -> bool {
        if !self.shared.healthy.load(Ordering::Acquire) {
            return false;
        }
        let Ok(key) = site_key(site) else {
            return false;
        };
        self.shared.gates.try_lock().ok().is_some_and(|gates| {
            gates
                .get(&key)
                .is_some_and(|g| g.meta.config.enabled && !g.meta.tombstoned && !g.meta.configuring)
        })
    }
    pub fn try_record(&self, site: &str, sample: Sample) -> RecordOutcome {
        if !self.shared.healthy.load(Ordering::Acquire) {
            return RecordOutcome::Unavailable;
        }
        let key = match site_key(site) {
            Ok(k) => k,
            Err(_) => {
                self.shared.invalid_dropped.fetch_add(1, Ordering::Relaxed);
                self.drop_one();
                return RecordOutcome::Invalid;
            }
        };
        if !sample.valid() {
            self.shared.invalid_dropped.fetch_add(1, Ordering::Relaxed);
            self.drop_one();
            return RecordOutcome::Invalid;
        }
        let gate = match self.shared.gates.try_lock() {
            Ok(g) => match g.get(&key) {
                Some(g) if g.meta.config.enabled => g.clone(),
                _ => return RecordOutcome::Disabled,
            },
            Err(_) => {
                self.drop_one();
                return RecordOutcome::Dropped;
            }
        };
        if OsRng.gen_range(0..1_000_000u32) >= gate.meta.config.sample_rate_ppm {
            return RecordOutcome::SampledOut;
        }
        let at = now();
        let mut bytes = match serde_json::to_vec(&StoredSample {
            recorded_at: at,
            sample,
        }) {
            Ok(b) => b,
            Err(_) => {
                self.drop_one();
                return RecordOutcome::Invalid;
            }
        };
        bytes.push(b'\n');
        if bytes.len() > MAX_SAMPLE_BYTES {
            self.shared.invalid_dropped.fetch_add(1, Ordering::Relaxed);
            self.drop_one();
            return RecordOutcome::Invalid;
        }
        match self.data.try_send(Pending {
            site: key,
            epoch: gate.meta.epoch,
            revision: gate.revision,
            bytes,
            at,
        }) {
            Ok(()) => RecordOutcome::Queued,
            Err(_) => {
                self.drop_one();
                RecordOutcome::Dropped
            }
        }
    }
    fn drop_one(&self) {
        self.shared.dropped.fetch_add(1, Ordering::Relaxed);
    }
    fn send(&self, c: Control) -> Result<()> {
        self.controls.try_send(c).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => Error::Busy,
            _ => Error::Unavailable,
        })
    }
    pub async fn configure(&self, site: &str, config: SiteConfig) -> Result<()> {
        let site = site_key(site)?;
        config.validate()?;
        let (tx, rx) = oneshot::channel();
        self.send(Control::Configure(site, config, tx))?;
        rx.await.map_err(|_| Error::Unavailable)?
    }
    pub async fn status(&self, site: &str) -> Result<Status> {
        let site = site_key(site)?;
        let (tx, rx) = oneshot::channel();
        self.send(Control::Status(site, tx))?;
        rx.await.map_err(|_| Error::Unavailable)?
    }
    pub async fn export_page(
        &self,
        site: &str,
        cursor: Option<String>,
        limit: usize,
    ) -> Result<ExportPage> {
        let site = site_key(site)?;
        if !(1..=MAX_PAGE).contains(&limit) {
            return Err(Error::InvalidLimit);
        }
        if cursor.as_ref().is_some_and(|c| c.len() > 1024) {
            return Err(Error::InvalidCursor);
        }
        let (tx, rx) = oneshot::channel();
        self.send(Control::Export(site, cursor, limit, tx))?;
        rx.await.map_err(|_| Error::Unavailable)?
    }
    /// Irreversible site retirement: disable, advance epoch, erase observations,
    /// and persist a tombstone. Reusing this site ID is rejected after restart.
    pub async fn delete_site(&self, site: &str) -> Result<u64> {
        let site = site_key(site)?;
        let (tx, rx) = oneshot::channel();
        self.send(Control::Delete(site, true, tx))?;
        rx.await.map_err(|_| Error::Unavailable)?
    }
    /// Advances durable epoch before unlinking. A crash during cleanup cannot
    /// resurrect old data: recovery unlinks every segment from an older epoch.
    /// Deletion preserves the configured opt-in, so *new* records can arrive.
    /// Disable first if collection should remain stopped.
    pub async fn delete(&self, site: &str) -> Result<u64> {
        let site = site_key(site)?;
        let (tx, rx) = oneshot::channel();
        self.send(Control::Delete(site, false, tx))?;
        rx.await.map_err(|_| Error::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "cap-training-{}-{}",
                std::process::id(),
                OsRng.next_u64()
            ));
            private_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn sample() -> Sample {
        Sample::new(Decision::Allow, ReasonId::ProofValid, 25, 20, true)
    }
    fn enabled() -> SiteConfig {
        SiteConfig {
            enabled: true,
            sample_rate_ppm: 1_000_000,
            ..SiteConfig::default()
        }
    }
    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }
    async fn flush(s: &TrainingService) {
        for _ in 0..2000 {
            if s.status("site").await.unwrap().queued == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("queue did not drain");
    }
    fn reopen(path: &Path) -> TrainingService {
        for _ in 0..1000 {
            match TrainingService::open(path) {
                Ok(s) => return s,
                Err(Error::Locked) => thread::sleep(Duration::from_millis(2)),
                Err(e) => panic!("reopen failed: {e}"),
            }
        }
        panic!("lock not released");
    }
    #[test]
    fn default_off_validation_and_permissions() {
        rt().block_on(async {
            let t = Temp::new();
            let s = TrainingService::open(&t.0).unwrap();
            assert_eq!(s.try_record("site", sample()), RecordOutcome::Disabled);
            assert!(!s.status("site").await.unwrap().config.enabled);
            for bad in ["", "../site", "a/b", "a.b", "a\\b", "\n", "用户"] {
                assert_eq!(s.status(bad).await.unwrap_err(), Error::InvalidSite);
            }
            let mut cfg = enabled();
            cfg.sample_rate_ppm = 1_000_001;
            assert_eq!(
                s.configure("site", cfg).await.unwrap_err(),
                Error::InvalidConfig
            );
            assert_eq!(
                fs::metadata(&t.0).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(t.0.join("manifest.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert!(matches!(TrainingService::open(&t.0), Err(Error::Locked)));
            drop(s);
            drop(reopen(&t.0));
        });
    }
    #[test]
    fn whitelist_and_byte_limit() {
        let mut value = serde_json::to_value(sample()).unwrap();
        for secret in ["token", "cookie", "ip", "ua", "probe", "input", "secret"] {
            value[secret] = serde_json::json!("sensitive");
            assert!(serde_json::from_value::<Sample>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(secret);
        }
        value["truth"] = serde_json::json!("human");
        assert!(serde_json::from_value::<Sample>(value).is_err());
        let mut s = sample();
        s.client = Some(ClientFeatures {
            source: ClientSource::ClientReported,
            browser: BrowserFamily::Chromium,
            os: OsFamily::Windows,
            hardware_concurrency: Some(256),
            software_renderer: Some(false),
            timing: Some(TimingBucket::Under100Ms),
        });
        s.proxy = Some(ProxyFeatures {
            source: ProxySource::TrustedProxy,
            tls: None,
            ja4_browser: Some(true),
            ja3_browser: Some(false),
            http2_browser: None,
            ua_mismatch: None,
        });
        assert!(
            serde_json::to_vec(&StoredSample {
                recorded_at: u64::MAX,
                sample: s.clone()
            })
            .unwrap()
            .len() < MAX_SAMPLE_BYTES
        );
        s.reasons = vec![ReasonId::ProofInvalid; 16];
        assert!(s.valid());
        s.reasons.push(ReasonId::Policy);
        assert!(!s.valid());
        s.reasons.clear();
        s.client.as_mut().unwrap().hardware_concurrency = Some(257);
        assert!(!s.valid());
    }
    #[test]
    fn export_delete_restart_and_permanent_tombstone() {
        rt().block_on(async {
            let t = Temp::new();
            let s = TrainingService::open(&t.0).unwrap();
            s.configure("site", enabled()).await.unwrap();
            for _ in 0..10 {
                assert_eq!(s.try_record("site", sample()), RecordOutcome::Queued);
            }
            flush(&s).await;
            let p = s.export_page("site", None, 2).await.unwrap();
            assert_eq!(p.samples.len(), 2);
            let cursor = p.next_cursor.unwrap();
            let bytes = s.status("site").await.unwrap().bytes;
            drop(s);
            let s = reopen(&t.0);
            assert_eq!(s.status("site").await.unwrap().bytes, bytes);
            assert_eq!(
                s.export_page("site", Some(cursor.clone()), 2)
                    .await
                    .unwrap()
                    .samples
                    .len(),
                2
            );
            assert_eq!(
                s.export_page("other", Some(cursor.clone()), 2)
                    .await
                    .unwrap_err(),
                Error::InvalidCursor
            );
            let epoch = s.delete("site").await.unwrap();
            assert!(
                s.export_page("site", None, 2)
                    .await
                    .unwrap()
                    .samples
                    .is_empty()
            );
            assert_eq!(
                s.export_page("site", Some(cursor.clone()), 2)
                    .await
                    .unwrap_err(),
                Error::InvalidCursor
            );
            drop(s);
            let s = reopen(&t.0);
            assert_eq!(s.status("site").await.unwrap().epoch, epoch);
            assert_eq!(
                s.export_page("site", Some(cursor), 2).await.unwrap_err(),
                Error::InvalidCursor
            );
            s.delete_site("site").await.unwrap();
            drop(s);
            let s = reopen(&t.0);
            assert!(s.status("site").await.unwrap().tombstoned);
            assert_eq!(
                s.configure("site", enabled()).await.unwrap_err(),
                Error::Deleted
            );
            drop(s);
            drop(reopen(&t.0));
        });
    }
    #[test]
    fn bounded_queues_disk_and_concurrent_disable() {
        rt().block_on(async {
            let t = Temp::new();
            let s = TrainingService::open(&t.0).unwrap();
            let mut cfg = enabled();
            cfg.cap_bytes = SEGMENT_BYTES;
            s.configure("site", cfg).await.unwrap();
            let producer = s.clone();
            let h = thread::spawn(move || {
                for _ in 0..20_000 {
                    producer.try_record("site", sample());
                }
            });
            s.configure("site", SiteConfig::default()).await.unwrap();
            let bytes = s.status("site").await.unwrap().bytes;
            h.join().unwrap();
            flush(&s).await;
            assert_eq!(s.status("site").await.unwrap().bytes, bytes);
            let mut cfg = enabled();
            cfg.cap_bytes = SEGMENT_BYTES;
            s.configure("site", cfg).await.unwrap();
            for _ in 0..20 {
                for _ in 0..QUEUE_CAPACITY {
                    s.try_record("site", sample());
                }
                flush(&s).await;
            }
            let st = s.status("site").await.unwrap();
            assert!(st.bytes <= SEGMENT_BYTES);
            assert!(st.dropped > 0);
            assert!(st.healthy);
            assert_eq!(st.write_errors, 0);
            s.delete("site").await.unwrap();
            flush(&s).await;
            assert_eq!(s.status("site").await.unwrap().bytes, 0);
            drop(s);
            drop(reopen(&t.0));
        });
    }
    // Exercise the writer deterministically without timers or racing the queue.
    fn worker(t: &Temp) -> Worker {
        let lock = file(&t.0.join("writer.lock"), true).unwrap();
        lock.try_lock().unwrap();
        Worker {
            root: t.0.clone(),
            _lock: lock,
            manifest: Manifest {
                version: 1,
                cursor_key: [7; 32],
                next_sequence: 1,
                sites: BTreeMap::new(),
                pending_operation: None,
            },
            shared: Arc::new(Shared {
                gates: Mutex::new(BTreeMap::new()),
                healthy: AtomicBool::new(true),
                dropped: AtomicU64::new(0),
                written: AtomicU64::new(0),
                write_errors: AtomicU64::new(0),
                segment_cap_dropped: AtomicU64::new(0),
                byte_cap_dropped: AtomicU64::new(0),
                invalid_dropped: AtomicU64::new(0),
                expired_dropped: AtomicU64::new(0),
            }),
            segments: BTreeMap::new(),
            total: 0,
        }
    }
    fn pending(w: &Worker, site: &str, at: u64) -> Pending {
        let g = w.shared.gates.lock().unwrap()[site].clone();
        let mut bytes = serde_json::to_vec(&StoredSample {
            recorded_at: at,
            sample: sample(),
        })
        .unwrap();
        bytes.push(b'\n');
        Pending {
            site: site.into(),
            epoch: g.meta.epoch,
            revision: g.revision,
            bytes,
            at,
        }
    }
    #[test]
    fn expiry_global_limit_stale_inflight_and_byte_limit() {
        let t = Temp::new();
        let mut w = worker(&t);
        let site = site_key("site").unwrap();
        let mut cfg = enabled();
        cfg.retention_secs = 60;
        w.configure(&site, cfg.clone()).unwrap();
        let old = pending(&w, &site, now());
        w.configure(&site, cfg.clone()).unwrap();
        w.record(old).unwrap();
        assert_eq!(w.total, 0);
        let old = pending(&w, &site, now());
        w.delete(&site, false).unwrap();
        w.record(old).unwrap();
        assert_eq!(w.total, 0);
        let mut huge = pending(&w, &site, now());
        huge.bytes = vec![b' '; MAX_SAMPLE_BYTES + 1];
        w.record(huge).unwrap();
        assert_eq!(w.total, 0);
        assert_eq!(w.shared.invalid_dropped.load(Ordering::Relaxed), 1);
        w.record(pending(&w, &site, now() - 61)).unwrap();
        assert_eq!(w.shared.expired_dropped.load(Ordering::Relaxed), 1);
        w.total = DATA_CAP;
        w.record(pending(&w, &site, now())).unwrap();
        assert_eq!(w.total, DATA_CAP);
        w.total = 0;
        w.record(pending(&w, &site, now() - 59)).unwrap();
        assert!(w.total > 0);
        w.segments.get_mut(&site).unwrap()[0].at = now() - 60;
        w.prune().unwrap();
        assert_eq!(w.total, 0);
        // A queue is strictly bounded even if the consumer never makes progress.
        let (tx, _rx) = mpsc::channel(QUEUE_CAPACITY);
        for _ in 0..QUEUE_CAPACITY {
            tx.try_send(pending(&w, &site, now())).unwrap();
        }
        assert!(tx.try_send(pending(&w, &site, now())).is_err());
        let (tx, _rx) = mpsc::channel(CONTROL_CAPACITY);
        for _ in 0..CONTROL_CAPACITY {
            let (reply, _) = oneshot::channel();
            tx.try_send(Control::Status(site.clone(), reply))
                .ok()
                .unwrap();
        }
        let (reply, _) = oneshot::channel();
        assert!(tx.try_send(Control::Status(site, reply)).is_err());
    }
    #[test]
    fn crash_after_epoch_commit_never_resurrects_old_segments() {
        let t = Temp::new();
        let mut w = worker(&t);
        let site = site_key("site").unwrap();
        w.configure(&site, enabled()).unwrap();
        w.record(pending(&w, &site, now())).unwrap();
        let stale_path = w.segments[&site][0].path.clone();
        assert!(stale_path.exists());
        // Simulate a power loss between the durable tombstone and unlink.
        w.manifest.sites.get_mut(&site).unwrap().epoch += 1;
        w.persist().unwrap();
        drop(w);
        let s = TrainingService::open(&t.0).unwrap();
        assert!(!stale_path.exists());
        rt().block_on(async {
            assert_eq!(s.status("site").await.unwrap().bytes, 0);
            assert!(
                s.export_page("site", None, 1)
                    .await
                    .unwrap()
                    .samples
                    .is_empty()
            );
        });
        drop(s);
        drop(reopen(&t.0));
    }
    #[test]
    fn audit_scan_and_symlink_bounds() {
        let t = Temp::new();
        let w = worker(&t);
        let site = site_key("site").unwrap();
        for _ in 0..1000 {
            w.audit("export", &site).unwrap();
        }
        for n in ["audit.jsonl", "audit.previous"] {
            assert!(fs::metadata(t.0.join(n)).unwrap().len() <= AUDIT_BYTES);
        }
        drop(w);
        let unexpected = t.0.join("unexpected");
        File::create(&unexpected).unwrap();
        assert!(matches!(TrainingService::open(&t.0), Err(Error::Storage)));
        fs::remove_file(unexpected).unwrap();
        std::os::unix::fs::symlink("/dev/null", t.0.join("manifest.json")).unwrap();
        assert!(matches!(TrainingService::open(&t.0), Err(Error::Storage)));
        let dir = t.0.join("scan");
        private_dir(&dir).unwrap();
        for i in 0..MAX_FILES + 1 {
            File::create(dir.join(i.to_string())).unwrap();
        }
        assert!(matches!(
            bounded_entries(&dir, MAX_FILES),
            Err(Error::Capacity)
        ));
    }
    #[test]
    fn failed_write_disables_ingestion_and_counts_errors() {
        rt().block_on(async {
            let t = Temp::new();
            let s = TrainingService::open(&t.0).unwrap();
            s.configure("site", enabled()).await.unwrap();
            let dir = t.0.join(site_key("site").unwrap());
            fs::remove_dir(&dir).unwrap();
            assert_eq!(s.try_record("site", sample()), RecordOutcome::Queued);
            flush(&s).await;
            let st = s.status("site").await.unwrap();
            assert!(!st.healthy);
            assert!(st.write_errors > 0);
            assert_eq!(s.try_record("site", sample()), RecordOutcome::Unavailable);
            drop(s);
            drop(reopen(&t.0));
        });
    }
    #[test]
    fn pending_configure_failure_recovers_disabled_for_enable_and_disable() {
        rt().block_on(async {
            for desired in [true, false] {
                let t = Temp::new();
                let key = site_key("site").unwrap();
                let mut w = worker(&t);
                w.configure(&key, enabled()).unwrap();
                fs::remove_file(t.0.join("audit.jsonl")).unwrap();
                private_dir(&t.0.join("audit.jsonl")).unwrap();
                let mut config = enabled();
                config.enabled = desired;
                assert_eq!(w.configure(&key, config), Err(Error::Storage));
                let disk: Manifest =
                    serde_json::from_reader(file(&t.0.join("manifest.json"), false).unwrap())
                        .unwrap();
                assert!(disk.sites[&key].configuring);
                assert!(!disk.sites[&key].config.enabled);
                assert!(!w.shared.gates.lock().unwrap()[&key].meta.config.enabled);
                drop(w);
                fs::remove_dir(t.0.join("audit.jsonl")).unwrap();
                let s = reopen(&t.0);
                assert!(!s.enabled("site"));
                assert!(!s.status("site").await.unwrap().config.enabled);
                drop(s);
                drop(reopen(&t.0));
            }
        });
    }
    #[test]
    fn pending_delete_replays_audit_once_including_torn_append_and_rotation() {
        rt().block_on(async {
            for permanent in [false, true] {
                for already_audited in [false, true] {
                    let t = Temp::new();
                    let key = site_key("site").unwrap();
                    let mut w = worker(&t);
                    w.configure(&key, enabled()).unwrap();
                    w.record(pending(&w, &key, now())).unwrap();
                    let old_path = w.segments[&key][0].path.clone();
                    let old_bytes = fs::read(&old_path).unwrap();
                    fs::remove_file(t.0.join("audit.jsonl")).unwrap();
                    private_dir(&t.0.join("audit.jsonl")).unwrap();
                    assert_eq!(w.delete(&key, permanent), Err(Error::Storage));
                    let op = w.manifest.pending_operation.clone().unwrap();
                    assert_eq!(
                        op.action,
                        if permanent {
                            "site_retire"
                        } else {
                            "site_data_delete"
                        }
                    );
                    fs::remove_dir(t.0.join("audit.jsonl")).unwrap();
                    if already_audited {
                        // Force a rotation and simulate death after audit fsync but
                        // before the pending-slot completion manifest is persisted.
                        let row = "{\"padding\":true}\n";
                        let mut f = file(&t.0.join("audit.jsonl"), true).unwrap();
                        for _ in 0..AUDIT_BYTES / row.len() as u64 {
                            f.write_all(row.as_bytes()).unwrap();
                        }
                        f.sync_all().unwrap();
                        w.audit_operation(&op).unwrap();
                        assert!(t.0.join("audit.previous").exists());
                    } else {
                        // Recreate the pre-unlink crash state under the committed
                        // pending epoch: recovery must erase it before audit completion.
                        let mut old = file(&old_path, true).unwrap();
                        old.write_all(&old_bytes).unwrap();
                        old.sync_all().unwrap();
                        let mut f = file(&t.0.join("audit.jsonl"), true).unwrap();
                        f.write_all(b"{\"operation_id\":").unwrap();
                        f.sync_all().unwrap();
                    }
                    drop(w);
                    let s = reopen(&t.0);
                    assert_eq!(s.status("site").await.unwrap().epoch, op.epoch);
                    assert!(
                        s.export_page("site", None, 10)
                            .await
                            .unwrap()
                            .samples
                            .is_empty()
                    );
                    drop(s);
                    drop(reopen(&t.0));
                    let audit = fs::read_to_string(t.0.join("audit.jsonl")).unwrap();
                    let count = audit
                        .lines()
                        .filter(|line| {
                            let row: serde_json::Value = serde_json::from_str(line).unwrap();
                            row["operation_id"].as_u64() == Some(op.id)
                        })
                        .count();
                    assert_eq!(count, 1);
                    let disk: Manifest =
                        serde_json::from_reader(file(&t.0.join("manifest.json"), false).unwrap())
                            .unwrap();
                    assert!(disk.pending_operation.is_none());
                }
            }
        });
    }
    #[test]
    fn sparse_retention_and_distinct_capacity_counters() {
        for retention in [86_400, 604_800] {
            let t = Temp::new();
            let mut w = worker(&t);
            let key = site_key("site").unwrap();
            let mut cfg = enabled();
            cfg.retention_secs = retention;
            w.configure(&key, cfg).unwrap();
            let start = now() - retention + 30;
            for i in 0..240 {
                w.record(pending(&w, &key, start + i * (retention / 240)))
                    .unwrap();
            }
            assert_eq!(w.shared.written.load(Ordering::Relaxed), 240);
            assert_eq!(w.shared.segment_cap_dropped.load(Ordering::Relaxed), 0);
            assert!(w.segments[&key].len() <= MAX_FILES);
        }
        let t = Temp::new();
        let mut w = worker(&t);
        let key = site_key("site").unwrap();
        w.configure(&key, enabled()).unwrap();
        for i in 0..=MAX_FILES {
            w.record(pending(&w, &key, now() + i as u64 * SEGMENT_SECS))
                .unwrap();
        }
        assert_eq!(w.shared.segment_cap_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(w.shared.byte_cap_dropped.load(Ordering::Relaxed), 0);
        w.total = DATA_CAP;
        w.record(pending(&w, &key, now())).unwrap();
        assert_eq!(w.shared.byte_cap_dropped.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn unknown_delete_and_separate_retirement_budget() {
        let t = Temp::new();
        let mut w = worker(&t);
        for i in 0..1000 {
            assert_eq!(
                w.delete(&site_key(&format!("unknown{i}")).unwrap(), false),
                Ok(0)
            );
        }
        assert!(w.manifest.sites.is_empty());
        for i in 0..MAX_RETIRED {
            let key = site_key(&format!("retired{i}")).unwrap();
            w.configure(&key, enabled()).unwrap();
            w.delete(&key, true).unwrap();
            assert_eq!(w.configure(&key, enabled()), Err(Error::Deleted));
        }
        let active = site_key("active").unwrap();
        w.configure(&active, enabled()).unwrap();
        assert_eq!(w.delete(&active, true), Err(Error::Capacity));
        assert!(!w.manifest.sites[&active].tombstoned);
        assert_eq!(w.manifest.sites.len(), MAX_RETIRED + 1);
    }
    #[test]
    fn cancelled_control_and_normal_close_drain_queue() {
        let t = Temp::new();
        let mut w = worker(&t);
        let key = site_key("site").unwrap();
        let (tx, rx) = oneshot::channel();
        drop(rx);
        w.control(Control::Configure(key.clone(), enabled(), tx), 0);
        assert!(w.manifest.sites.is_empty());
        w.configure(&key, enabled()).unwrap();
        let (data, rx) = mpsc::channel(QUEUE_CAPACITY);
        let (control, crx) = mpsc::channel(CONTROL_CAPACITY);
        for _ in 0..10 {
            data.try_send(pending(&w, &key, now())).unwrap();
        }
        drop(data);
        drop(control);
        w.run(rx, crx);
        assert_eq!(w.shared.written.load(Ordering::Relaxed), 10);
        let first = w.export(&key, None, 3).unwrap();
        let second = w.export(&key, first.next_cursor, 10).unwrap();
        assert_eq!(second.samples.len(), 7);
    }
    #[test]
    fn multiprocess_lock_child() {
        if let Some(path) = std::env::var_os("CAP_TRAINING_LOCK_TEST") {
            assert!(matches!(
                TrainingService::open(PathBuf::from(path)),
                Err(Error::Locked)
            ));
        }
    }
    #[test]
    fn multiprocess_lock() {
        let t = Temp::new();
        let s = TrainingService::open(&t.0).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!(
                    "{}::multiprocess_lock_child",
                    module_path!().split_once("::").unwrap().1
                ),
            ])
            .env("CAP_TRAINING_LOCK_TEST", &t.0)
            .status()
            .unwrap();
        assert!(status.success());
        drop(s);
        drop(reopen(&t.0));
    }
}

#[derive(Clone)]
struct Segment {
    epoch: u64,
    sequence: u64,
    at: u64,
    bytes: u64,
    path: PathBuf,
}
struct Worker {
    root: PathBuf,
    _lock: File,
    manifest: Manifest,
    shared: Arc<Shared>,
    segments: BTreeMap<String, Vec<Segment>>,
    total: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    site: String,
    epoch: u64,
    sequence: u64,
    offset: u64,
}
impl Worker {
    fn fail(&self) {
        self.shared.healthy.store(false, Ordering::Release);
        self.shared.write_errors.fetch_add(1, Ordering::Relaxed);
    }
    fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.manifest)?;
        if bytes.len() as u64 > MANIFEST_BYTES {
            return Err(Error::Capacity);
        }
        let mut f = file(&self.root.join("manifest.tmp"), true)?;
        f.set_len(0)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(
            self.root.join("manifest.tmp"),
            self.root.join("manifest.json"),
        )?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn recover(&mut self) -> Result<()> {
        self.finish_operation()?;
        // Reject orphan directories rather than interpreting them as consent.
        for e in bounded_entries(&self.root, MAX_SITES + MAX_RETIRED + 6)? {
            if e.file_type()?.is_dir()
                && !self
                    .manifest
                    .sites
                    .contains_key(&e.file_name().to_string_lossy().into_owned())
            {
                return Err(Error::Storage);
            }
        }
        for (key, meta) in &self.manifest.sites {
            let dir = self.root.join(key);
            private_dir(&dir)?;
            let mut segments = Vec::new();
            for e in bounded_entries(&dir, MAX_FILES)? {
                if !e.file_type()?.is_file() {
                    return Err(Error::Storage);
                }
                let name = e.file_name().to_string_lossy().into_owned();
                let parts: Vec<_> = name
                    .strip_suffix(".jsonl")
                    .ok_or(Error::Storage)?
                    .split('-')
                    .collect();
                if parts.len() != 3 {
                    return Err(Error::Storage);
                }
                let epoch: u64 = parts[0].parse().map_err(|_| Error::Storage)?;
                let sequence: u64 = parts[1].parse().map_err(|_| Error::Storage)?;
                let at: u64 = parts[2].parse().map_err(|_| Error::Storage)?;
                if epoch != meta.epoch || meta.tombstoned {
                    fs::remove_file(e.path())?;
                    continue;
                }
                if sequence >= self.manifest.next_sequence {
                    return Err(Error::Storage);
                }
                let f = file(&e.path(), false)?;
                let bytes = f.metadata()?.len();
                if bytes > SEGMENT_BYTES {
                    return Err(Error::Capacity);
                }
                // Validate each line with a hard read bound. A torn write is not
                // made visible after restart: discard its incomplete final line.
                let mut reader = BufReader::new(f);
                let mut valid_bytes = 0u64;
                loop {
                    let mut line = Vec::new();
                    let n = reader
                        .by_ref()
                        .take((MAX_SAMPLE_BYTES + 1) as u64)
                        .read_until(b'\n', &mut line)?;
                    if n == 0 {
                        break;
                    }
                    if n > MAX_SAMPLE_BYTES {
                        return Err(Error::Storage);
                    }
                    if line.last() != Some(&b'\n') {
                        reader.get_ref().set_len(valid_bytes)?;
                        reader.get_ref().sync_all()?;
                        break;
                    }
                    let row: StoredSample = serde_json::from_slice(&line)?;
                    if !row.sample.valid()
                        || row.recorded_at < at
                        || row.recorded_at > at.saturating_add(SEGMENT_SECS)
                    {
                        return Err(Error::Storage);
                    }
                    valid_bytes += n as u64;
                }
                self.total = self.total.checked_add(valid_bytes).ok_or(Error::Capacity)?;
                segments.push(Segment {
                    epoch,
                    sequence,
                    at,
                    bytes: valid_bytes,
                    path: e.path(),
                });
            }
            File::open(&dir)?.sync_all()?;
            segments.sort_by_key(|s| s.sequence);
            if segments.windows(2).any(|w| w[0].sequence == w[1].sequence) {
                return Err(Error::Storage);
            }
            self.segments.insert(key.clone(), segments);
        }
        self.prune()?;
        if self.total > DATA_CAP {
            return Err(Error::Capacity);
        }
        // Bound audit files even after restart, without reading their contents.
        for name in ["audit.jsonl", "audit.previous"] {
            let path = self.root.join(name);
            if path.exists() && file(&path, false)?.metadata()?.len() > AUDIT_BYTES {
                return Err(Error::Capacity);
            }
        }
        Ok(())
    }
    fn run(&mut self, mut data: mpsc::Receiver<Pending>, mut control: mpsc::Receiver<Control>) {
        let mut last_prune = now();
        loop {
            // Control has priority, but at most eight controls before a data turn.
            for _ in 0..CONTROL_CAPACITY {
                match control.try_recv() {
                    Ok(c) => self.control(c, data.len()),
                    Err(_) => break,
                }
            }
            match data.try_recv() {
                Ok(p) => {
                    if self.shared.healthy.load(Ordering::Acquire) {
                        if self.record(p).is_err() {
                            self.fail();
                        }
                    } else {
                        self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(mpsc::error::TryRecvError::Disconnected)
                    if control.is_closed() && control.is_empty() =>
                {
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(2)),
            }
            if now().saturating_sub(last_prune) >= 1 {
                if self.prune().is_err() {
                    self.fail();
                }
                last_prune = now();
            }
        }
    }
    fn control(&mut self, c: Control, queued: usize) {
        match c {
            Control::Status(site, tx) => {
                let pruned = self.prune();
                if pruned.is_err() {
                    self.fail();
                }
                let meta = self.manifest.sites.get(&site);
                let _ = tx.send(Ok(Status {
                    config: meta.map(|m| m.config.clone()).unwrap_or_default(),
                    epoch: meta.map(|m| m.epoch).unwrap_or(0),
                    bytes: self.site_bytes(&site),
                    global_bytes: self.total,
                    queue_capacity: QUEUE_CAPACITY,
                    queued,
                    dropped: self.shared.dropped.load(Ordering::Relaxed),
                    segment_cap_dropped: self.shared.segment_cap_dropped.load(Ordering::Relaxed),
                    byte_cap_dropped: self.shared.byte_cap_dropped.load(Ordering::Relaxed),
                    invalid_dropped: self.shared.invalid_dropped.load(Ordering::Relaxed),
                    expired_dropped: self.shared.expired_dropped.load(Ordering::Relaxed),
                    segments: self.segments.get(&site).map_or(0, Vec::len),
                    global_segments: self.segments.values().map(Vec::len).sum(),
                    written: self.shared.written.load(Ordering::Relaxed),
                    write_errors: self.shared.write_errors.load(Ordering::Relaxed),
                    healthy: self.shared.healthy.load(Ordering::Acquire),
                    tombstoned: meta.is_some_and(|m| m.tombstoned),
                }));
            }
            Control::Configure(site, cfg, tx) => {
                if tx.is_closed() {
                    return;
                }
                let r = self.configure(&site, cfg);
                self.check_error(&r);
                let _ = tx.send(r);
            }
            Control::Delete(site, permanent, tx) => {
                if tx.is_closed() {
                    return;
                }
                let r = self.delete(&site, permanent);
                self.check_error(&r);
                let _ = tx.send(r);
            }
            Control::Export(site, cursor, limit, tx) => {
                let r = self.export(&site, cursor, limit);
                self.check_error(&r);
                let _ = tx.send(r);
            }
        }
    }
    fn check_error<T>(&self, r: &Result<T>) {
        if matches!(r, Err(Error::Storage)) {
            self.fail();
        }
    }
    fn site_bytes(&self, site: &str) -> u64 {
        self.segments
            .get(site)
            .map(|v| v.iter().map(|s| s.bytes).sum())
            .unwrap_or(0)
    }
    fn ensure_site(&mut self, site: &str) -> Result<()> {
        if !self.manifest.sites.contains_key(site) {
            if self
                .manifest
                .sites
                .values()
                .filter(|s| !s.tombstoned)
                .count()
                >= MAX_SITES
            {
                return Err(Error::Capacity);
            }
            self.manifest.sites.insert(
                site.into(),
                SiteMeta {
                    config: SiteConfig::default(),
                    epoch: 1,
                    tombstoned: false,
                    configuring: false,
                },
            );
        }
        Ok(())
    }
    fn configure(&mut self, site: &str, config: SiteConfig) -> Result<()> {
        if !self.shared.healthy.load(Ordering::Acquire) {
            return Err(Error::Unavailable);
        }
        self.ensure_site(site)?;
        if self.manifest.sites[site].tombstoned {
            return Err(Error::Deleted);
        }
        if self.manifest.pending_operation.is_some() {
            return Err(Error::Unavailable);
        }
        let meta = self.manifest.sites.get_mut(site).unwrap();
        meta.config = config.clone();
        meta.config.enabled = false;
        meta.configuring = true;
        // Disable producers before doing any IO; even a failed disable stays off
        // in this process. Once the pending manifest is durable, restart stays off.
        self.publish(site)?;
        let result = (|| {
            self.persist()?;
            private_dir(&self.root.join(site))?;
            File::open(&self.root)?.sync_all()?;
            self.prune()?;
            self.audit("configure", site)?;
            let meta = self.manifest.sites.get_mut(site).unwrap();
            meta.config = config;
            meta.configuring = false;
            self.persist()?; // commit; a lost reply must never roll this back
            self.publish(site)
        })();
        if result.is_err() {
            self.fail();
            self.manifest.sites.get_mut(site).unwrap().config.enabled = false;
        }
        result
    }
    fn publish(&self, site: &str) -> Result<()> {
        // The writer alone handles controls and data. Publishing this revision
        // rejects every old queued/in-flight producer, even after re-enabling.
        let mut gates = self.shared.gates.lock().map_err(|_| Error::Storage)?;
        let revision = gates
            .get(site)
            .map(|g| g.revision)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::Storage)?;
        gates.insert(
            site.into(),
            Gate {
                meta: self.manifest.sites[site].clone(),
                revision,
            },
        );
        Ok(())
    }
    fn delete(&mut self, site: &str, permanent: bool) -> Result<u64> {
        if self.manifest.pending_operation.is_some() {
            return Err(Error::Unavailable);
        }
        if !permanent && !self.manifest.sites.contains_key(site) {
            return Ok(0); // Unknown ordinary deletes never consume metadata.
        }
        if self.manifest.sites.get(site).is_some_and(|s| s.tombstoned) {
            return Ok(self.manifest.sites[site].epoch);
        }
        if permanent
            && self
                .manifest
                .sites
                .values()
                .filter(|s| s.tombstoned)
                .count()
                >= MAX_RETIRED
        {
            return Err(Error::Capacity);
        }
        if permanent && !self.manifest.sites.contains_key(site) {
            // Unknown retirements use only the retired budget, not active slots.
            self.manifest.sites.insert(
                site.into(),
                SiteMeta {
                    config: SiteConfig::default(),
                    epoch: 1,
                    tombstoned: true,
                    configuring: false,
                },
            );
        } else {
            self.ensure_site(site)?;
        }
        let meta = self.manifest.sites.get_mut(site).unwrap();
        if permanent {
            meta.config.enabled = false;
            meta.tombstoned = true;
        }
        meta.epoch = meta.epoch.checked_add(1).ok_or(Error::Storage)?;
        let epoch = meta.epoch;
        let id = self.manifest.next_sequence;
        self.manifest.next_sequence = id.checked_add(1).ok_or(Error::Storage)?;
        self.manifest.pending_operation = Some(Operation {
            id,
            action: if permanent {
                "site_retire"
            } else {
                "site_data_delete"
            }
            .into(),
            site: site.into(),
            epoch,
        });
        let result = (|| {
            self.persist()?; // Epoch and recovery intent commit atomically.
            self.publish(site)?;
            self.finish_operation()?;
            Ok(epoch)
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn finish_operation(&mut self) -> Result<()> {
        let Some(op) = self.manifest.pending_operation.clone() else {
            return Ok(());
        };
        let site = op.site.as_str();
        let dir = self.root.join(site);
        private_dir(&dir)?;
        for e in bounded_entries(&dir, MAX_FILES)? {
            if !e.file_type()?.is_file() {
                return Err(Error::Storage);
            }
            fs::remove_file(e.path())?;
        }
        File::open(dir)?.sync_all()?;
        self.total = self.total.saturating_sub(self.site_bytes(site));
        self.segments.insert(site.into(), Vec::new());
        self.audit_operation(&op)?;
        self.manifest.pending_operation = None;
        if let Err(e) = self.persist() {
            self.manifest.pending_operation = Some(op);
            return Err(e);
        }
        Ok(())
    }
    fn prune(&mut self) -> Result<()> {
        let time = now();
        for (site, segments) in &mut self.segments {
            let config = &self.manifest.sites[site].config;
            let mut bytes: u64 = segments.iter().map(|s| s.bytes).sum();
            let mut i = 0;
            while i < segments.len() {
                if time >= segments[i].at.saturating_add(config.retention_secs)
                    || bytes > config.cap_bytes
                {
                    let s = &segments[i];
                    fs::remove_file(&s.path)?;
                    bytes -= s.bytes;
                    self.total -= s.bytes;
                    segments.remove(i);
                } else {
                    i += 1;
                }
            }
        }
        Ok(())
    }
    fn record(&mut self, p: Pending) -> Result<()> {
        let g = self
            .shared
            .gates
            .lock()
            .map_err(|_| Error::Storage)?
            .get(&p.site)
            .cloned();
        let accept = g.as_ref().is_some_and(|g| {
            g.meta.config.enabled
                && g.meta.epoch == p.epoch
                && g.revision == p.revision
                && p.at.saturating_add(g.meta.config.retention_secs) > now()
        });
        if !accept || p.bytes.len() > MAX_SAMPLE_BYTES {
            if p.bytes.len() > MAX_SAMPLE_BYTES {
                self.shared.invalid_dropped.fetch_add(1, Ordering::Relaxed);
            } else if g
                .as_ref()
                .is_some_and(|g| p.at.saturating_add(g.meta.config.retention_secs) <= now())
            {
                self.shared.expired_dropped.fetch_add(1, Ordering::Relaxed);
            }
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let config = &g.unwrap().meta.config;
        let n = p.bytes.len() as u64;
        if self.total + n > DATA_CAP || self.site_bytes(&p.site) + n > config.cap_bytes {
            self.shared.byte_cap_dropped.fetch_add(1, Ordering::Relaxed);
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let segments = self.segments.entry(p.site.clone()).or_default();
        let rotate = segments.last().is_none_or(|s| {
            s.bytes + n > SEGMENT_BYTES || p.at < s.at || p.at >= s.at.saturating_add(SEGMENT_SECS)
        });
        if rotate {
            if segments.len() >= MAX_FILES {
                self.shared
                    .segment_cap_dropped
                    .fetch_add(1, Ordering::Relaxed);
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            // Durable, never-reused sequence prevents an expired cursor from
            // accidentally addressing a later segment (including after restart).
            let sequence = self.manifest.next_sequence;
            self.manifest.next_sequence = sequence.checked_add(1).ok_or(Error::Storage)?;
            self.persist()?;
            let path = self
                .root
                .join(&p.site)
                .join(format!("{}-{}-{}.jsonl", p.epoch, sequence, p.at));
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.sync_all()?;
            File::open(self.root.join(&p.site))?.sync_all()?;
            self.segments.get_mut(&p.site).unwrap().push(Segment {
                epoch: p.epoch,
                sequence,
                at: p.at,
                bytes: 0,
                path,
            });
        }
        let s = self.segments.get_mut(&p.site).unwrap().last_mut().unwrap();
        let mut f = file(&s.path, false)?;
        f.seek(SeekFrom::End(0))?;
        f.write_all(&p.bytes)?;
        f.sync_data()?;
        s.bytes += n;
        self.total += n;
        self.shared.written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn audit(&self, action: &'static str, site: &str) -> Result<()> {
        // Only static action, hashed site, and server timestamp. No cursor,
        // exported rows, credentials, caller-provided reason, or original site.
        let row = format!(
            "{{\"at\":{},\"action\":\"{}\",\"site_hash\":\"{}\"}}\n",
            now(),
            action,
            site
        );
        self.append_audit(&row)
    }
    fn audit_operation(&self, op: &Operation) -> Result<()> {
        // No other controls execute while this slot is pending, so its entry
        // cannot age out of the bounded pair before the completion checkpoint.
        for name in ["audit.jsonl", "audit.previous"] {
            let path = self.root.join(name);
            if !path.exists() {
                continue;
            }
            let mut f = file(&path, false)?;
            if f.metadata()?.len() > AUDIT_BYTES {
                return Err(Error::Capacity);
            }
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            for line in bytes.split_inclusive(|b| *b == b'\n') {
                if line.last() != Some(&b'\n') {
                    continue;
                }
                let row: serde_json::Value = serde_json::from_slice(line)?;
                if row["operation_id"].as_u64() == Some(op.id) {
                    if row["action"].as_str() != Some(&op.action)
                        || row["epoch"].as_u64() != Some(op.epoch)
                        || row["site_hash"].as_str() != Some(&op.site)
                    {
                        return Err(Error::Storage);
                    }
                    f.sync_all()?;
                    File::open(&self.root)?.sync_all()?;
                    return Ok(());
                }
            }
        }
        self.append_audit(&format!(
            "{{\"at\":{},\"action\":\"{}\",\"site_hash\":\"{}\",\"operation_id\":{},\"epoch\":{}}}\n",
            now(), op.action, op.site, op.id, op.epoch
        ))
    }
    fn append_audit(&self, row: &str) -> Result<()> {
        let path = self.root.join("audit.jsonl");
        let mut f = file(&path, true)?;
        if f.metadata()?.len() > AUDIT_BYTES {
            return Err(Error::Capacity);
        }
        // Remove an interrupted final append before attempting the same operation.
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        f.set_len(complete as u64)?;
        if f.metadata()?.len() + row.len() as u64 > AUDIT_BYTES {
            drop(f);
            fs::rename(&path, self.root.join("audit.previous"))?;
            f = file(&path, true)?;
        }
        f.seek(SeekFrom::End(0))?;
        f.write_all(row.as_bytes())?;
        f.sync_all()?;
        // Covers both first creation and rename/recreation on rotation.
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn encode_cursor(&self, cursor: &Cursor) -> Result<String> {
        let mut bytes = serde_json::to_vec(cursor)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.manifest.cursor_key)
            .map_err(|_| Error::Storage)?;
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
    fn decode_cursor(&self, text: &str, site: &str, epoch: u64) -> Result<Cursor> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| Error::InvalidCursor)?;
        if bytes.len() <= 32 {
            return Err(Error::InvalidCursor);
        }
        let (payload, tag) = bytes.split_at(bytes.len() - 32);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.manifest.cursor_key)
            .map_err(|_| Error::Storage)?;
        mac.update(payload);
        mac.verify_slice(tag).map_err(|_| Error::InvalidCursor)?;
        let c: Cursor = serde_json::from_slice(payload).map_err(|_| Error::InvalidCursor)?;
        if c.site != site || c.epoch != epoch || c.offset > SEGMENT_BYTES {
            return Err(Error::InvalidCursor);
        }
        Ok(c)
    }
    fn export(&mut self, site: &str, cursor: Option<String>, limit: usize) -> Result<ExportPage> {
        if self.manifest.pending_operation.is_some() {
            return Err(Error::Unavailable);
        }
        self.prune()?;
        let epoch = self.manifest.sites.get(site).map(|m| m.epoch).unwrap_or(0);
        let c = cursor
            .as_deref()
            .map(|s| self.decode_cursor(s, site, epoch))
            .transpose()?;
        self.audit("export", site)?;
        let segments = self.segments.get(site).map(Vec::as_slice).unwrap_or(&[]);
        let mut index = match &c {
            Some(c) => segments
                .iter()
                .position(|s| s.sequence == c.sequence)
                .ok_or(Error::InvalidCursor)?,
            None => 0,
        };
        let mut offset = c.map(|c| c.offset).unwrap_or(0);
        let mut samples = Vec::with_capacity(limit);
        let mut next_cursor = None;
        while index < segments.len() {
            let s = &segments[index];
            if s.epoch != epoch || offset > s.bytes {
                return Err(Error::InvalidCursor);
            }
            let mut f = file(&s.path, false)?;
            f.seek(SeekFrom::Start(offset))?;
            let mut reader = BufReader::new(f);
            while offset < s.bytes {
                if samples.len() == limit {
                    next_cursor = Some(self.encode_cursor(&Cursor {
                        site: site.into(),
                        epoch,
                        sequence: s.sequence,
                        offset,
                    })?);
                    return Ok(ExportPage {
                        samples,
                        next_cursor,
                        epoch,
                    });
                }
                let mut line = Vec::new();
                let n = reader
                    .by_ref()
                    .take((MAX_SAMPLE_BYTES + 1) as u64)
                    .read_until(b'\n', &mut line)?;
                if n == 0 || n > MAX_SAMPLE_BYTES || line.last() != Some(&b'\n') {
                    return Err(Error::Storage);
                }
                offset += n as u64;
                let row: StoredSample = serde_json::from_slice(&line)?;
                if !row.sample.valid() {
                    return Err(Error::Storage);
                }
                let retention = self.manifest.sites[site].config.retention_secs;
                if row.recorded_at.saturating_add(retention) > now() {
                    samples.push(row);
                }
            }
            index += 1;
            offset = 0;
        }
        Ok(ExportPage {
            samples,
            next_cursor,
            epoch,
        })
    }
}
