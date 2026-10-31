//! `cap-instr` — Rust port of the Cap instrumentation (probe) generator.
//!
//! Each challenge ships a per-session JavaScript script that runs inside a
//! sandboxed iframe, collects environment signals, computes a small state value
//! and posts `{type:'cap:instr', nonce:<id>, result:{i,state,p,ts[,mac]}}` to the
//! parent page. The server verifies the state against `expected_vals` (and the
//! HMAC against `mac_key` when signing was requested).
//!
//! Phase-1 scope
//! -------------
//! * `obfuscation_level` is clamped to `1..=10` and currently a **no-op**: the
//!   whitespace normalisation below is applied for every level. The JS
//!   implementation runs esbuild minification (levels 4..=7) and
//!   `javascript-obfuscator` (levels 8..=10); those are native JS toolchains
//!   and are not ported yet. `script_hash` is computed over
//!   the exact text returned in `script`.
//! * `script` is the *uncompressed* body. The JS generator additionally
//!   raw-deflates + base64-encodes it for transport (`instrumentation`); that
//!   belongs to the transport layer, not this crate.
//! * Two documented deviations from the reference are listed in `state.rs`
//!   (DOM-free op-5 helper) and `probes.rs` (IIFE extended probes are emitted as
//!   functions so they actually run).
//!
//! Nothing here panics on out-of-range options; values are clamped.

mod crypto;
pub mod mac;
mod probes;
mod rng;
mod script;
mod state;

pub use crypto::sha256_hex;
pub use mac::{js_f64, js_stringify, verify_result_mac};
pub use probes::{EXTENDED_PROBE_KEYS, PROBE_FONT_STACK_COUNT, PROBE_FONT_STACKS};

use rng::{Namer, Rng};
use script::ScriptInput;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default challenge TTL, matching `DEFAULT_TTL_MS` in the JS generator.
pub const DEFAULT_TTL_MS: i64 = 5 * 60 * 1000;

/// Which optional consistency probes to run.
#[derive(Debug, Clone, Copy)]
pub enum ExtProbes<'a> {
    /// No extended probes (`extended_fields` is `None`).
    Off,
    /// Every key in [`EXTENDED_PROBE_KEYS`].
    All,
    /// The intersection of this list with [`EXTENDED_PROBE_KEYS`].
    List(&'a [&'a str]),
}

#[derive(Debug, Clone, Copy)]
pub struct InstrOptions<'a> {
    pub block_automated_browsers: bool,
    pub extended_probes: ExtProbes<'a>,
    /// 0.0..=1.0. When > 0 and more than two extended probes are selected, a
    /// random subset is dropped (always keeping `platform` and `workerUA`).
    pub polymorphism: f64,
    /// When true a per-session 32-hex-char MAC key is generated and the client
    /// HMACs the result (WebCrypto, domain string `cap-instr`).
    pub sign_results: bool,
    /// 1..=10; clamped. Currently a no-op beyond whitespace normalisation.
    pub obfuscation_level: u8,
    pub ttl_ms: i64,
}

impl Default for InstrOptions<'_> {
    fn default() -> Self {
        InstrOptions {
            block_automated_browsers: false,
            extended_probes: ExtProbes::Off,
            polymorphism: 0.0,
            sign_results: false,
            obfuscation_level: 3,
            ttl_ms: DEFAULT_TTL_MS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstrChallenge {
    /// 32 lowercase hex chars (16 random bytes), same shape as the JS `rHex(32)`.
    pub id: String,
    /// Four unique, valid JS identifiers (`^[a-z][a-z0-9]*$`).
    pub vars: [String; 4],
    /// The values the emitted script computes for `vars` in a normal browser,
    /// each in `100_000..1_000_000`.
    pub expected_vals: [i64; 4],
    /// The full probe script (uncompressed).
    pub script: String,
    /// `sha256(script)` as lowercase hex.
    pub script_hash: String,
    /// 32 lowercase hex chars when `sign_results` (16 bytes of entropy, exactly
    /// like the JS `rHex(32)`), else `None`.
    pub mac_key: Option<String>,
    /// Resolved extended probe keys, or `None` when extended probes are off.
    pub extended_fields: Option<Vec<String>>,
    pub block_automated_browsers: bool,
    /// `now + ttl_ms` (unix millis).
    pub expires: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Generate a fresh challenge from OS entropy.
pub fn generate(opts: &InstrOptions<'_>) -> InstrChallenge {
    let mut rng = Rng::from_entropy();
    build(&mut rng, opts, now_ms())
}

/// Generate a challenge deterministically from `seed` (expiry still uses the
/// wall clock). Useful for tests and reproducible fixtures.
pub fn generate_with_seed(opts: &InstrOptions<'_>, seed: u64) -> InstrChallenge {
    let mut rng = Rng::from_seed(seed);
    build(&mut rng, opts, now_ms())
}

/// Fully deterministic variant: the caller supplies both the seed and `now`.
pub fn generate_at(opts: &InstrOptions<'_>, seed: u64, now: i64) -> InstrChallenge {
    let mut rng = Rng::from_seed(seed);
    build(&mut rng, opts, now)
}

fn build(rng: &mut Rng, opts: &InstrOptions<'_>, now: i64) -> InstrChallenge {
    let id = rng.hex(16);
    let mac_key = if opts.sign_results {
        Some(rng.hex(16))
    } else {
        None
    };

    let polymorphism = clamp01(opts.polymorphism);
    let extended = probes::resolve_extended_fields(rng, &opts.extended_probes, polymorphism);

    let mut namer = Namer::new();
    let plan = state::plan_state(rng, &mut namer);

    let raw = script::build_script(
        rng,
        &mut namer,
        &ScriptInput {
            id: &id,
            vars: &plan.vars,
            init_vals: &plan.init_vals,
            client_eqs: &plan.client_eqs,
            block_automated_browsers: opts.block_automated_browsers,
            extended: extended.as_deref(),
            mac_key: mac_key.as_deref(),
        },
    );
    let script = script::apply_obfuscation(raw, opts.obfuscation_level);
    let script_hash = crypto::sha256_hex(&script);

    InstrChallenge {
        id,
        vars: plan.vars,
        expected_vals: plan.expected,
        script,
        script_hash,
        mac_key,
        extended_fields: extended,
        block_automated_browsers: opts.block_automated_browsers,
        expires: now.saturating_add(opts.ttl_ms.max(0)),
    }
}

fn clamp01(x: f64) -> f64 {
    if x.is_nan() {
        0.0
    } else if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_hex(s: &str, len: usize) -> bool {
        s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    #[test]
    fn shape_ranges_and_uniqueness() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..200 {
            let c = generate(&InstrOptions::default());
            assert!(is_hex(&c.id, 32), "id {:?}", c.id);
            assert!(ids.insert(c.id.clone()), "duplicate id");
            for v in &c.vars {
                assert!(!v.is_empty());
                assert!(v.chars().next().unwrap().is_ascii_lowercase());
                assert!(v.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit()));
            }
            let mut seen = std::collections::HashSet::new();
            for v in &c.vars {
                assert!(seen.insert(v.clone()), "duplicate var name");
            }
            for v in c.expected_vals {
                assert!((100_000..1_000_000).contains(&v), "expected {} ", v);
            }
            assert!(is_hex(&c.script_hash, 64));
            assert_eq!(c.script_hash, sha256_hex(&c.script));
            assert!(c.script.len() > 1000);
            assert!(c.mac_key.is_none());
            assert!(c.extended_fields.is_none());
        }
    }

    #[test]
    fn seeded_generation_is_deterministic() {
        let opts = InstrOptions {
            block_automated_browsers: true,
            extended_probes: ExtProbes::All,
            polymorphism: 0.5,
            sign_results: true,
            obfuscation_level: 7,
            ttl_ms: 1234,
        };
        let a = generate_at(&opts, 0xDEAD_BEEF, 1_700_000_000_000);
        let b = generate_at(&opts, 0xDEAD_BEEF, 1_700_000_000_000);
        assert_eq!(a.id, b.id);
        assert_eq!(a.vars, b.vars);
        assert_eq!(a.expected_vals, b.expected_vals);
        assert_eq!(a.script, b.script);
        assert_eq!(a.script_hash, b.script_hash);
        assert_eq!(a.mac_key, b.mac_key);
        assert_eq!(a.extended_fields, b.extended_fields);
        assert_eq!(a.expires, 1_700_000_001_234);

        let c = generate_at(&opts, 0xDEAD_BEF0, 1_700_000_000_000);
        assert_ne!(a.id, c.id);
        assert_ne!(a.script, c.script);
    }

    #[test]
    fn extended_field_selection() {
        let base = InstrOptions::default();

        assert!(generate_at(&base, 1, 0).extended_fields.is_none());

        let all = generate_at(
            &InstrOptions {
                extended_probes: ExtProbes::All,
                ..base
            },
            1,
            0,
        );
        let keys = all.extended_fields.expect("all");
        assert_eq!(keys.len(), EXTENDED_PROBE_KEYS.len());
        for k in EXTENDED_PROBE_KEYS {
            assert!(keys.iter().any(|x| x == k), "missing {}", k);
        }

        let list = ["canvas", "nope", "webgl"];
        let some = generate_at(
            &InstrOptions {
                extended_probes: ExtProbes::List(&list),
                ..base
            },
            1,
            0,
        );
        assert_eq!(
            some.extended_fields.unwrap(),
            vec!["webgl".to_string(), "canvas".to_string()]
        );

        // polymorphism drops fields but never the two cross-checks
        for seed in 0..40 {
            let c = generate_at(
                &InstrOptions {
                    extended_probes: ExtProbes::All,
                    polymorphism: 1.0,
                    ..base
                },
                seed,
                0,
            );
            let keys = c.extended_fields.unwrap();
            assert!(keys.iter().any(|k| k == "platform"));
            assert!(keys.iter().any(|k| k == "workerUA"));
            assert!(keys.len() <= EXTENDED_PROBE_KEYS.len());
        }
    }

    #[test]
    fn signing_toggles_mac_key_and_emitted_mac() {
        let signed = generate_at(
            &InstrOptions {
                sign_results: true,
                ..InstrOptions::default()
            },
            5,
            0,
        );
        let key = signed.mac_key.clone().expect("mac key");
        assert!(is_hex(&key, 32));
        assert!(signed.script.contains("__cR.mac"));
        assert!(signed.script.contains("'cap-instr|'"));

        let unsigned = generate_at(&InstrOptions::default(), 5, 0);
        assert!(unsigned.mac_key.is_none());
        assert!(!unsigned.script.contains("__cR.mac"));
    }

    #[test]
    fn protocol_markers_present() {
        let c = generate_at(&InstrOptions::default(), 9, 0);
        for marker in [
            "cap:instr",
            "parent.postMessage",
            "state:",
            "ts:Date.now()",
            "\"ua\",function()",
            "\"productSub\"",
            "\"tamper\"",
        ] {
            assert!(c.script.contains(marker), "missing marker {:?}", marker);
        }
        // The probe object is posted under `p`.
        assert!(c.script.contains(",p:"));
    }

    #[test]
    fn ttl_and_clamping() {
        let c = generate_at(
            &InstrOptions {
                ttl_ms: -5,
                obfuscation_level: 250,
                polymorphism: f64::NAN,
                ..InstrOptions::default()
            },
            3,
            1_000,
        );
        assert_eq!(c.expires, 1_000);

        let d = generate_with_seed(
            &InstrOptions {
                ttl_ms: 60_000,
                obfuscation_level: 0,
                ..InstrOptions::default()
            },
            3,
        );
        assert!(d.expires > now_ms() + 50_000);
    }

    #[test]
    fn block_automated_browsers_flows_through() {
        let off = generate_at(&InstrOptions::default(), 8, 0);
        assert!(!off.block_automated_browsers);
        assert!(!off.script.contains("blocked: true"));

        let on = generate_at(
            &InstrOptions {
                block_automated_browsers: true,
                ..InstrOptions::default()
            },
            8,
            0,
        );
        assert!(on.block_automated_browsers);
        assert!(on.script.contains("blocked: true"));
        assert!(on.script.len() > off.script.len());
    }

    #[test]
    fn obfuscation_level_is_noop_but_valid() {
        let opts = |lvl| InstrOptions {
            obfuscation_level: lvl,
            ..InstrOptions::default()
        };
        let a = generate_at(&opts(1), 21, 0);
        let b = generate_at(&opts(10), 21, 0);
        // Documented phase-1 behaviour: level currently does not change output.
        assert_eq!(a.script, b.script);
        assert_eq!(a.script_hash, b.script_hash);
    }
}

/// Compress the probe script the way the JS server does: raw DEFLATE followed
/// by standard base64 (`deflateRawSync(...).toString("base64")`). The widget
/// base64-decodes and inflates this back into the executable script.
pub fn script_blob(script: &str) -> String {
    use base64::Engine as _;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(script.as_bytes()).expect("deflate");
    let compressed = enc.finish().expect("deflate finish");
    base64::engine::general_purpose::STANDARD.encode(compressed)
}

#[cfg(test)]
mod blob_tests {
    use super::*;

    #[test]
    fn blob_roundtrips_through_raw_deflate() {
        use base64::Engine as _;
        use flate2::read::DeflateDecoder;
        use std::io::Read;

        let script = "function probe(){return 42}\n".repeat(20);
        let blob = script_blob(&script);
        // Standard base64 alphabet (the widget uses atob()).
        assert!(blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&blob)
            .expect("b64");
        let mut out = String::new();
        DeflateDecoder::new(&raw[..]).read_to_string(&mut out).unwrap();
        assert_eq!(out, script);
        assert!(blob.len() < script.len());
    }
}
