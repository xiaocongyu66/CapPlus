//! Demo mode: synthetic keys and charts so the dashboard can be explored
//! without a real deployment. Mirrors `standalone/src/demo.js`.
//!
//! Read-only by design — mutating routes are answered by the demo write guard
//! in `lib.rs` and never reach this module.

use serde_json::{Value, json};

use crate::util;

struct DemoKey {
    site_key: &'static str,
    name: &'static str,
    days_ago: i64,
    /// Requests over the lifetime of the key (91 days).
    traffic: i64,
    fail_rate: f64,
    config: fn() -> Value,
}

fn config_prod() -> Value {
    json!({
        "protocol": "hashwx", "hashwxDifficulty": 1000000, "rsw": false,
        "difficulty": 4, "challengeCount": 80, "saltSize": 32,
        "instrumentation": true, "obfuscationLevel": 5,
        "blockAutomatedBrowsers": true, "ratelimitMax": null,
        "ratelimitDuration": null, "corsOrigins": ["example.com", "www.example.com"],
        "blockNonBrowserUA": true, "requiredHeaders": ["accept-language", "sec-ch-ua"],
    })
}

fn config_mobile() -> Value {
    json!({
        "protocol": "hashwx", "hashwxDifficulty": 250000, "rsw": false,
        "difficulty": 3, "challengeCount": 50, "saltSize": 32,
        "instrumentation": true, "obfuscationLevel": 3,
        "blockAutomatedBrowsers": false, "ratelimitMax": 50,
        "ratelimitDuration": 10000, "corsOrigins": null,
        "blockNonBrowserUA": false, "requiredHeaders": null,
    })
}

fn config_checkout() -> Value {
    json!({
        "protocol": "rsw", "rsw": true, "rswT": 75000,
        "difficulty": 5, "challengeCount": 120, "saltSize": 32,
        "instrumentation": true, "obfuscationLevel": 4,
        "blockAutomatedBrowsers": true, "ratelimitMax": 20,
        "ratelimitDuration": 5000, "corsOrigins": ["shop.example.com"],
        "blockNonBrowserUA": true, "requiredHeaders": null,
    })
}

fn config_cdn() -> Value {
    json!({
        "protocol": "sha256-pow", "difficulty": 3, "challengeCount": 40,
        "saltSize": 32, "instrumentation": false, "obfuscationLevel": 2,
        "blockAutomatedBrowsers": false, "ratelimitMax": null,
        "ratelimitDuration": null, "corsOrigins": null,
        "blockNonBrowserUA": false, "requiredHeaders": null,
    })
}

const DEMO_KEYS: [DemoKey; 7] = [
    DemoKey { site_key: "a1b2c3d4e5", name: "production-web", days_ago: 90, traffic: 2_800_000, fail_rate: 0.06, config: config_prod },
    DemoKey { site_key: "f6g7h8i9j0", name: "mobile-app", days_ago: 75, traffic: 420_000, fail_rate: 0.04, config: config_mobile },
    DemoKey { site_key: "k1l2m3n4o5", name: "checkout-flow", days_ago: 60, traffic: 890_000, fail_rate: 0.09, config: config_checkout },
    DemoKey { site_key: "p6q7r8s9t0", name: "docs-site", days_ago: 45, traffic: 64_000, fail_rate: 0.03, config: config_cdn },
    DemoKey { site_key: "u1v2w3x4y5", name: "staging", days_ago: 30, traffic: 12_000, fail_rate: 0.11, config: config_mobile },
    DemoKey { site_key: "z6a7b8c9d0", name: "partner-api", days_ago: 14, traffic: 5_400, fail_rate: 0.05, config: config_cdn },
    DemoKey { site_key: "e1f2g3h4i5", name: "personal-blog", days_ago: 3, traffic: 210, fail_rate: 0.02, config: config_cdn },
];

fn hash_str(s: &str) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

/// Deterministic PRNG identical in spirit to `mulberry32` (0..1).
fn mulberry32(seed: u32) -> impl FnMut() -> f64 {
    let mut a = seed;
    move || {
        a = a.wrapping_add(0x6d2b_79f5);
        let mut t = a;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        ((t ^ (t >> 14)) as f64) / 4_294_967_296.0
    }
}

fn find(site_key: &str) -> Option<&'static DemoKey> {
    DEMO_KEYS.iter().find(|k| k.site_key == site_key)
}

fn created_ms(key: &DemoKey) -> i64 {
    util::now_ms() - key.days_ago * 86_400_000
}

pub fn keys_list() -> Value {
    Value::Array(
        DEMO_KEYS
            .iter()
            .map(|key| {
                let mut rng = mulberry32(hash_str(&format!("{}24h", key.site_key)));
                let daily = key.traffic as f64 / 91.0;
                let current = (daily * (0.8 + rng() * 0.4)).round() as i64;
                let previous = (daily * (0.8 + rng() * 0.4)).round() as i64;
                let (change, direction) = if previous > 0 {
                    (
                        (current - previous) as f64 / previous as f64 * 100.0,
                        if current > previous {
                            "up"
                        } else if current < previous {
                            "down"
                        } else {
                            ""
                        },
                    )
                } else if current > 0 {
                    (100.0, "up")
                } else {
                    (0.0, "")
                };
                json!({
                    "siteKey": key.site_key,
                    "name": key.name,
                    "created": created_ms(key),
                    "config": (key.config)(),
                    "solvesLast24h": current,
                    "difference": { "value": format!("{change:.2}"), "direction": direction },
                })
            })
            .collect(),
    )
}

/// Buckets for the requested window and synthetic per-bucket counts.
fn chart(key: &DemoKey, duration: &str) -> (Value, Value, Value) {
    let now = util::now_ms() / 1000;
    let daily = key.traffic as f64 / 91.0;
    let (bucket_size, start, end): (i64, i64, i64) = match duration {
        "today" => (3600, now / 86_400 * 86_400, now / 3600 * 3600 + 3600),
        "yesterday" => {
            let s = (now / 86_400) * 86_400 - 86_400;
            (3600, s, s + 86_400)
        }
        "last7days" => (86_400, (now / 86_400) * 86_400 - 6 * 86_400, now / 86_400 * 86_400 + 86_400),
        "last28days" => (86_400, (now / 86_400) * 86_400 - 27 * 86_400, now / 86_400 * 86_400 + 86_400),
        "last91days" => (86_400, (now / 86_400) * 86_400 - 90 * 86_400, now / 86_400 * 86_400 + 86_400),
        "alltime" => (86_400, now - 91 * 86_400, now + 86_400),
        _ => (3600, now - 86_400, now + 3600),
    };

    let mut rng = mulberry32(hash_str(&format!("{}{duration}", key.site_key)));
    let mut data = Vec::new();
    let (mut total_verified, mut total_failed) = (0i64, 0i64);
    let mut b = start;
    while b < end {
        let share = if bucket_size == 3600 {
            daily / 24.0
        } else {
            daily
        };
        let challenges = (share * (0.75 + rng() * 0.5)).round() as i64;
        let failed = (challenges as f64 * key.fail_rate * (0.6 + rng() * 0.8)).round() as i64;
        let verified = (challenges - failed).max(0);
        let rate_limited = (challenges as f64 * 0.01 * rng()).round() as i64;
        total_verified += verified;
        total_failed += failed;
        data.push(json!({
            "bucket": b,
            "challenges": challenges,
            "verified": verified,
            "failed": failed,
            "rateLimited": rate_limited,
        }));
        b += bucket_size;
    }

    let avg_latency = (60.0 + rng() * 140.0).round() as i64;
    let stats = json!({
        "challenges": total_verified + total_failed,
        "verified": total_verified,
        "failed": total_failed,
        "avgLatency": avg_latency,
        "rateLimited": (total_verified as f64 * 0.008).round() as i64,
    });
    let prev = json!({
        "challenges": (stats["challenges"].as_i64().unwrap_or(0) as f64 * 0.92) as i64,
        "verified": (total_verified as f64 * 0.92) as i64,
        "failed": (total_failed as f64 * 0.95) as i64,
        "avgLatency": (avg_latency as f64 * 1.04) as i64,
        "rateLimited": (stats["rateLimited"].as_i64().unwrap_or(0) as f64 * 0.9) as i64,
    });
    let chart_data = json!({
        "duration": duration,
        "bucketSize": bucket_size,
        "data": data,
    });
    (stats, prev, chart_data)
}

pub fn key_detail(site_key: &str, duration: &str) -> Option<Value> {
    let key = find(site_key)?;
    let (stats, prev, chart_data) = chart(key, duration);
    Some(json!({
        "key": {
            "siteKey": key.site_key,
            "name": key.name,
            "created": created_ms(key),
            "config": (key.config)(),
        },
        "stats": stats,
        "prevStats": if duration == "alltime" { Value::Null } else { prev },
        "chartData": chart_data,
    }))
}

pub fn geo_stats(site_key: &str) -> Value {
    let key = match find(site_key) {
        Some(k) => k,
        None => {
            return json!({
                "countries": [], "totalCountry": 0,
                "asns": [], "totalAsn": 0,
                "platforms": [], "totalPlatform": 0,
                "oses": [], "totalOs": 0,
            })
        }
    };
    let total = (key.traffic as f64 / 91.0).round() as i64;
    json!({
        "countries": [
            {"code": "US", "count": total * 38 / 100},
            {"code": "DE", "count": total * 17 / 100},
            {"code": "GB", "count": total * 12 / 100},
            {"code": "BR", "count": total * 9 / 100},
            {"code": "IN", "count": total * 7 / 100},
            {"code": "JP", "count": total * 5 / 100},
        ],
        "totalCountry": total * 88 / 100,
        "asns": [
            {"name": "AS15169 Google LLC", "count": total * 22 / 100},
            {"name": "AS16509 Amazon.com, Inc.", "count": total * 18 / 100},
            {"name": "AS13335 Cloudflare, Inc.", "count": total * 14 / 100},
            {"name": "AS8075 Microsoft Corporation", "count": total * 11 / 100},
        ],
        "totalAsn": total * 65 / 100,
        "platforms": [
            {"name": "Desktop", "count": total * 54 / 100},
            {"name": "Phone", "count": total * 39 / 100},
            {"name": "Tablet", "count": total * 7 / 100},
        ],
        "totalPlatform": total,
        "oses": [
            {"name": "Windows", "count": total * 34 / 100},
            {"name": "macOS", "count": total * 21 / 100},
            {"name": "Android", "count": total * 24 / 100},
            {"name": "iOS", "count": total * 15 / 100},
            {"name": "Linux", "count": total * 6 / 100},
        ],
        "totalOs": total,
    })
}

pub fn sessions() -> Value {
    let now = util::now_ms();
    json!([
        {
            "token": "d3mo-Session-Key-01",
            "expires": now + 25 * 86_400_000,
        }
    ])
}

pub fn api_keys() -> Value {
    json!([
        {
            "id": "demo-key-1",
            "name": "read-only",
            "siteKeys": null,
            "readonly": true,
            "created": util::now_ms() - 3 * 86_400_000,
            "lastUsed": Value::Null,
        }
    ])
}

pub fn shares(site_key: &str) -> Value {
    if find(site_key).is_none() {
        return Value::Array(Vec::new());
    }
    json!([
        {
            "id": "demo-share-1",
            "name": "Public stats",
            "created": util::now_ms() - 2 * 86_400_000,
            "expires": Value::Null,
        }
    ])
}

pub fn blocked_ips(site_key: &str) -> Value {
    if find(site_key).is_none() {
        return Value::Array(Vec::new());
    }
    let now = util::now_ms();
    json!([
        {"ip": "203.0.113.42", "type": "ip", "permanent": true, "expires": Value::Null},
        {"ip": "198.51.100.0/24", "type": "cidr", "permanent": false, "expires": now + 3_600_000},
        {"ip": "AS4134", "type": "asn", "permanent": false, "expires": now + 86_400_000},
    ])
}
