//! Buffered metric writes.
//!
//! Every challenge/redeem writes a handful of `HINCRBY`s (latency, platform,
//! OS, verified, geo) — 2-4 Redis round trips per request that the client never
//! waits for semantically. They are counters, not state: a lost second on a
//! crash is acceptable, so they are accumulated in memory and flushed in one
//! pipeline per second.

use std::collections::HashMap;
use std::sync::Mutex;

use cap_kv::Kv;

type Entry = (String, String);

#[derive(Default)]
pub struct MetricsBuffer {
    /// `metric:key` + field -> increment
    counters: Mutex<HashMap<Entry, i64>>,
    /// latency key -> (sum, count) per field
    latencies: Mutex<HashMap<Entry, (i64, i64)>>,
}

impl MetricsBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn incr(&self, name: &str, field: &str, by: i64) {
        let mut m = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        *m.entry((name.to_string(), field.to_string())).or_insert(0) += by;
    }

    /// Record one latency sample: `sum_key` gets `+ms`, `count_key` gets `+1`.
    pub fn latency(&self, sum_key: &str, count_key: &str, field: &str, ms: i64) {
        let mut m = self.latencies.lock().unwrap_or_else(|e| e.into_inner());
        let entry = m
            .entry((sum_key.to_string(), field.to_string()))
            .or_insert((0, 0));
        entry.0 += ms;
        entry.1 += 1;
        let mut c = self.counters.lock().unwrap_or_else(|e| e.into_inner());
        *c.entry((count_key.to_string(), field.to_string()))
            .or_insert(0) += 1;
    }

    /// Take everything accumulated so far.
    fn drain(&self) -> Vec<(String, String, i64)> {
        let mut out = Vec::new();
        {
            let mut m = self.counters.lock().unwrap_or_else(|e| e.into_inner());
            out.reserve(m.len());
            for ((name, field), by) in m.drain() {
                if by != 0 {
                    out.push((name, field, by));
                }
            }
        }
        {
            let mut m = self.latencies.lock().unwrap_or_else(|e| e.into_inner());
            for ((name, field), (sum, _)) in m.drain() {
                if sum != 0 {
                    out.push((name, field, sum));
                }
            }
        }
        out
    }

    /// Write buffered counters. Call once per flush interval.
    pub async fn flush(&self, kv: &Kv) -> Result<usize, cap_kv::KvError> {
        let items = self.drain();
        if items.is_empty() {
            return Ok(0);
        }
        kv.hincrby_many(&items).await?;
        Ok(items.len())
    }
}
