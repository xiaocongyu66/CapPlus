//! In-process fixed-window rate limiter.
//!
//! The Redis limiter costs one round trip per request and funnels every request
//! for a site key through a single hot key. For a single-instance deployment
//! (the default) the same policy fits in memory: a sharded map keyed by
//! `{scope}:{ip}:{window}` is all the JS implementation keeps either.
//!
//! Set `CAP_RL_MODE=redis` when several instances share one Redis and the limit
//! must be global.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SHARDS: usize = 32;
type Shard = Mutex<HashMap<String, (Instant, i64)>>;

pub struct LocalLimiter {
    shards: Vec<Shard>,
}

impl Default for LocalLimiter {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }
}

impl LocalLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    fn shard_of(&self, key: &str) -> &Shard {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    /// `true` when the request is within the limit. Mirrors
    /// [`cap_store::Store::rate_hit`]: fixed window, empty IP disables the
    /// limiter.
    pub fn hit(&self, scope: &str, ip: &str, window_ms: i64, max: i64) -> bool {
        if ip.is_empty() || max <= 0 {
            return true;
        }
        let window_ms = window_ms.max(1);
        let now = crate::now_ms();
        let window = now / window_ms;
        let key = format!("{scope}:{ip}:{window}");
        let mut map = self
            .shard_of(&key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let expires = Instant::now() + Duration::from_millis(window_ms as u64);
        let entry = map.entry(key).or_insert_with(|| (expires, 0));
        entry.1 += 1;
        entry.1 <= max
    }

    /// 在同一把锁下预占验证次数，避免并发请求越过上限。
    pub fn claim_attempt(&self, key: &str, ttl_ms: i64, max: i64) -> bool {
        let mut map = self.shard_of(key).lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let expires = now + Duration::from_millis(ttl_ms.max(1) as u64);
        let entry = map.entry(key.to_string()).or_insert((expires, 0));
        if entry.0 <= now {
            *entry = (expires, 0);
        }
        if entry.1 >= max {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Drop expired entries. Called from a background task.
    pub fn sweep(&self) {
        let now = Instant::now();
        for shard in &self.shards {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, (expires, _)| *expires > now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LocalLimiter;
    use std::sync::{Arc, Barrier};

    #[test]
    fn concurrent_attempts_never_exceed_budget() {
        let limiter = Arc::new(LocalLimiter::new());
        let barrier = Arc::new(Barrier::new(40));
        let threads: Vec<_> = (0..40)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    limiter.claim_attempt("same-token", 60_000, 5)
                })
            })
            .collect();
        let accepted = threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>();
        assert_eq!(accepted, 5);
        assert!(!limiter.claim_attempt("same-token", 60_000, 5));
        assert!(limiter.claim_attempt("other-token", 60_000, 5));
    }
}
