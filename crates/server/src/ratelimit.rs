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
use std::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const SHARDS: usize = 32;
const MAX_PER_SHARD: usize = 2048;
type Shard = Mutex<HashMap<[u8; 32], (Instant, i64)>>;

pub struct LocalLimiter {
    shards: Vec<Shard>,
    capacity_rejections: AtomicU64,
    limit_rejections: AtomicU64,
}

impl Default for LocalLimiter {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            capacity_rejections: AtomicU64::new(0),
            limit_rejections: AtomicU64::new(0),
        }
    }
}

impl LocalLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(parts: &[&[u8]]) -> [u8; 32] {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        hash.finalize().into()
    }

    pub fn rejection_counts(&self) -> (u64, u64) {
        (self.capacity_rejections.load(Ordering::Relaxed),
         self.limit_rejections.load(Ordering::Relaxed))
    }

    fn shard_of(&self, key: &[u8; 32]) -> &Shard {
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
        let key = Self::key(&[b"rate", scope.as_bytes(), ip.as_bytes(), &window.to_be_bytes()]);
        let mut map = self
            .shard_of(&key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let expires = Instant::now() + Duration::from_millis(window_ms as u64);
        if !map.contains_key(&key) && map.len() >= MAX_PER_SHARD {
            self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let entry = map.entry(key).or_insert_with(|| (expires, 0));
        if entry.1 >= max {
            self.limit_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }

    /// 在同一把锁下预占验证次数，避免并发请求越过上限。
    pub fn claim_attempt(&self, key: &str, ttl_ms: i64, max: i64) -> bool {
        if max <= 0 {
            self.limit_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let key = Self::key(&[b"attempt", key.as_bytes()]);
        let mut map = self.shard_of(&key).lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let expires = now + Duration::from_millis(ttl_ms.max(1) as u64);
        if !map.contains_key(&key) && map.len() >= MAX_PER_SHARD {
            self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let entry = map.entry(key).or_insert((expires, 0));
        if entry.0 <= now {
            *entry = (expires, 0);
        }
        if entry.1 >= max {
            self.limit_rejections.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }

    /// Drop expired entries. Called from a background task.
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    fn sweep_at(&self, now: Instant) {
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

    fn entries(limiter: &LocalLimiter) -> usize {
        limiter.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }

    #[test]
    fn nonpositive_attempt_budget_rejects_without_allocating() {
        let limiter = LocalLimiter::new();
        for max in [0, -1, i64::MIN] {
            assert!(!limiter.claim_attempt("unallocated", 60_000, max));
        }
        assert_eq!(entries(&limiter), 0);
        assert_eq!(limiter.rejection_counts(), (0, 3));
        assert!(limiter.claim_attempt("unallocated", 60_000, 1));
        assert!(!limiter.claim_attempt("unallocated", 60_000, 0));
        assert!(!limiter.claim_attempt("unallocated", 60_000, 1));
        assert_eq!(entries(&limiter), 1);
        assert_eq!(limiter.rejection_counts(), (0, 5));
    }

    #[test]
    fn hit_disabled_policy_differs_from_attempt_budget() {
        let limiter = LocalLimiter::new();
        for max in [0, -1, i64::MIN] {
            assert!(limiter.hit("scope", "ip", 60_000, max));
        }
        assert!(limiter.hit("scope", "", 60_000, 1));
        assert_eq!(entries(&limiter), 0);
        assert_eq!(limiter.rejection_counts(), (0, 0));
        // A very long fixed window avoids wall-clock boundary flakes.
        assert!(limiter.hit("scope", "ip", i64::MAX, 1));
        assert!(!limiter.hit("scope", "ip", i64::MAX, 1));
        assert_eq!(limiter.rejection_counts(), (0, 1));
    }

    #[test]
    fn public_api_high_cardinality_is_bounded_and_fail_closed() {
        for attempts in [false, true] {
            let limiter = LocalLimiter::new();
            let capacity = super::SHARDS * super::MAX_PER_SHARD;
            let mut accepted = 0;
            for n in 0..capacity * 2 {
                let key = format!("unique-{n}");
                let allowed = if attempts {
                    limiter.claim_attempt(&key, 600_000, 1)
                } else {
                    limiter.hit(&key, "ip", i64::MAX, 1)
                };
                accepted += usize::from(allowed);
            }
            assert_eq!(entries(&limiter), accepted);
            assert!(accepted <= capacity);
            assert!(limiter.shards.iter().all(|s| s.lock().unwrap().len() <= super::MAX_PER_SHARD));
            assert_eq!(limiter.rejection_counts(), ((capacity * 2 - accepted) as u64, 0));
        }
    }

    #[test]
    fn sweep_removes_expiry_at_boundary_but_preserves_live_quota() {
        let limiter = LocalLimiter::new();
        let now = std::time::Instant::now();
        for (name, expires) in [
            ("past", now - std::time::Duration::from_nanos(1)),
            ("boundary", now),
            ("live", now + std::time::Duration::from_secs(60)),
        ] {
            assert!(limiter.claim_attempt(name, 60_000, 1));
            let key = LocalLimiter::key(&[b"attempt", name.as_bytes()]);
            limiter.shard_of(&key).lock().unwrap().get_mut(&key).unwrap().0 = expires;
        }
        limiter.sweep_at(now);
        assert_eq!(entries(&limiter), 1);
        assert!(!limiter.claim_attempt("live", 60_000, 1));
        assert!(limiter.claim_attempt("past", 60_000, 1));
        assert!(limiter.claim_attempt("boundary", 60_000, 1));
        assert_eq!(limiter.rejection_counts(), (0, 1));
    }

    #[test]
    fn expired_attempt_resets_without_sweep() {
        let limiter = LocalLimiter::new();
        assert!(limiter.claim_attempt("token", 60_000, 1));
        let key = LocalLimiter::key(&[b"attempt", b"token"]);
        limiter.shard_of(&key).lock().unwrap().get_mut(&key).unwrap().0 = std::time::Instant::now();
        assert!(limiter.claim_attempt("token", 60_000, 1));
        assert!(!limiter.claim_attempt("token", 60_000, 1));
        assert_eq!(entries(&limiter), 1);
        assert_eq!(limiter.rejection_counts(), (0, 1));
    }

    #[test]
    fn concurrent_hits_and_sweep_preserve_exact_quota() {
        let limiter = Arc::new(LocalLimiter::new());
        let barrier = Arc::new(Barrier::new(40));
        let threads: Vec<_> = (0..40).map(|_| {
            let limiter = limiter.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                limiter.sweep();
                limiter.hit("same-scope", "same-ip", i64::MAX, 5)
            })
        }).collect();
        let accepted: usize = threads.into_iter().map(|t| usize::from(t.join().unwrap())).sum();
        assert_eq!(accepted, 5);
        assert_eq!(entries(&limiter), 1);
        assert_eq!(limiter.rejection_counts(), (0, 35));
    }

    #[test]
    fn capacity_does_not_evict_active_attempts() {
        let limiter = LocalLimiter::new();
        let held = LocalLimiter::key(&[b"attempt", b"held"]);
        let mut map = limiter.shard_of(&held).lock().unwrap();
        let expires = std::time::Instant::now() + std::time::Duration::from_secs(60);
        map.insert(held, (expires, 1));
        for index in 0..super::MAX_PER_SHARD - 1 {
            map.insert(LocalLimiter::key(&[b"filler", &index.to_be_bytes()]), (expires, 0));
        }
        drop(map);
        assert!(limiter.claim_attempt("held", 60_000, 2));
        assert!(!limiter.claim_attempt("held", 60_000, 2));
        let candidate = (0u64..).map(|n| format!("candidate-{n}")).find(|s| {
            let key = LocalLimiter::key(&[b"attempt", s.as_bytes()]);
            std::ptr::eq(limiter.shard_of(&key), limiter.shard_of(&held))
        }).unwrap();
        assert!(!limiter.claim_attempt(&candidate, 60_000, 2));
        assert_eq!(limiter.rejection_counts(), (1, 1));
        assert_eq!(limiter.shard_of(&held).lock().unwrap().len(), super::MAX_PER_SHARD);
        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
        for (key, value) in limiter.shard_of(&held).lock().unwrap().iter_mut() {
            if *key != held { value.0 = past; }
        }
        limiter.sweep();
        assert!(limiter.claim_attempt(&candidate, 60_000, 2));
        assert!(!limiter.claim_attempt("held", 60_000, 2));
    }

    #[test]
    fn keys_are_fixed_size_and_unambiguous() {
        assert_ne!(LocalLimiter::key(&[b"a:b", b"c"]), LocalLimiter::key(&[b"a", b"b:c"]));
        assert_ne!(LocalLimiter::key(&[b"rate", b"x"]), LocalLimiter::key(&[b"attempt", b"x"]));
        assert_eq!(LocalLimiter::key(&[&vec![b'x'; 100_000]]).len(), 32);
        let limiter = LocalLimiter::new();
        assert!(limiter.hit("scope", "127.0.0.1", 60_000, 0));
        assert_eq!(limiter.shards.iter().map(|s| s.lock().unwrap().len()).sum::<usize>(), 0);
    }

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
        assert_eq!(limiter.rejection_counts(), (0, 35));
        assert!(!limiter.claim_attempt("same-token", 60_000, 5));
        assert!(limiter.claim_attempt("other-token", 60_000, 5));
        assert_eq!(limiter.rejection_counts(), (0, 36));
    }
}
