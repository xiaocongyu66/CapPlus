//! Storage access for the admin/management API.
//!
//! A thin wrapper over [`cap_kv::Kv`], so the same handlers run on the SQLite
//! data directory or on Redis (key schema identical to the JS server).

use std::collections::HashMap;

use cap_kv::Kv;

#[derive(Clone)]
pub struct AdminStore {
    kv: Kv,
}

fn e(err: cap_kv::KvError) -> String {
    err.0
}

impl AdminStore {
    pub fn new(kv: Kv) -> Self {
        Self { kv }
    }

    /// Connect to Redis (kept for tests and Redis deployments).
    pub async fn connect(url: &str) -> Result<Self, String> {
        Ok(Self { kv: Kv::connect_redis(url).await.map_err(e)? })
    }

    pub(crate) async fn get(&self, key: &str) -> Result<Option<String>, String> {
        self.kv.get(key).await.map_err(e)
    }

    pub(crate) async fn set(&self, key: &str, value: &str) -> Result<(), String> {
        self.kv.set(key, value).await.map_err(e)
    }

    pub(crate) async fn set_ex(&self, key: &str, value: &str, secs: i64) -> Result<(), String> {
        self.kv.set_ex(key, value, secs).await.map_err(e)
    }

    pub(crate) async fn del(&self, key: &str) -> Result<i64, String> {
        self.kv.del(key).await.map_err(e)
    }

    /// `INCR key` — used by the fixed-window login rate limiter.
    pub(crate) async fn incr(&self, key: &str) -> Result<i64, String> {
        self.kv.incr(key).await.map_err(e)
    }

    /// `EXPIRE key <secs>` — rate-limit windows and share hashes.
    pub(crate) async fn expire(&self, key: &str, secs: i64) -> Result<(), String> {
        self.kv.expire(key, secs).await.map_err(e)
    }

    pub(crate) async fn del_many(&self, keys: &[String]) -> Result<(), String> {
        self.kv.del_many(keys).await.map_err(e)
    }

    /// Public existence check for the lead (cookie session bindings).
    pub async fn kv_exists(&self, key: &str) -> Result<bool, String> {
        self.kv.exists(key).await.map_err(e)
    }

    pub(crate) async fn exists(&self, key: &str) -> Result<bool, String> {
        self.kv.exists(key).await.map_err(e)
    }

    pub(crate) async fn sadd(&self, set: &str, member: &str) -> Result<(), String> {
        self.kv.sadd(set, member).await.map_err(e)
    }

    pub(crate) async fn srem(&self, set: &str, member: &str) -> Result<(), String> {
        self.kv.srem(set, member).await.map_err(e)
    }

    pub(crate) async fn smembers(&self, set: &str) -> Result<Vec<String>, String> {
        self.kv.smembers(set).await.map_err(e)
    }

    pub(crate) async fn hget(&self, name: &str, field: &str) -> Result<Option<String>, String> {
        self.kv.hget(name, field).await.map_err(e)
    }

    pub(crate) async fn hmget(
        &self,
        name: &str,
        fields: &[&str],
    ) -> Result<Vec<Option<String>>, String> {
        self.kv.hmget(name, fields).await.map_err(e)
    }

    /// `HDEL name f1 f2 …` — drop fields from a hash.
    pub(crate) async fn hdel_fields(&self, name: &str, fields: &[&str]) -> Result<(), String> {
        self.kv.hdel_fields(name, fields).await.map_err(e)
    }

    pub(crate) async fn hgetall(&self, name: &str) -> Result<HashMap<String, String>, String> {
        self.kv.hgetall(name).await.map_err(e)
    }

    pub(crate) async fn hset_pairs(
        &self,
        name: &str,
        pairs: &[(&str, String)],
    ) -> Result<(), String> {
        self.kv.hset_pairs(name, pairs).await.map_err(e)
    }
}
