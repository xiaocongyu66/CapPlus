//! `cap-kv` — the storage layer behind Cap.
//!
//! A small key/value API covering exactly the Redis commands the server uses
//! (strings with TTL, hashes, sets, counters), with the same key schema as the
//! JavaScript server so both can share one instance during migration.

use std::collections::HashMap;

use redis::aio::ConnectionManager;
use redis::FromRedisValue;

/// Error type: a plain message, so callers can wrap it as they like.
#[derive(Debug, Clone)]
pub struct KvError(pub String);

impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KvError {}

impl From<redis::RedisError> for KvError {
    fn from(e: redis::RedisError) -> Self {
        KvError(format!("redis: {e}"))
    }
}

pub type KvResult<T> = Result<T, KvError>;

/// Cheap to clone; all clones share one connection manager.
#[derive(Clone)]
pub struct Kv {
    conn: ConnectionManager,
}

impl Kv {
    pub async fn connect_redis(url: &str) -> KvResult<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self {
            conn: ConnectionManager::new(client).await?,
        })
    }

    pub fn backend_name(&self) -> &'static str {
        "redis"
    }

    async fn query<T: FromRedisValue>(&self, cmd: redis::Cmd) -> KvResult<T> {
        let mut conn = self.conn.clone();
        Ok(cmd.query_async(&mut conn).await?)
    }

    // ---- strings -------------------------------------------------------

    pub async fn get(&self, key: &str) -> KvResult<Option<String>> {
        self.query(redis::cmd("GET").arg(key).clone()).await
    }

    pub async fn set(&self, key: &str, value: &str) -> KvResult<()> {
        self.query::<()>(redis::cmd("SET").arg(key).arg(value).clone())
            .await
    }

    /// `SET key value EX secs`.
    pub async fn set_ex(&self, key: &str, value: &str, secs: i64) -> KvResult<()> {
        self.query::<()>(
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(secs.max(1))
                .clone(),
        )
        .await
    }

    /// `SET key value NX EX secs` → `true` when this caller set it.
    pub async fn set_nx_ex(&self, key: &str, value: &str, secs: i64) -> KvResult<bool> {
        let got: Option<String> = self
            .query(
                redis::cmd("SET")
                    .arg(key)
                    .arg(value)
                    .arg("NX")
                    .arg("EX")
                    .arg(secs.max(1))
                    .clone(),
            )
            .await?;
        Ok(got.as_deref() == Some("OK"))
    }

    /// `DEL key` → number of keys removed.
    pub async fn del(&self, key: &str) -> KvResult<i64> {
        self.query(redis::cmd("DEL").arg(key).clone()).await
    }

    pub async fn del_many(&self, keys: &[String]) -> KvResult<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut cmd = redis::cmd("DEL");
        for k in keys {
            cmd.arg(k);
        }
        self.query::<i64>(cmd).await.map(|_| ())
    }

    pub async fn exists(&self, key: &str) -> KvResult<bool> {
        let n: i64 = self.query(redis::cmd("EXISTS").arg(key).clone()).await?;
        Ok(n > 0)
    }

    /// `INCR key` → new value.
    pub async fn incr(&self, key: &str) -> KvResult<i64> {
        self.query(redis::cmd("INCR").arg(key).clone()).await
    }

    /// `EXPIRE key secs`.
    pub async fn expire(&self, key: &str, secs: i64) -> KvResult<()> {
        self.query::<i64>(redis::cmd("EXPIRE").arg(key).arg(secs.max(1)).clone())
            .await
            .map(|_| ())
    }

    // ---- sets ----------------------------------------------------------

    pub async fn sadd(&self, set: &str, member: &str) -> KvResult<()> {
        self.query::<i64>(redis::cmd("SADD").arg(set).arg(member).clone())
            .await
            .map(|_| ())
    }

    pub async fn srem(&self, set: &str, member: &str) -> KvResult<()> {
        self.query::<i64>(redis::cmd("SREM").arg(set).arg(member).clone())
            .await
            .map(|_| ())
    }

    pub async fn smembers(&self, set: &str) -> KvResult<Vec<String>> {
        self.query(redis::cmd("SMEMBERS").arg(set).clone()).await
    }

    // ---- hashes --------------------------------------------------------

    pub async fn hget(&self, name: &str, field: &str) -> KvResult<Option<String>> {
        self.query(redis::cmd("HGET").arg(name).arg(field).clone())
            .await
    }

    pub async fn hmget(&self, name: &str, fields: &[&str]) -> KvResult<Vec<Option<String>>> {
        let mut cmd = redis::cmd("HMGET");
        cmd.arg(name);
        for f in fields {
            cmd.arg(*f);
        }
        self.query(cmd).await
    }

    pub async fn hgetall(&self, name: &str) -> KvResult<HashMap<String, String>> {
        self.query(redis::cmd("HGETALL").arg(name).clone()).await
    }

    pub async fn hset_pairs(&self, name: &str, pairs: &[(&str, String)]) -> KvResult<()> {
        if pairs.is_empty() {
            return Ok(());
        }
        let mut cmd = redis::cmd("HSET");
        cmd.arg(name);
        for (f, v) in pairs {
            cmd.arg(*f).arg(v);
        }
        self.query::<i64>(cmd).await.map(|_| ())
    }

    pub async fn hdel_fields(&self, name: &str, fields: &[&str]) -> KvResult<()> {
        if fields.is_empty() {
            return Ok(());
        }
        let mut cmd = redis::cmd("HDEL");
        cmd.arg(name);
        for f in fields {
            cmd.arg(*f);
        }
        self.query::<i64>(cmd).await.map(|_| ())
    }

    /// `HINCRBY name field by` → new value.
    pub async fn hincrby(&self, name: &str, field: &str, by: i64) -> KvResult<i64> {
        self.query(redis::cmd("HINCRBY").arg(name).arg(field).arg(by).clone())
            .await
    }

    /// Atomically write several string keys with one TTL (used to issue a
    /// verification token: `bind:`, `token:`, `verified:`).
    pub async fn set_many_ex(&self, items: &[(String, String)], secs: i64) -> KvResult<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        pipe.atomic();
        for (k, v) in items {
            pipe.cmd("SET")
                .arg(k)
                .arg(v)
                .arg("EX")
                .arg(secs.max(1))
                .ignore();
        }
        let mut conn = self.conn.clone();
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
