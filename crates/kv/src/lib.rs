//! `cap-kv` — the storage layer behind Cap.
//!
//! A small key/value API covering exactly the Redis commands the server uses
//! (strings with TTL, hashes, sets, counters), with the same key schema as the
//! JavaScript server so both can share one instance during migration.

pub mod cpu;

#[cfg(test)]
mod business_tests;

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
        Ok(Self { conn: ConnectionManager::new(client).await? })
    }

    /// Internal business state machine; Redis TIME is the commit clock.
    /// Storage errors include unknown commit outcomes: never reset on error.
    pub async fn business_transition(&self, keys: &[String], args: &[String]) -> KvResult<Vec<String>> {
        if !matches!(keys.len(), 1 | 5) || args.len() != 10
            || keys.iter().any(|k| k.len() > 512 || k.is_empty())
            || args.iter().any(|a| a.len() > 16384)
            || keys.iter().enumerate().any(|(i,k)| keys[..i].contains(k))
        {
            return Err(KvError("invalid business command budget".into()));
        }
        let script = redis::Script::new(include_str!("business.lua"));
        let mut invocation = script.prepare_invoke();
        invocation.key(keys).arg(args);
        let mut conn = self.conn.clone();
        invocation.invoke_async(&mut conn).await.map_err(Into::into)
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

    /// `MGET k1 k2 …` in one round trip.
    pub async fn mget(&self, keys: &[String]) -> KvResult<Vec<Option<String>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut cmd = redis::cmd("MGET");
        for k in keys {
            cmd.arg(k);
        }
        self.query(cmd).await
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

    /// Durable, non-expiring deletion receipt. Only a live key can mint one.
    pub async fn begin_site_delete(&self, site: &str) -> KvResult<bool> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(r#"
            local intent = redis.call('GET', KEYS[2])
            if intent == 'pending' or intent == 'complete' then return 1 end
            if intent then return redis.error_reply('invalid deletion receipt') end
            if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
            redis.call('SET', KEYS[2], 'pending')
            return 1
        "#).key(format!("key:{site}")).key(format!("site-delete:{site}"))
            .invoke_async(&mut conn).await?;
        Ok(n == 1)
    }

    /// Preflight all types and write ACLs before mutating. Redis scripts do NOT
    /// roll back runtime errors; retain the receipt on every error for retry.
    /// Requires Redis 7 ACL checks; older servers fail closed before deletion.
    pub async fn finish_site_delete(&self, site: &str, data: &[String]) -> KvResult<()> {
        let mut conn = self.conn.clone();
        redis::Script::new(r#"
            local receipt = redis.call('GET', KEYS[1])
            if receipt ~= 'pending' and receipt ~= 'complete' then
                return redis.error_reply('missing deletion receipt')
            end
            for i = 2, 4 do
                local t = redis.call('TYPE', KEYS[i]).ok
                if t ~= 'none' and t ~= 'set' then return redis.error_reply('WRONGTYPE deletion index') end
            end
            local ids = redis.call('SMEMBERS', KEYS[3])
            local dels = {}
            for i = 5, #KEYS do table.insert(dels, KEYS[i]) end
            for _, id in ipairs(ids) do table.insert(dels, 'share:' .. id) end
            if not redis.acl_check_cmd('DEL', KEYS[3]) or
               not redis.acl_check_cmd('SET', KEYS[1], 'complete') or
               not redis.acl_check_cmd('SREM', KEYS[2], ARGV[1]) then
                return redis.error_reply('NOPERM deletion preflight')
            end
            for _, key in ipairs(dels) do
                if not redis.acl_check_cmd('DEL', key) then return redis.error_reply('NOPERM deletion preflight') end
            end
            for _, id in ipairs(ids) do
                if not redis.acl_check_cmd('SREM', KEYS[4], id) then return redis.error_reply('NOPERM deletion preflight') end
            end
            for _, key in ipairs(dels) do redis.call('DEL', key) end
            redis.call('SREM', KEYS[2], ARGV[1])
            for _, id in ipairs(ids) do redis.call('SREM', KEYS[4], id) end
            -- Keep the per-site share list until all index cleanup succeeded.
            redis.call('DEL', KEYS[3])
            redis.call('SET', KEYS[1], 'complete')
            return 1
        "#).key(format!("site-delete:{site}")).key("keys")
            .key(format!("shares:{site}")).key("shares").key(data).arg(site)
            .invoke_async::<i64>(&mut conn).await?;
        Ok(())
    }

    pub async fn exists(&self, key: &str) -> KvResult<bool> {
        let n: i64 = self.query(redis::cmd("EXISTS").arg(key).clone()).await?;
        Ok(n > 0)
    }

    /// `INCR key` → new value.
    pub async fn incr(&self, key: &str) -> KvResult<i64> {
        self.query(redis::cmd("INCR").arg(key).clone()).await
    }

    /// `INCR` + `EXPIRE` in a single round trip (fixed window: the TTL is set
    /// only when the counter is created).
    pub async fn incr_with_expire(&self, key: &str, secs: i64) -> KvResult<i64> {
        let mut conn = self.conn.clone();
        redis::Script::new(
            "local c = redis.call('INCR', KEYS[1]) \
             if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end \
             return c",
        )
        .key(key)
        .arg(secs.max(1))
        .invoke_async(&mut conn)
        .await
        .map_err(Into::into)
    }

    /// Atomically delete `claim` and, only if it existed, `also`. Returns
    /// whether `claim` was deleted by this call, so it works as a single-use
    /// claim that cleans up a companion key in the same round trip.
    pub async fn claim_del(&self, claim: &str, also: &str) -> KvResult<bool> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(
            "local c = redis.call('DEL', KEYS[1]) \
             if c == 1 then redis.call('DEL', KEYS[2]) end \
             return c",
        )
        .key(claim)
        .key(also)
        .invoke_async(&mut conn)
        .await?;
        Ok(n == 1)
    }

    /// Several `HINCRBY`s in one pipeline round trip.
    pub async fn hincrby_many(&self, items: &[(String, String, i64)]) -> KvResult<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        for (name, field, by) in items {
            pipe.cmd("HINCRBY").arg(name).arg(field).arg(*by).ignore();
        }
        let mut conn = self.conn.clone();
        pipe.query_async::<()>(&mut conn).await?;
        Ok(())
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

    /// Consume a verified recovery hash from the *current* JSON array. Checking
    /// the enabled flag and secret also rejects a stale verifier after rotation
    /// or disable. No snapshot is written back. Existing legacy replay markers
    /// reject login while permanently pruning the hash (including duplicates).
    /// Only recoveryVersion=1 is accepted: legacy marker expiry cannot make an
    /// unversioned/old set valid. Publish a fresh setup to migrate, never stamp
    /// existing arrays. Stop old writers AND drain in-flight requests first;
    /// mixed writers and direct rollback of authentication writers are unsafe.
    /// Malformed storage fails closed before any mutation.
    pub async fn consume_recovery_hash(
        &self,
        name: &str,
        expected_secret: &str,
        hash: &str,
    ) -> KvResult<bool> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'totpEnabled') ~= 'true'
                or redis.call('HGET', KEYS[1], 'totpSecret') ~= ARGV[1]
                or redis.call('HGET', KEYS[1], 'recoveryVersion') ~= '1' then
                return 0
            end
            local raw = redis.call('HGET', KEYS[1], 'recovery')
            if not raw then return 0 end
            if not string.match(raw, '^%s*%[') then
                return redis.error_reply('recovery must be a JSON array')
            end
            local hashes = cjson.decode(raw)
            local remaining = {}
            local found = false
            for _, hash in ipairs(hashes) do
                if type(hash) ~= 'string' then
                    return redis.error_reply('recovery must contain strings')
                end
                if hash == ARGV[2] then found = true
                else table.insert(remaining, hash) end
            end
            if not found then return 0 end
            local encoded = '[]'
            if #remaining > 0 then encoded = cjson.encode(remaining) end
            -- Old releases could resurrect a consumed hash in the array.
            -- Remove it permanently even when its legacy marker rejects login.
            local used = redis.call('EXISTS', KEYS[2])
            redis.call('HSET', KEYS[1], 'recovery', encoded)
            if used ~= 0 then return 0 end
            return 1
            "#,
        )
        .key(name)
        .key(format!("2fa:recovery-used:{hash}"))
        .arg(expected_secret)
        .arg(hash)
        .invoke_async(&mut conn)
        .await?;
        Ok(n == 1)
    }

    /// Confirm a verified TOTP snapshot and claim the legacy counter marker in
    /// one atomic operation. A completed rotation/disable rejects stale work;
    /// a claim completed first remains a successful authentication.
    pub async fn claim_totp(
        &self,
        name: &str,
        expected_secret: &str,
        counter: u64,
        secs: i64,
    ) -> KvResult<bool> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(r#"
            local enabled = redis.call('HGET', KEYS[1], 'totpEnabled')
            if not enabled then
                if redis.call('HEXISTS', KEYS[1], 'totpSecret') == 1
                    or redis.call('HEXISTS', KEYS[1], 'recovery') == 1
                    or redis.call('HEXISTS', KEYS[1], 'recoveryVersion') == 1 then
                    return redis.error_reply('missing TOTP enabled flag')
                end
                return 0
            end
            -- Explicit false is a supported disabled state, even with legacy material.
            if enabled == 'false' then return 0 end
            if enabled ~= 'true' then return redis.error_reply('invalid TOTP enabled flag') end
            local secret = redis.call('HGET', KEYS[1], 'totpSecret')
            if not secret or secret == '' then return redis.error_reply('missing TOTP secret') end
            if secret ~= ARGV[1] then return 0 end
            if redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[2]) then return 1 end
            return 0
        "#)
        .key(name)
        .key(format!("2fa:totp-used:{counter}"))
        .arg(expected_secret)
        .arg(secs.max(1))
        .invoke_async(&mut conn)
        .await?;
        Ok(n == 1)
    }

    /// Publish a verified setup only while its unique pending secret is still
    /// current. Setup replaces this generation token; disable deletes it;
    /// successful enable consumes it. Stale Argon work cannot re-enable 2FA.
    pub async fn publish_totp(&self, name: &str, pending: &str, recovery: &str) -> KvResult<bool> {
        let mut conn = self.conn.clone();
        let n: i64 = redis::Script::new(r#"
            if redis.call('HGET', KEYS[1], 'totpPending') ~= ARGV[1] then return 0 end
            if type(redis.acl_check_cmd) ~= 'function' then
                return redis.error_reply('TOTP publication requires Redis 7.0+ ACL preflight support')
            end
            if not redis.acl_check_cmd('HSET', KEYS[1], 'totpSecret', ARGV[1], 'totpEnabled', 'true', 'recovery', ARGV[2], 'recoveryVersion', '1')
                or not redis.acl_check_cmd('HDEL', KEYS[1], 'totpPending') then
                return redis.error_reply('TOTP publication ACL denied')
            end
            redis.call('HSET', KEYS[1], 'totpSecret', ARGV[1], 'totpEnabled', 'true', 'recovery', ARGV[2], 'recoveryVersion', '1')
            redis.call('HDEL', KEYS[1], 'totpPending')
            return 1
        "#).key(name).arg(pending).arg(recovery).invoke_async(&mut conn).await?;
        Ok(n == 1)
    }

    /// Create a previously absent hash and register its index member in one
    /// atomic operation. A collision changes neither hash nor index. Validate
    /// the index type and both commands' ACLs before mutation (Redis 7.0+).
    /// Redis scripts do not roll back arbitrary runtime failures; this guards
    /// collisions, wrong types and ACL denial, not OOM/server failure atomicity.
    pub async fn hcreate_indexed(
        &self,
        name: &str,
        pairs: &[(&str, String)],
        index: &str,
        member: &str,
    ) -> KvResult<bool> {
        if pairs.is_empty() || name == index {
            return Err(KvError("indexed hash requires fields and a distinct index".into()));
        }
        let script = redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
            local kind = redis.call('TYPE', KEYS[2]).ok
            if kind ~= 'none' and kind ~= 'set' then
                return redis.error_reply('index must be a set')
            end
            if type(redis.acl_check_cmd) ~= 'function' then
                return redis.error_reply('indexed creation requires Redis 7.0+ ACL preflight support')
            end
            if not redis.acl_check_cmd('HSET', KEYS[1], unpack(ARGV, 2))
                or not redis.acl_check_cmd('SADD', KEYS[2], ARGV[1]) then
                return redis.error_reply('indexed creation ACL denied')
            end
            redis.call('HSET', KEYS[1], unpack(ARGV, 2))
            redis.call('SADD', KEYS[2], ARGV[1])
            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation.key(name).key(index).arg(member);
        for (field, value) in pairs {
            invocation.arg(*field).arg(value);
        }
        let mut conn = self.conn.clone();
        let n: i64 = invocation.invoke_async(&mut conn).await?;
        Ok(n == 1)
    }

    /// Best-effort callers may ignore cleanup errors, but never read errors.
    /// Compare exact snapshots atomically, in batches of at most 128 fields.
    /// Invalid expiry strings are retained, not treated as proven expired.
    /// Atomic per batch, not across batches; an error may follow earlier deletions.
    pub async fn hdel_expired_blocks(
        &self,
        name: &str,
        snapshots: &[(String, String)],
        now: i64,
    ) -> KvResult<i64> {
        let script = redis::Script::new(r#"
            local removed = 0
            for i = 2, #ARGV, 2 do
                local old = ARGV[i + 1]
                local expiry = tonumber(old)
                if old ~= '0' and expiry and expiry <= tonumber(ARGV[1])
                    and redis.call('HGET', KEYS[1], ARGV[i]) == old then
                    removed = removed + redis.call('HDEL', KEYS[1], ARGV[i])
                end
            end
            return removed
        "#);
        let mut removed = 0;
        let mut conn = self.conn.clone();
        for batch in snapshots.chunks(128) {
            let mut invocation = script.prepare_invoke();
            invocation.key(name).arg(now);
            let mut count = 0;
            for (field, old) in batch {
                // Exact i64 comparison also guards Lua's floating-point rounding.
                if old != "0" && old.parse::<i64>().is_ok_and(|expiry| expiry <= now) {
                    invocation.arg(field).arg(old);
                    count += 1;
                }
            }
            if count != 0 {
                removed += invocation.invoke_async::<i64>(&mut conn).await?;
            }
        }
        Ok(removed)
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

    /// Write several string keys with one TTL in a single MULTI/EXEC.
    ///
    /// Note: Redis does not roll back on execution-time errors (e.g. OOM), so a
    /// partial write is possible; the TTL bounds how long it lingers.
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

#[cfg(test)]
mod atomic_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn expired_blocks_cas_batches() {
        let kv = Kv::connect_redis(&std::env::var("CAP_TEST_REDIS_URL").expect("explicit isolated Redis required")).await.unwrap();
        let name = format!("test:expired:{}:{}", std::process::id(), now_ms());
        let now = 1_000;
        // More than two batches, with renewed, unchanged and missing entries.
        for i in 0..260 {
            kv.hset_pairs(&name, &[(&format!("field:{i}"), "999".into())]).await.unwrap();
        }
        let mut snapshot: Vec<_> = kv.hgetall(&name).await.unwrap().into_iter().collect();
        snapshot.sort();
        kv.hset_pairs(&name, &[("field:0", "0".into()), ("field:1", "1001".into())]).await.unwrap();
        kv.hdel_fields(&name, &["field:2"]).await.unwrap();
        for (field, value) in [("permanent", "0"), ("future", "1001"), ("invalid", "broken"), ("boundary", "1000")] {
            kv.hset_pairs(&name, &[(field, value.into())]).await.unwrap();
            snapshot.push((field.into(), value.into()));
        }
        assert_eq!(kv.hdel_expired_blocks(&name, &snapshot, now).await.unwrap(), 258);
        let remaining = kv.hgetall(&name).await.unwrap();
        assert_eq!(remaining.len(), 5);
        assert_eq!(remaining["field:0"], "0");
        assert_eq!(remaining["field:1"], "1001");
        assert_eq!(kv.hdel_expired_blocks(&name, &snapshot, now).await.unwrap(), 0);
        // Avoid rounded Lua numbers deleting a future i64 timestamp.
        kv.hset_pairs(&name, &[("large", i64::MAX.to_string())]).await.unwrap();
        assert_eq!(kv.hdel_expired_blocks(&name, &[("large".into(), i64::MAX.to_string())], i64::MAX - 1).await.unwrap(), 0);
        kv.del(&name).await.unwrap();
        kv.set(&name, "wrong type").await.unwrap();
        assert!(kv.hdel_expired_blocks(&name, &snapshot, now).await.is_err());
        kv.del(&name).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn atomic_totp_claim() {
        let kv = Kv::connect_redis(&std::env::var("CAP_TEST_REDIS_URL").unwrap()).await.unwrap();
        let name = &format!("totp-claim-test:{}", std::process::id());
        let counter = 9_000_000_000;
        let marker = &format!("2fa:totp-used:{counter}");
        kv.hset_pairs(name, &[("totpEnabled", "true".into()), ("totpSecret", "old".into())]).await.unwrap();
        // Deterministic interleaving: snapshot/verification precedes rotation,
        // but its claim runs only after rotation has completed.
        let snapshot = kv.hget(name, "totpSecret").await.unwrap().unwrap();
        kv.hset_pairs(name, &[("totpSecret", "new".into())]).await.unwrap();
        assert!(!kv.claim_totp(name, &snapshot, counter, 120).await.unwrap());
        assert!(!kv.exists(marker).await.unwrap());
        kv.hdel_fields(name, &["totpEnabled", "totpSecret"]).await.unwrap();
        assert!(!kv.claim_totp(name, "new", counter, 120).await.unwrap());
        kv.hset_pairs(name, &[("totpEnabled", "true".into()), ("totpSecret", "new".into())]).await.unwrap();
        let (a, b) = tokio::join!(kv.claim_totp(name, "new", counter, 120), kv.claim_totp(name, "new", counter, 120));
        assert_ne!(a.unwrap(), b.unwrap());
        let ttl: i64 = kv.query(redis::cmd("TTL").arg(marker).clone()).await.unwrap();
        assert!((1..=120).contains(&ttl));
        // A later disable does not retract the completed claim or its marker.
        kv.del(name).await.unwrap();
        assert_eq!(kv.get(marker).await.unwrap().as_deref(), Some("1"));
        kv.hset_pairs(name, &[("totpEnabled", "true".into()), ("totpSecret", "new".into())]).await.unwrap();
        kv.set_ex(marker, "legacy", 80).await.unwrap();
        assert!(!kv.claim_totp(name, "new", counter, 120).await.unwrap());
        assert_eq!(kv.get(marker).await.unwrap().as_deref(), Some("legacy"));
        let ttl: i64 = kv.query(redis::cmd("TTL").arg(marker).clone()).await.unwrap();
        assert!((1..=80).contains(&ttl));
        kv.hset_pairs(name, &[("totpEnabled", "broken".into())]).await.unwrap();
        assert!(kv.claim_totp(name, "new", counter, 120).await.is_err());
        kv.hdel_fields(name, &["totpEnabled"]).await.unwrap();
        assert!(kv.claim_totp(name, "new", counter, 120).await.is_err());
        kv.del(name).await.unwrap();
        kv.set(name, "wrong type").await.unwrap();
        assert!(kv.claim_totp(name, "new", counter, 120).await.is_err());
        kv.del(name).await.unwrap();
        kv.del(marker).await.unwrap();
    }

    // Explicit opt-in only: never connect to a default or shared Redis.
    #[tokio::test]
    #[ignore = "requires CAP_TEST_REDIS_URL pointing to an isolated Redis"]
    async fn atomic_recovery_and_indexed_creation() {
        let kv = Kv::connect_redis(&std::env::var("CAP_TEST_REDIS_URL").unwrap()).await.unwrap();
        let prefix = format!("atomic-test:{}:{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let name = &format!("{prefix}:2fa");
        kv.hset_pairs(name, &[
            ("totpEnabled", "true".into()),
            ("totpSecret", "old-secret".into()),
            ("recoveryVersion", "1".into()),
            ("recovery", r#"["a","b","c"]"#.into()),
        ]).await.unwrap();
        // Both callers verified the same old snapshot, but distinct hashes
        // must both disappear rather than resurrect each other.
        let (a, b) = tokio::join!(
            kv.consume_recovery_hash(name, "old-secret", "a"),
            kv.consume_recovery_hash(name, "old-secret", "b"),
        );
        assert!(a.unwrap() && b.unwrap());
        assert_eq!(kv.hget(name, "recovery").await.unwrap().as_deref(), Some(r#"["c"]"#));
        let (a, b) = tokio::join!(
            kv.consume_recovery_hash(name, "old-secret", "c"),
            kv.consume_recovery_hash(name, "old-secret", "c"),
        );
        assert_ne!(a.unwrap(), b.unwrap());
        assert_eq!(kv.hget(name, "recovery").await.unwrap().as_deref(), Some("[]"));

        // A rotation between Argon verification and consumption must neither
        // admit the old login nor restore any part of the old configuration.
        kv.hset_pairs(name, &[("totpSecret", "new-secret".into()), ("recovery", r#"["new"]"#.into())]).await.unwrap();
        let rotated = kv.hgetall(name).await.unwrap();
        assert!(!kv.consume_recovery_hash(name, "old-secret", "a").await.unwrap());
        assert!(!kv.consume_recovery_hash(name, "old-secret", "new").await.unwrap());
        assert!(!kv.consume_recovery_hash(name, "new-secret", "a").await.unwrap());
        assert_eq!(kv.hgetall(name).await.unwrap(), rotated);
        kv.hdel_fields(name, &["totpEnabled", "totpSecret", "recovery", "recoveryVersion"]).await.unwrap();
        assert!(!kv.consume_recovery_hash(name, "new-secret", "new").await.unwrap());
        assert!(!kv.exists(name).await.unwrap());

        // Legacy replay marker must reject AND permanently remove all copies.
        let legacy = format!("{prefix}:legacy-hash");
        let marker = format!("2fa:recovery-used:{legacy}");
        kv.hset_pairs(name, &[("totpEnabled", "true".into()), ("totpSecret", "s".into()), ("recovery", format!(r#"["{legacy}","{legacy}","fresh"]"#))]).await.unwrap();
        kv.set_ex(&marker, "1", 60).await.unwrap();
        kv.del(&marker).await.unwrap(); // Expired BEFORE the first upgraded login.
        let unversioned = kv.hgetall(name).await.unwrap();
        assert!(!kv.consume_recovery_hash(name, "s", &legacy).await.unwrap());
        assert_eq!(kv.hgetall(name).await.unwrap(), unversioned);
        kv.hset_pairs(name, &[("recoveryVersion", "0".into())]).await.unwrap();
        assert!(!kv.consume_recovery_hash(name, "s", &legacy).await.unwrap());
        kv.hset_pairs(name, &[("recoveryVersion", "1".into())]).await.unwrap();
        kv.set_ex(&marker, "1", 60).await.unwrap();
        assert!(!kv.consume_recovery_hash(name, "s", &legacy).await.unwrap());
        assert_eq!(kv.hget(name, "recovery").await.unwrap().as_deref(), Some(r#"["fresh"]"#));
        kv.del(&marker).await.unwrap(); // Simulate TTL expiry; no resurrection.
        assert!(!kv.consume_recovery_hash(name, "s", &legacy).await.unwrap());
        for malformed in ["[", "{}", r#"["fresh",123]"#, r#"["fresh",null]"#] {
            kv.hset_pairs(name, &[("recovery", malformed.into())]).await.unwrap();
            assert!(kv.consume_recovery_hash(name, "s", "fresh").await.is_err());
            assert_eq!(kv.hget(name, "recovery").await.unwrap().as_deref(), Some(malformed));
        }
        kv.hset_pairs(name, &[("recovery", r#"["fresh","fresh"]"#.into())]).await.unwrap();
        assert!(kv.consume_recovery_hash(name, "s", "fresh").await.unwrap());
        assert_eq!(kv.hget(name, "recovery").await.unwrap().as_deref(), Some("[]"));
        kv.hset_pairs(name, &[("totpEnabled", "false".into()), ("recovery", r#"["fresh"]"#.into())]).await.unwrap();
        let disabled = kv.hgetall(name).await.unwrap();
        assert!(!kv.consume_recovery_hash(name, "s", "fresh").await.unwrap());
        assert_eq!(kv.hgetall(name).await.unwrap(), disabled);

        // Pause an enable after reading its generation; let disable or setup
        // finish, then release the stale publication. No timing sleeps.
        for replacement in [None, Some("new-pending")] {
            kv.hset_pairs(name, &[("totpPending", "old-pending".into())]).await.unwrap();
            let ready = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let resume = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let worker = {
                let (kv, name, ready, resume) = (kv.clone(), name.clone(), ready.clone(), resume.clone());
                tokio::spawn(async move {
                    let pending = kv.hget(&name, "totpPending").await.unwrap().unwrap();
                    ready.wait().await;
                    resume.wait().await;
                    kv.publish_totp(&name, &pending, r#"["stale"]"#).await.unwrap()
                })
            };
            ready.wait().await;
            if let Some(pending) = replacement {
                kv.hset_pairs(name, &[("totpPending", pending.into())]).await.unwrap();
            } else {
                kv.hdel_fields(name, &["totpPending", "totpEnabled", "totpSecret", "recovery"]).await.unwrap();
            }
            let current = kv.hgetall(name).await.unwrap();
            resume.wait().await;
            assert!(!worker.await.unwrap());
            assert_eq!(kv.hgetall(name).await.unwrap(), current);
        }
        let (a, b) = tokio::join!(kv.publish_totp(name, "new-pending", "[]"), kv.publish_totp(name, "new-pending", "[]"));
        assert_ne!(a.unwrap(), b.unwrap());
        assert_eq!(kv.hget(name, "totpSecret").await.unwrap().as_deref(), Some("new-pending"));
        assert_eq!(kv.hget(name, "totpPending").await.unwrap(), None);
        assert_eq!(kv.hget(name, "recoveryVersion").await.unwrap().as_deref(), Some("1"));
        kv.del(name).await.unwrap();

        let key = &format!("{prefix}:key");
        let index = &format!("{prefix}:keys");
        let first = [("secret", "first".into())];
        let second = [("secret", "second".into())];
        let (a, b) = tokio::join!(
            kv.hcreate_indexed(key, &first, index, "site"),
            kv.hcreate_indexed(key, &second, index, "site"),
        );
        let a = a.unwrap();
        assert_ne!(a, b.unwrap());
        assert_eq!(kv.hget(key, "secret").await.unwrap().as_deref(), Some(if a { "first" } else { "second" }));
        assert_eq!(kv.smembers(index).await.unwrap(), vec!["site"]);
        assert!(!kv.hcreate_indexed(key, &second, index, "loser").await.unwrap());
        assert_eq!(kv.smembers(index).await.unwrap(), vec!["site"]);
        kv.del(key).await.unwrap();
        kv.del(index).await.unwrap();
        kv.set(index, "wrong-type").await.unwrap();
        assert!(kv.hcreate_indexed(key, &first, index, "site").await.is_err());
        assert!(!kv.exists(key).await.unwrap(), "index error must not leave an orphan hash");
        kv.del(index).await.unwrap();

        // A user allowed HSET but denied SADD used to leave an orphan hash.
        // Exercise actual Redis ACL enforcement, not a mocked command error.
        let user = format!("test-user-{}-{}", std::process::id(), now_ms());
        kv.query::<()>(redis::cmd("ACL").arg("SETUSER").arg(&user)
            .arg("on").arg(">test-password").arg("~*").arg("+@all").arg("-sadd").clone()).await.unwrap();
        let client = redis::Client::open(std::env::var("CAP_TEST_REDIS_URL").unwrap()).unwrap();
        let mut conn = ConnectionManager::new(client).await.unwrap();
        redis::cmd("AUTH").arg(&user).arg("test-password").query_async::<()>(&mut conn).await.unwrap();
        let limited = Kv { conn };
        assert!(limited.hcreate_indexed(key, &first, index, "site").await.is_err());
        assert!(!kv.exists(key).await.unwrap());
        assert!(!kv.exists(index).await.unwrap());
        // Denial of the other command likewise cannot register a stray member.
        kv.query::<()>(redis::cmd("ACL").arg("SETUSER").arg(&user).arg("+sadd").arg("-hset").clone()).await.unwrap();
        assert!(limited.hcreate_indexed(key, &first, index, "site").await.is_err());
        assert!(!kv.exists(key).await.unwrap());
        assert!(!kv.exists(index).await.unwrap());
        kv.query::<()>(redis::cmd("ACL").arg("SETUSER").arg(&user).arg("+hset").arg("-hdel").clone()).await.unwrap();
        kv.hset_pairs(name, &[("totpPending", "acl-pending".into())]).await.unwrap();
        let before = kv.hgetall(name).await.unwrap();
        assert!(limited.publish_totp(name, "acl-pending", "[]").await.is_err());
        assert_eq!(kv.hgetall(name).await.unwrap(), before);
        kv.del(name).await.unwrap();
        kv.query::<i64>(redis::cmd("ACL").arg("DELUSER").arg(&user).clone()).await.unwrap();
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
