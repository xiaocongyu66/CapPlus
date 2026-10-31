# cap-rust — modular port spec

Rust rewrite of `cap` (self-hosted CAPTCHA). **Verified-embed-only** architecture:
the widget always runs inside a Cap-origin iframe (`/embed.js` + `/embed/:siteKey`),
and only tokens redeemed from that iframe (request `Origin` == `Host`) are marked
`verified:<token>` and accepted by `/siteverify`.

Target: single static binary, low RSS (~10–20 MB), axum + tokio + redis.

## Module map (one owner per crate)

| crate | responsibility | status |
|---|---|---|
| `cap-core` | prng / sha256 / JWT-HS256 / pow-verify / UA hash / bind record | **done** |
| `cap-store` | Redis repository: key config, nonce, token/bind/verified, rate limit, metrics | TODO |
| `cap-detect` | trust scoring port of `core/src/trust.js` (probe detection = phase 2) | TODO |
| `cap-embed` | embed HTML + parent loader JS + frame-ancestors policy (pure strings) | TODO |
| `cap-verify` | Turnstile-compatible siteverify contract (parse, errors, secret check) | TODO |
| `cap-server` | axum wiring of all routes (owner: lead) | TODO |

**Rules**
- Only edit files inside your own crate. Do not touch `Cargo.toml` (workspace) or
  other crates. No new workspace members.
- Everything must compile with `cargo test -p <crate>` (no warnings that fail CI).
- Behaviour must match the existing JavaScript implementation
  (`/root/cpa/cap/core/src`, `/root/cpa/cap/standalone/src`) — read it as the spec.

## Shared wire/Redis conventions

Redis (same schema as the JS server, so both can run against one instance):

| key | type | meaning |
|---|---|---|
| `key:<siteKey>` | hash | fields `jwtSecret` (string), `secretHash` (`sha256:<hex>` or legacy `$argon2…`), `config` (JSON, camelCase) |
| `blocklist:<sigHex>` | string, `EX` | nonce consumption: `SET NX EX ttl` succeeds ⇒ first use |
| `token:<token>` | string = `expiresMs`, `EX` | issued verification token |
| `bind:<token>` | string = JSON `{ip,ua,host,ts}`, `EX` | session bind captured at redeem |
| `verified:<token>` | string `"1"`, `EX` | token came from the Cap-hosted iframe |
| `rl:<scope>:<ip>:<windowMs>:<window>` | counter `INCR`+`EXPIRE` | fixed-window rate limit |
| `metrics:failed:<siteKey>` | hash bucket→count | failure metrics (`HINCRBY`) |

Key config (JSON, camelCase): `difficulty` (u32, 4), `challengeCount` (u32, 80),
`saltSize` (u32, 32), `protocol` (string, `"hashwx"`), `instrumentation` (bool),
`requireSessionBind` (bool), `blockOnDeny` (bool, true), `corsOrigins` (array|null),
`ratelimitMax`/`ratelimitDuration` (number|null), `autoBlockOnDeny`, `autoBlockDenyMs`,
`throttleOnRestrict`, `throttleRestrictMs`, `extendedProbes`, `polymorphism`,
`obfuscationLevel`, `blockNonAutomatedBrowsers`-style flags, `hashwxDifficulty`, `rswT`.

Timings: challenge TTL 15 min, token TTL 2 h, rate-limit window default 5 s / 30 reqs.

## `cap-store` API (owner: store agent)

```rust
pub struct KeyInfo { pub site_key: String, pub jwt_secret: String,
                     pub secret_hash: String, pub config: KeyConfig }
pub struct Store { /* ConnectionManager */ }

impl Store {
    pub async fn connect(redis_url: &str) -> redis::RedisResult<Self>;
    pub async fn key(&self, site_key: &str) -> Result<Option<KeyInfo>, StoreError>;
    pub async fn consume_nonce(&self, sig_hex: &str, ttl_ms: i64) -> Result<bool, StoreError>;
    pub async fn issue(&self, token: &str, bind_json: &str, expires_ms: i64, ttl_ms: i64)
        -> Result<(), StoreError>;            // pipeline: bind, token, verified
    pub async fn peek_token(&self, token: &str) -> Result<Option<i64>, StoreError>;
    pub async fn consume_token(&self, token: &str) -> Result<bool, StoreError>;  // DEL
    pub async fn has_verified(&self, token: &str) -> Result<bool, StoreError>;
    pub async fn drop_verified(&self, token: &str) -> Result<(), StoreError>;
    pub async fn rate_hit(&self, scope: &str, ip: &str, window_ms: i64, max: i64)
        -> Result<bool, StoreError>;          // true = allowed
    pub async fn incr_metric(&self, name: &str, bucket: i64) -> Result<(), StoreError>;
}
```

`KeyConfig` deserialises the camelCase JSON with defaults matching `keyDefaults`
in `standalone/src/server.js`. Tests may use a live Redis (`REDIS_URL`, default
`redis://127.0.0.1:6379`) and must **skip gracefully** when it is unreachable.

## `cap-detect` API (owner: detect agent)

Port of `core/src/trust.js` only (probe field detection lands in phase 2):

```rust
pub const SIGNAL_PENALTY: &[(&str, i32)];               // exact table from trust.js
pub struct TrustInput<'a> { pub signals: &'a [String],
                            pub network: Option<&'a NetworkSignals>,
                            pub probe_passed: Option<bool> }
pub struct Trust { pub score: i32, pub level: Level,            // 0..=100 / hostile|restricted|clean
                   pub reasons: Vec<Reason>,                    // {id, penalty, gating}
                   pub gating_failure: bool }
pub enum Action { Allow, Deny }
pub fn compute_trust(input: &TrustInput) -> Trust;
pub fn trust_action(trust: &Trust) -> Action;           // gating ⇒ Deny; score < 60 ⇒ Deny
```

Unknown signal ids default to penalty 5; duplicate ids are de-duplicated;
`probe_passed == Some(false)` applies `probe_failed`. Numbers must match
`core/test/trust.test.js` exactly — port those tests.

## `cap-embed` API (owner: embed agent)

```rust
pub enum FramePolicy { Allow(String), Deny }
pub fn frame_policy(cors_origins: &[String], parent: &str) -> FramePolicy;
pub fn embed_page(site_key: &str, parent_origin: &str, widget_url: &str) -> String;
pub fn loader_js() -> &'static str;
```

- HTML/loader text is copied from `standalone/src/embed.js` (keep the
  `cap:token` / `cap:ready` / `cap:error` messages, hidden `cap-token` input,
  same-origin `ev.origin === CAP_ORIGIN` check in the loader).
- All interpolated values must be HTML-escaped (`site_key` is validated as
  `[A-Za-z0-9_-]{1,64}` by the caller, but escape anyway).
- Tests: escaping, deny/allow matrix, presence of protocol markers.

## `cap-verify` API (owner: verify agent)

Cloudflare Turnstile–compatible contract, no HTTP:

```rust
pub enum ErrorCode { MissingInputSecret, InvalidInputSecret, MissingInputResponse,
                     InvalidInputResponse, TimeoutOrDuplicate, BadRequest }
pub struct SiteverifyRequest { pub secret: String, pub response: String,
                               pub remoteip: Option<String>, pub client_ip: Option<String>,
                               pub user_agent: Option<String>, pub hostname: Option<String> }
pub fn parse_body(content_type: &str, raw: &str) -> Option<serde_json::Map<String, serde_json::Value>>;
pub fn parse_request(map: &serde_json::Map<String, serde_json::Value>) -> Result<SiteverifyRequest, ErrorCode>;
pub fn ok_response(challenge_ts_ms: i64, hostname: &str) -> serde_json::Value;   // {success:true,"error-codes":[],challenge_ts,hostname}
pub fn err_response(code: ErrorCode, message: &str) -> serde_json::Value;        // {success:false,error,"error-codes":[code]}
pub fn check_secret(stored: &str, provided: &str) -> SecretCheck;  // Fast(bool) | Argon2Unsupported
```

`challenge_ts` is RFC3339 (`chrono`), `error-codes` strings must match
Cloudflare's (`missing-input-secret`, `invalid-input-secret`,
`missing-input-response`, `invalid-input-response`, `timeout-or-duplicate`,
`bad-request`). Constant-time compare for the fast hash.

## `cap-server` (owner: lead)

axum routes: `GET /health`, `POST /:siteKey/challenge`, `POST /:siteKey/redeem`
(verified-only), `POST /:siteKey/siteverify`, `POST /:siteKey/validate`,
`POST /turnstile/v0/siteverify`, `GET /embed.js`, `GET /embed/:siteKey`.
Phase 1 supports the `sha256-pow` protocol; `hashwx`/`rsw`/instrumentation are
phase 2 and return `{"error":"protocol_not_supported"}` until ported.
