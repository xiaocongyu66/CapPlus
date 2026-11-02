//! `cap-verify` — the Cloudflare Turnstile–compatible `/siteverify` contract,
//! implemented as pure functions (no HTTP, no Redis).
//!
//! Mirrors `cap/standalone/src/siteverify.js`: request parsing (JSON or
//! form-encoded), the six Cloudflare error codes, the success / error payload
//! shapes, secret verification (`sha256:<hex>` fast hash, legacy argon2) and
//! the end-user context precedence used for session-bind evaluation.

use serde_json::{Map, Value, json};
use subtle::ConstantTimeEq;

/// The six Cloudflare error codes Cap can emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    MissingInputSecret,
    InvalidInputSecret,
    MissingInputResponse,
    InvalidInputResponse,
    TimeoutOrDuplicate,
    BadRequest,
}

impl ErrorCode {
    /// The exact Cloudflare wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::MissingInputSecret => "missing-input-secret",
            ErrorCode::InvalidInputSecret => "invalid-input-secret",
            ErrorCode::MissingInputResponse => "missing-input-response",
            ErrorCode::InvalidInputResponse => "invalid-input-response",
            ErrorCode::TimeoutOrDuplicate => "timeout-or-duplicate",
            ErrorCode::BadRequest => "bad-request",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a raw request body into a field map.
///
/// * JSON body (any content type) → the parsed object.
/// * `application/x-www-form-urlencoded` → the decoded fields.
/// * empty body → `Some(empty map)`.
/// * anything unparseable, or a JSON value that is not an object → `None`
///   (the caller maps that to `bad-request` / HTTP 400, like the JS handler).
pub fn parse_body(content_type: &str, raw: &str) -> Option<Map<String, Value>> {
    let ct = content_type.to_ascii_lowercase();
    let text = raw.trim();
    if text.is_empty() {
        // `readBody` returns `{}` for an empty body regardless of content type.
        return Some(Map::new());
    }
    if ct.contains("application/x-www-form-urlencoded") {
        // `Object.fromEntries(new URLSearchParams(text))`: last duplicate wins.
        let mut map = Map::new();
        for (k, v) in form_urlencoded::parse(text.as_bytes()) {
            map.insert(k.into_owned(), Value::String(v.into_owned()));
        }
        return Some(map);
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// The parsed, validated shape of a `/siteverify` request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteverifyRequest {
    pub secret: String,
    pub response: String,
    /// Standard Turnstile extension.
    pub remoteip: Option<String>,
    /// Cap extension: the end user's IP.
    pub client_ip: Option<String>,
    /// Cap extension: the end user's User-Agent.
    pub user_agent: Option<String>,
    /// Cap extension: the site host the end user was on.
    pub hostname: Option<String>,
}

/// Extract a trimmed, non-empty string field.
fn ext_str(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Validate the parsed body: `secret` is required, `response` must look like a
/// Cap token (`siteKey:id:secret`). Extensions are captured when present.
pub fn parse_request(map: &Map<String, Value>) -> Result<SiteverifyRequest, ErrorCode> {
    let secret = match map.get("secret").and_then(Value::as_str).map(str::trim) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => return Err(ErrorCode::MissingInputSecret),
    };
    let response = match map.get("response").and_then(Value::as_str) {
        Some(s) if s.trim().split(':').count() == 3 => s.trim().to_owned(),
        _ => return Err(ErrorCode::MissingInputResponse),
    };
    Ok(SiteverifyRequest {
        secret,
        response,
        remoteip: ext_str(map, "remoteip"),
        client_ip: ext_str(map, "clientIp"),
        user_agent: ext_str(map, "userAgent"),
        hostname: ext_str(map, "hostname"),
    })
}

/// The site key embedded in a token — everything before the first `:`.
pub fn token_site_key(response: &str) -> Option<&str> {
    response.split_once(':').map(|(site_key, _)| site_key)
}

/// Success payload: `{success:true,"error-codes":[],challenge_ts,hostname}`.
pub fn ok_response(challenge_ts_ms: i64, hostname: &str) -> Value {
    let now = || chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(challenge_ts_ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        // An out-of-range timestamp falls back to "now" rather than panicking.
        .unwrap_or_else(now);
    json!({
        "success": true,
        "error-codes": [],
        "challenge_ts": ts,
        "hostname": hostname,
    })
}

/// Failure payload: `{success:false,error,"error-codes":[code]}`.
pub fn err_response(code: ErrorCode, message: &str) -> Value {
    json!({
        "success": false,
        "error": message,
        "error-codes": [code.as_str()],
    })
}

/// Invalid or over-budget stored PHC; distinct from a password mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPhc;

/// Shared admin/legacy-secret policy. Bounds workspace, not process RSS.
pub fn validate_argon2_phc(phc: &str) -> Result<argon2::PasswordHash<'_>, InvalidPhc> {
    if phc.len() > 1024 { return Err(InvalidPhc); }
    let parsed = argon2::PasswordHash::new(phc).map_err(|_| InvalidPhc)?;
    argon2::Algorithm::try_from(parsed.algorithm).map_err(|_| InvalidPhc)?;
    match parsed.version {
        Some(16 | 19) => {},
        _ => return Err(InvalidPhc),
    }
    // PHC costs must be explicit, not silently supplied by library defaults.
    for name in ["m", "t", "p"] {
        if parsed.params.get_decimal(name).is_none() {
            return Err(InvalidPhc);
        }
    }
    let mut salt_bytes = [0u8; 64];
    let salt = parsed.salt.ok_or(InvalidPhc)?;
    if salt.decode_b64(&mut salt_bytes).map_err(|_| InvalidPhc)?.len() < 8 {
        return Err(InvalidPhc);
    }
    let params = argon2::Params::try_from(&parsed).map_err(|_| InvalidPhc)?;
    if params.m_cost() > 65536 || params.t_cost() > 10 || params.p_cost() > 4
        || parsed.salt.is_none() || parsed.hash.is_none()
    { return Err(InvalidPhc); }
    Ok(parsed)
}

pub fn verify_argon2(password: &str, phc: &str) -> Result<bool, InvalidPhc> {
    use argon2::PasswordVerifier as _;
    let parsed = validate_argon2_phc(phc)?;
    match argon2::Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(_) => Err(InvalidPhc),
    }
}

/// Outcome of checking a provided secret against the stored `secretHash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretCheck {
    /// Fast hash compared (constant time); `true` = the secret matched.
    Fast(bool),
    /// Stored hash is a legacy password-KDF (`$argon2…`) and the value did
    /// not match. Kept for API compatibility.
    Argon2Unsupported,
}

/// Verify `provided` against a stored `secretHash`.
///
/// * `sha256:<hex>` → constant-time comparison of `sha256(provided)`.
/// * `$argon2…` → verified with Argon2id/Argon2i/Argon2d (legacy keys created
///   by the JS server).
/// * anything else → [`SecretCheck::Fast`]`(false)`.
pub fn check_secret(stored: &str, provided: &str) -> SecretCheck {
    const PREFIX: &str = "sha256:";
    if let Some(expected) = stored.strip_prefix(PREFIX) {
        let actual = cap_core::sha256_hex(provided);
        // Compare as bytes, constant time; differing lengths fail closed.
        let ok = actual.as_bytes().ct_eq(expected.as_bytes());
        return SecretCheck::Fast(bool::from(ok));
    }
    if stored.starts_with("$argon2") {
        return match verify_argon2(provided, stored) {
            Ok(true) => SecretCheck::Fast(true),
            _ => SecretCheck::Argon2Unsupported,
        };
    }
    SecretCheck::Fast(false)
}

/// Resolve the end-user context used to evaluate a session bind.
///
/// Precedence mirrors the JS `bindOk`:
/// * IP: `remoteip` → `clientIp` → first `x-forwarded-for` entry → `""`.
/// * UA: `userAgent` → `x-cap-client-ua` → `""`.
/// * Host: `hostname` → `x-cap-client-host` → `""`.
///
/// Origin/Referer parsing is deliberately left to the caller, which may pass
/// the derived host as `hostname`.
pub fn bind_inputs(
    req: &SiteverifyRequest,
    headers_xff: Option<&str>,
    headers_ua: Option<&str>,
    headers_host: Option<&str>,
) -> (String, String, String) {
    fn clean(s: Option<&str>) -> Option<String> {
        s.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    let xff_ip = headers_xff
        .and_then(|v| v.split(',').next())
        .and_then(|v| clean(Some(v)));
    let ip = clean(req.remoteip.as_deref())
        .or_else(|| clean(req.client_ip.as_deref()))
        .or(xff_ip)
        .unwrap_or_default();

    let ua = clean(req.user_agent.as_deref())
        .or_else(|| clean(headers_ua))
        .unwrap_or_default();

    let host = clean(req.hostname.as_deref())
        .or_else(|| clean(headers_host))
        .unwrap_or_default();

    (ip, ua, host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_core::SessionBind;

    fn body_json(s: &str) -> Map<String, Value> {
        parse_body("application/json", s).expect("json body")
    }

    // --- body parsing -----------------------------------------------------

    #[test]
    fn parses_json_body() {
        let m = body_json(r#"{"secret":"s","response":"k:i:j"}"#);
        assert_eq!(m.get("secret").unwrap(), "s");
        assert_eq!(m.get("response").unwrap(), "k:i:j");
    }

    #[test]
    fn parses_json_body_with_any_content_type() {
        // `readBody` falls through to JSON.parse for non-form types.
        let m = parse_body("text/plain", r#"{"a":1}"#).expect("json via text/plain");
        assert_eq!(m.get("a").unwrap(), 1);
    }

    #[test]
    fn parses_form_body() {
        let m = parse_body(
            "application/x-www-form-urlencoded; charset=utf-8",
            "secret=s%26x&response=k%3Ai%3Aj&remoteip=1.2.3.4",
        )
        .expect("form");
        assert_eq!(m.get("secret").unwrap(), "s&x");
        assert_eq!(m.get("response").unwrap(), "k:i:j");
        assert_eq!(m.get("remoteip").unwrap(), "1.2.3.4");
    }

    #[test]
    fn form_duplicate_keys_last_wins() {
        let m = parse_body("application/x-www-form-urlencoded", "a=1&a=2").unwrap();
        assert_eq!(m.get("a").unwrap(), "2");
    }

    #[test]
    fn empty_body_is_empty_map() {
        assert_eq!(parse_body("application/json", ""), Some(Map::new()));
        assert_eq!(
            parse_body("application/x-www-form-urlencoded", "   "),
            Some(Map::new())
        );
        assert_eq!(parse_body("", ""), Some(Map::new()));
    }

    #[test]
    fn garbage_body_is_none() {
        assert_eq!(parse_body("application/json", "{not json"), None);
        assert_eq!(parse_body("text/plain", "%%%"), None);
        // A JSON scalar or array is not an object → malformed request.
        assert_eq!(parse_body("application/json", "[1,2]"), None);
        assert_eq!(parse_body("application/json", "42"), None);
        assert_eq!(parse_body("application/json", "null"), None);
    }

    // --- request parsing --------------------------------------------------

    #[test]
    fn request_missing_secret() {
        let m = body_json(r#"{"response":"k:i:j"}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputSecret));
        let m = body_json(r#"{"secret":"","response":"k:i:j"}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputSecret));
        let m = body_json(r#"{"secret":7,"response":"k:i:j"}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputSecret));
    }

    #[test]
    fn request_missing_or_malformed_response() {
        let m = body_json(r#"{"secret":"s"}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputResponse));
        let m = body_json(r#"{"secret":"s","response":"k:i"}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputResponse));
        let m = body_json(r#"{"secret":"s","response":"k:i:j:x"}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputResponse));
        let m = body_json(r#"{"secret":"s","response":123}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputResponse));
        let m = body_json(r#"{"secret":"s","response":""}"#);
        assert_eq!(parse_request(&m), Err(ErrorCode::MissingInputResponse));
    }

    #[test]
    fn request_accepts_valid_token() {
        let m = body_json(r#"{"secret":"s","response":"site:abc:def"}"#);
        let r = parse_request(&m).unwrap();
        assert_eq!(r.secret, "s");
        assert_eq!(r.response, "site:abc:def");
        assert_eq!(r.remoteip, None);
        assert_eq!(r.client_ip, None);
        assert_eq!(r.user_agent, None);
        assert_eq!(r.hostname, None);
    }

    #[test]
    fn request_extracts_extensions_trimmed() {
        let m = body_json(
            r#"{"secret":"s","response":"k:i:j","remoteip":" 1.2.3.4 ",
                "clientIp":"5.6.7.8","userAgent":"  Mozilla/5.0 ","hostname":" app.example.com "}"#,
        );
        let r = parse_request(&m).unwrap();
        assert_eq!(r.remoteip.as_deref(), Some("1.2.3.4"));
        assert_eq!(r.client_ip.as_deref(), Some("5.6.7.8"));
        assert_eq!(r.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(r.hostname.as_deref(), Some("app.example.com"));
    }

    #[test]
    fn request_blank_extensions_are_none() {
        let m = body_json(
            r#"{"secret":"s","response":"k:i:j","remoteip":"   ","clientIp":"","userAgent":5}"#,
        );
        let r = parse_request(&m).unwrap();
        assert_eq!(r.remoteip, None);
        assert_eq!(r.client_ip, None);
        assert_eq!(r.user_agent, None);
    }

    #[test]
    fn form_request_end_to_end() {
        let m = parse_body(
            "application/x-www-form-urlencoded",
            "secret=s&response=k%3Ai%3Aj&userAgent=UA",
        )
        .unwrap();
        let r = parse_request(&m).unwrap();
        assert_eq!(r.response, "k:i:j");
        assert_eq!(r.user_agent.as_deref(), Some("UA"));
    }

    #[test]
    fn token_site_key_is_prefix() {
        assert_eq!(token_site_key("site:abc:def"), Some("site"));
        assert_eq!(token_site_key("a:b:c:d"), Some("a"));
        assert_eq!(token_site_key("nocolon"), None);
        assert_eq!(token_site_key(":x:y"), Some(""));
    }

    // --- response payloads ------------------------------------------------

    #[test]
    fn ok_response_shape() {
        let v = ok_response(1_700_000_000_123, "app.example.com");
        assert_eq!(v["success"], true);
        assert_eq!(v["error-codes"], json!([]));
        assert_eq!(v["hostname"], "app.example.com");
        let ts = v["challenge_ts"].as_str().unwrap();
        let parsed = chrono::DateTime::parse_from_rfc3339(ts).expect("rfc3339");
        assert_eq!(parsed.timestamp_millis(), 1_700_000_000_123);
        assert!(ts.ends_with('Z'));
        assert_eq!(v.as_object().unwrap().len(), 4);
    }

    #[test]
    fn err_response_shape() {
        let v = err_response(ErrorCode::TimeoutOrDuplicate, "nope");
        assert_eq!(v["success"], false);
        assert_eq!(v["error"], "nope");
        assert_eq!(v["error-codes"], json!(["timeout-or-duplicate"]));
        assert_eq!(v.as_object().unwrap().len(), 3);
    }

    #[test]
    fn error_code_strings() {
        assert_eq!(
            ErrorCode::MissingInputSecret.as_str(),
            "missing-input-secret"
        );
        assert_eq!(
            ErrorCode::InvalidInputSecret.as_str(),
            "invalid-input-secret"
        );
        assert_eq!(
            ErrorCode::MissingInputResponse.as_str(),
            "missing-input-response"
        );
        assert_eq!(
            ErrorCode::InvalidInputResponse.as_str(),
            "invalid-input-response"
        );
        assert_eq!(
            ErrorCode::TimeoutOrDuplicate.as_str(),
            "timeout-or-duplicate"
        );
        assert_eq!(ErrorCode::BadRequest.as_str(), "bad-request");
        assert_eq!(ErrorCode::BadRequest.to_string(), "bad-request");
    }

    // --- secret checking --------------------------------------------------

    fn stored_for(secret: &str) -> String {
        format!("sha256:{}", cap_core::sha256_hex(secret))
    }

    #[test]
    fn secret_fast_match() {
        let stored = stored_for("hunter2");
        assert_eq!(check_secret(&stored, "hunter2"), SecretCheck::Fast(true));
    }

    #[test]
    fn secret_fast_mismatch() {
        let stored = stored_for("hunter2");
        assert_eq!(check_secret(&stored, "hunter3"), SecretCheck::Fast(false));
        // Truncated / malformed stored hash also fails closed.
        assert_eq!(
            check_secret("sha256:deadbeef", "hunter2"),
            SecretCheck::Fast(false)
        );
        assert_eq!(check_secret("sha256:", ""), SecretCheck::Fast(false));
    }

    #[test]
    fn secret_wrong_prefix() {
        assert_eq!(check_secret("md5:abc", "x"), SecretCheck::Fast(false));
        assert_eq!(check_secret("", "x"), SecretCheck::Fast(false));
        assert_eq!(check_secret("hunter2", "hunter2"), SecretCheck::Fast(false));
    }

    #[test]
    fn secret_legacy_argon2() {
        let stored = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash";
        assert_eq!(
            check_secret(stored, "hunter2"),
            SecretCheck::Argon2Unsupported
        );
        assert_eq!(
            check_secret("$argon2i$v=19$x", "hunter2"),
            SecretCheck::Argon2Unsupported
        );
    }

    // --- bind input precedence -------------------------------------------

    fn req(
        remoteip: Option<&str>,
        client_ip: Option<&str>,
        user_agent: Option<&str>,
        hostname: Option<&str>,
    ) -> SiteverifyRequest {
        SiteverifyRequest {
            secret: "s".into(),
            response: "k:i:j".into(),
            remoteip: remoteip.map(str::to_owned),
            client_ip: client_ip.map(str::to_owned),
            user_agent: user_agent.map(str::to_owned),
            hostname: hostname.map(str::to_owned),
        }
    }

    #[test]
    fn bind_inputs_precedence() {
        // remoteip beats clientIp beats xff.
        let r = req(Some("1.1.1.1"), Some("2.2.2.2"), None, None);
        assert_eq!(
            bind_inputs(&r, Some("3.3.3.3, 4.4.4.4"), None, None).0,
            "1.1.1.1"
        );
        // clientIp beats xff.
        let r = req(None, Some("2.2.2.2"), None, None);
        assert_eq!(bind_inputs(&r, Some("3.3.3.3"), None, None).0, "2.2.2.2");
        // xff first value, trimmed.
        let r = req(None, None, None, None);
        assert_eq!(
            bind_inputs(&r, Some(" 3.3.3.3 , 4.4.4.4"), None, None).0,
            "3.3.3.3"
        );
        // Nothing anywhere.
        let r = req(None, None, None, None);
        assert_eq!(
            bind_inputs(&r, None, None, None),
            ("".into(), "".into(), "".into())
        );
        assert_eq!(bind_inputs(&r, Some("  "), Some(" "), Some(" ")).0, "");

        // UA: body beats header.
        let r = req(None, None, Some("body-UA"), None);
        assert_eq!(bind_inputs(&r, None, Some("hdr-UA"), None).1, "body-UA");
        let r = req(None, None, None, None);
        assert_eq!(bind_inputs(&r, None, Some("hdr-UA"), None).1, "hdr-UA");
        assert_eq!(bind_inputs(&r, None, None, None).1, "");

        // Host: body beats header.
        let r = req(None, None, None, Some("body.example"));
        assert_eq!(
            bind_inputs(&r, None, None, Some("hdr.example")).2,
            "body.example"
        );
        let r = req(None, None, None, None);
        assert_eq!(
            bind_inputs(&r, None, None, Some("hdr.example")).2,
            "hdr.example"
        );
        assert_eq!(bind_inputs(&r, None, None, None).2, "");
    }

    // --- bind integration -------------------------------------------------

    #[test]
    fn bind_matches_ua_ip_host_matrix() {
        let ts = 1_700_000_000_000;
        let bind = SessionBind::new(Some("1.2.3.4".to_string()), "Mozilla/5.0", ts);

        // Correct context passes in both modes.
        assert!(bind.matches(true, "1.2.3.4", "Mozilla/5.0", "app.example"));
        assert!(bind.matches(false, "1.2.3.4", "Mozilla/5.0", "app.example"));

        // Wrong UA always fails (UA is enforced even lenient).
        assert!(!bind.matches(true, "1.2.3.4", "Other", ""));
        assert!(!bind.matches(false, "1.2.3.4", "Other", ""));
        // Missing UA always fails.
        assert!(!bind.matches(true, "1.2.3.4", "", ""));
        assert!(!bind.matches(false, "1.2.3.4", "", ""));

        // Missing IP: strict fails, lenient passes (skip).
        assert!(!bind.matches(true, "", "Mozilla/5.0", ""));
        assert!(bind.matches(false, "", "Mozilla/5.0", ""));
        // Different IP: both fail.
        assert!(!bind.matches(true, "9.9.9.9", "Mozilla/5.0", ""));
        assert!(!bind.matches(false, "9.9.9.9", "Mozilla/5.0", ""));

        // Host is unbound by SessionBind::new → any host passes.
        assert!(bind.matches(true, "1.2.3.4", "Mozilla/5.0", ""));
        assert!(bind.matches(true, "1.2.3.4", "Mozilla/5.0", "whatever"));
    }

    #[test]
    fn bind_matches_without_ip() {
        let bind = SessionBind::new(None, "UA", 1);
        assert!(bind.ip.is_none());
        assert!(bind.matches(true, "", "UA", ""));
        assert!(bind.matches(false, "1.2.3.4", "UA", ""));
        assert!(!bind.matches(true, "", "nope", ""));
    }

    #[test]
    fn bind_inputs_feed_matches() {
        let r = req(
            Some(" 1.2.3.4 "),
            None,
            Some("Mozilla/5.0"),
            Some("app.example"),
        );
        let (ip, ua, host) = bind_inputs(&r, Some("9.9.9.9"), Some("x-ua"), Some("hdr.host"));
        let bind = SessionBind::new(Some("1.2.3.4".to_string()), "Mozilla/5.0", 42);
        assert!(bind.matches(true, &ip, &ua, &host));

        // Context from headers only, body silent.
        let r = req(None, None, None, None);
        let (ip, ua, host) = bind_inputs(&r, Some("1.2.3.4, 9.9.9.9"), Some("Mozilla/5.0"), None);
        assert!(bind.matches(true, &ip, &ua, &host));
    }

    #[test]
    fn serialize_round_trip_bind() {
        // A bind produced here is the same JSON shape the store round-trips.
        let bind = SessionBind::new(Some("1.2.3.4".into()), "UA", 7);
        let parsed: SessionBind = serde_json::from_str(&bind.to_json()).unwrap();
        assert_eq!(parsed.ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(parsed.ua, bind.ua);
        assert_eq!(parsed.ts, 7);
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};

    #[test]
    fn argon2_legacy_hash_verifies() {
        let salt = SaltString::generate(&mut OsRng);
        let stored = Argon2::default()
            .hash_password(b"sk-legacy-secret", &salt)
            .unwrap()
            .to_string();
        assert_eq!(check_secret(&stored, "sk-legacy-secret"), SecretCheck::Fast(true));
        assert_eq!(check_secret(&stored, "nope"), SecretCheck::Argon2Unsupported);
    }

    #[test]
    fn phc_policy_rejects_invalid_and_over_budget_without_work() {
        let salt = SaltString::encode_b64(b"policy-test-salt").unwrap();
        let stored = Argon2::default().hash_password(b"x", &salt).unwrap().to_string();
        for (from, to) in [("m=19456", "m=65537"), ("t=2", "t=11"),
            ("p=1", "p=5"), ("v=19", "v=20"), ("argon2id", "scrypt")] {
            let invalid = stored.replace(from, to);
            assert_ne!(invalid, stored);
            assert!(validate_argon2_phc(&invalid).is_err(), "{invalid}");
        }
        for missing in ["m=19456,", "t=2,", ",p=1"] {
            assert!(validate_argon2_phc(&stored.replace(missing, "")).is_err());
        }
        let short_salt = stored.replace(salt.as_str(), "YWJjZA");
        assert!(validate_argon2_phc(&short_salt).is_err());
        assert!(validate_argon2_phc(&"x".repeat(1025)).is_err());
        assert!(validate_argon2_phc("$argon2id$v=19$m=32,t=1,p=1").is_err());
        let legacy = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, None).unwrap())
            .hash_password(b"legacy", &salt).unwrap().to_string();
        assert_eq!(verify_argon2("legacy", &legacy), Ok(true));
        assert_eq!(verify_argon2("wrong", &legacy), Ok(false));
    }

    #[test]
    fn sha256_hash_still_works() {
        let stored = format!("sha256:{}", cap_core::sha256_hex("sk-x"));
        assert_eq!(check_secret(&stored, "sk-x"), SecretCheck::Fast(true));
        assert_eq!(check_secret(&stored, "sk-y"), SecretCheck::Fast(false));
    }
}
