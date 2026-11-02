use crate::{jwt_sign, jwt_verified_payload, random_hex, sha256_hex};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const BUSINESS_TOKEN_TYPE: &str = "cap-business";
pub const BUSINESS_TOKEN_VERSION: u32 = 1;
pub const DEFAULT_BUSINESS_TTL_MS: i64 = 120_000;
pub const MAX_BUSINESS_TTL_MS: i64 = 300_000;
pub const MAX_BUSINESS_TOKEN_BYTES: usize = 8192;
pub const MAX_SITE_BYTES: usize = 128;
pub const MAX_SESSION_BYTES: usize = 256;
pub const MAX_ACTION_BYTES: usize = 128;
pub const MAX_NONCE_BYTES: usize = 256;
pub const MAX_REQUEST_METHOD_BYTES: usize = 32;
pub const MAX_REQUEST_ROUTE_BYTES: usize = 4096;
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const REQUEST_DIGEST_PREFIX: &[u8] = b"cap-business-request-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessError {
    InvalidField(&'static str),
    InvalidToken,
    InvalidTypeOrVersion,
    InvalidTime,
    InvalidTtl,
    TokenTooLong,
}

impl fmt::Display for BusinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid business field: {field}"),
            Self::InvalidToken => f.write_str("invalid business token"),
            Self::InvalidTypeOrVersion => f.write_str("invalid business type or version"),
            Self::InvalidTime => f.write_str("invalid business time"),
            Self::InvalidTtl => f.write_str("invalid business TTL"),
            Self::TokenTooLong => f.write_str("business token too long"),
        }
    }
}

impl std::error::Error for BusinessError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusinessBinding {
    pub site: String,
    pub session: String,
    pub action: String,
    pub nonce: String,
    pub request_digest: String,
}

impl BusinessBinding {
    /// 字节长度有界；session/action 只允许 ASCII 0x21..=0x7e，不裁剪或规范化。
    /// nonce 允许非控制 Unicode；随机性及业务唯一性不能靠格式校验保证。
    pub fn validate(&self) -> Result<(), BusinessError> {
        if !bounded(&self.site, MAX_SITE_BYTES)
            || !self
                .site
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(BusinessError::InvalidField("site"));
        }
        for (field, value, max) in [
            ("session", self.session.as_str(), MAX_SESSION_BYTES),
            ("action", self.action.as_str(), MAX_ACTION_BYTES),
        ] {
            if !bounded(value, max) || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                return Err(BusinessError::InvalidField(field));
            }
        }
        if !bounded(&self.nonce, MAX_NONCE_BYTES) || self.nonce.chars().any(char::is_control) {
            return Err(BusinessError::InvalidField("nonce"));
        }
        if self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(BusinessError::InvalidField("requestDigest"));
        }
        Ok(())
    }
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

/// 生成 128-bit 随机业务标识；去重、幂等和消费状态仍由存储层负责。
pub fn new_business_nonce() -> String {
    random_hex(32)
}

/// 编码为版本前缀 + method/route/body 各自的 u64 BE 字节长度和原始字节。
/// method 必须已大写；不隐式改写大小写、路由或 JSON。
/// 接入方须将具体资源及影响业务的 query/header 纳入 route_id 或 body，
/// 并将凭据放在 body 外，避免摘要自引用。本函数不持久化正文。
pub fn request_digest(
    method: &str,
    route_id: &str,
    raw_body: &[u8],
) -> Result<String, BusinessError> {
    if !bounded(method, MAX_REQUEST_METHOD_BYTES)
        || !method.bytes().all(|b| {
            b.is_ascii_uppercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
    {
        return Err(BusinessError::InvalidField("method"));
    }
    if !bounded(route_id, MAX_REQUEST_ROUTE_BYTES) || route_id.chars().any(char::is_control) {
        return Err(BusinessError::InvalidField("routeId"));
    }
    if raw_body.len() > MAX_REQUEST_BODY_BYTES {
        return Err(BusinessError::InvalidField("body"));
    }
    let mut encoded = Vec::with_capacity(
        REQUEST_DIGEST_PREFIX.len() + 24 + method.len() + route_id.len() + raw_body.len(),
    );
    encoded.extend_from_slice(REQUEST_DIGEST_PREFIX);
    for part in [method.as_bytes(), route_id.as_bytes(), raw_body] {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    Ok(sha256_hex(encoded))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BusinessClaims {
    pub typ: String,
    pub v: u32,
    pub binding: BusinessBinding,
    pub iat: i64,
    pub exp: i64,
}

impl BusinessClaims {
    /// 所有时间均为 Unix 毫秒；反序列化不等于验证，读取存储后也须调用此方法。
    pub fn validate_at(&self, now_ms: i64) -> Result<(), BusinessError> {
        if self.typ != BUSINESS_TOKEN_TYPE || self.v != BUSINESS_TOKEN_VERSION {
            return Err(BusinessError::InvalidTypeOrVersion);
        }
        self.binding.validate()?;
        if now_ms < 0 || self.iat < 0 || self.iat > now_ms || self.exp <= now_ms {
            return Err(BusinessError::InvalidTime);
        }
        let ttl = self
            .exp
            .checked_sub(self.iat)
            .ok_or(BusinessError::InvalidTime)?;
        if !(1..=MAX_BUSINESS_TTL_MS).contains(&ttl) {
            return Err(BusinessError::InvalidTtl);
        }
        Ok(())
    }
}

/// 仅生成密码学凭据；调用方必须先鉴权，并负责 nonce 幂等存储。
/// ttl_ms=None 使用默认 120 秒；不接受零、负数或超过 300 秒。
pub fn sign_business_token(
    binding: BusinessBinding,
    secret: &str,
    now_ms: i64,
    ttl_ms: Option<i64>,
) -> Result<String, BusinessError> {
    let ttl = ttl_ms.unwrap_or(DEFAULT_BUSINESS_TTL_MS);
    if !(1..=MAX_BUSINESS_TTL_MS).contains(&ttl) {
        return Err(BusinessError::InvalidTtl);
    }
    let exp = now_ms.checked_add(ttl).ok_or(BusinessError::InvalidTime)?;
    let claims = BusinessClaims {
        typ: BUSINESS_TOKEN_TYPE.into(),
        v: BUSINESS_TOKEN_VERSION,
        binding,
        iat: now_ms,
        exp,
    };
    claims.validate_at(now_ms)?;
    let payload = serde_json::to_value(claims).map_err(|_| BusinessError::InvalidToken)?;
    let token = jwt_sign(&payload, secret);
    if token.len() > MAX_BUSINESS_TOKEN_BYTES {
        return Err(BusinessError::TokenTooLong);
    }
    Ok(token)
}

/// 只验证签名、类型、字段及时间；调用方仍须比较预期绑定并原子消费存储状态。
pub fn verify_business_token(
    token: &str,
    secret: &str,
    now_ms: i64,
) -> Result<BusinessClaims, BusinessError> {
    if token.len() > MAX_BUSINESS_TOKEN_BYTES {
        return Err(BusinessError::TokenTooLong);
    }
    let payload = jwt_verified_payload(token, secret).ok_or(BusinessError::InvalidToken)?;
    let claims: BusinessClaims =
        serde_json::from_slice(&payload).map_err(|_| BusinessError::InvalidToken)?;
    claims.validate_at(now_ms)?;
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JWT_HEADER_B64, hmac_sha256, jwt_verify};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::json;

    fn sign_raw_payload(payload: &str) -> String {
        let input = format!("{JWT_HEADER_B64}.{}", URL_SAFE_NO_PAD.encode(payload));
        let sig = URL_SAFE_NO_PAD.encode(hmac_sha256("key", &input));
        format!("{input}.{sig}")
    }

    #[test]
    fn authenticated_raw_json_rejects_duplicate_and_unknown_fields() {
        let token = sign_business_token(binding(), "key", 1000, None).unwrap();
        let payload = jwt_verify(&token, "key").unwrap();
        let raw = serde_json::to_string(&payload).unwrap();
        let valid = sign_raw_payload(&raw);
        assert_eq!(
            verify_business_token(&valid, "key", 1000).unwrap().binding,
            binding()
        );

        for (object, fields) in [
            (&payload, &["typ", "v", "binding", "iat", "exp"][..]),
            (
                &payload["binding"],
                &["site", "session", "action", "nonce", "requestDigest"][..],
            ),
        ] {
            for field in fields {
                let member = format!("\"{field}\":{}", object[field]);
                let duplicate = raw.replacen(&member, &format!("{member},{member}"), 1);
                assert_ne!(duplicate, raw);
                let signed = sign_raw_payload(&duplicate);
                assert_eq!(
                    jwt_verified_payload(&signed, "key").unwrap(),
                    duplicate.as_bytes()
                );
                assert_eq!(jwt_verify(&signed, "key").unwrap(), payload);
                assert_eq!(
                    verify_business_token(&signed, "key", 1000),
                    Err(BusinessError::InvalidToken),
                    "{field}"
                );
            }
        }

        for bad in [
            raw.replacen("\"exp\":121000", "\"exp\":1000,\"exp\":121000", 1),
            raw.replacen("\"action\":", "\"action\":\"other\",\"action\":", 1),
            raw.replacen(
                "\"requestDigest\":",
                "\"requestDigest\":\"invalid\",\"requestDigest\":",
                1,
            ),
            raw.replacen("\"exp\":", "\"extra\":1,\"exp\":", 1),
            raw.replacen("\"action\":", "\"extra\":1,\"action\":", 1),
        ] {
            assert_ne!(bad, raw);
            let signed = sign_raw_payload(&bad);
            assert_eq!(
                jwt_verified_payload(&signed, "key").unwrap(),
                bad.as_bytes()
            );
            let collapsed = jwt_verify(&signed, "key").unwrap();
            if !bad.contains("\"extra\"") {
                assert_eq!(collapsed, payload);
                assert!(
                    serde_json::from_value::<BusinessClaims>(collapsed)
                        .unwrap()
                        .validate_at(1000)
                        .is_ok()
                );
            }
            assert_eq!(
                verify_business_token(&signed, "key", 1000),
                Err(BusinessError::InvalidToken)
            );
        }
    }

    fn binding() -> BusinessBinding {
        BusinessBinding {
            site: "a1b2c3d4e5".into(),
            session: "session:abc/DEF+123=".into(),
            action: "orders.create".into(),
            nonce: "550e8400-e29b-41d4-a716-446655440000".into(),
            request_digest: request_digest("POST", "/orders/42?currency=CNY", br#"{"amount":100}"#)
                .unwrap(),
        }
    }

    #[test]
    fn digest_known_vectors() {
        assert_eq!(
            binding().request_digest,
            "b60d8ba971979d812dd9d921b05803a10e575ad693921eb43f1e2d58e51a0065"
        );
        assert_eq!(
            request_digest("GET", "/订单/四十二?币种=元", b"").unwrap(),
            "f5558afa1e6417375ef1432c85d6482edb57f87cb6259c77f37abe4a7932c6ff"
        );
    }

    #[test]
    fn digest_preserves_boundaries_and_raw_content() {
        let digest = |m, r, b| request_digest(m, r, b).unwrap();
        assert_ne!(digest("AB", "C", b""), digest("A", "BC", b""));
        assert_ne!(digest("GET", "ab", b"c"), digest("GET", "a", b"bc"));
        assert_ne!(digest("GET", "/42?q=a", b""), digest("GET", "/42?q=b", b""));
        assert_ne!(digest("GET", "/42", b""), digest("GET", "/43", b""));
        assert_ne!(digest("GET", "/42", b""), digest("POST", "/42", b""));
        assert_ne!(
            digest("POST", "/", br#"{"a":1,"b":2}"#),
            digest("POST", "/", br#"{"b":2,"a":1}"#)
        );
        assert_ne!(digest("POST", "/", b"x"), digest("POST", "/", b"x "));
        assert_ne!(digest("GET", "/é", b""), digest("GET", "/e\u{301}", b""));
        assert!(request_digest("POST", "/", &[0, 255]).is_ok());
    }

    #[test]
    fn digest_input_limits() {
        for method in ["", "get", "Get", "G ET", "G\nET", "GÉT", "GET/", "GET:"] {
            assert!(request_digest(method, "/", b"").is_err(), "{method:?}");
        }
        assert!(request_digest("!#$%&'*+-.^_`|~09AZ", "/", b"").is_ok());
        assert!(request_digest(&"A".repeat(MAX_REQUEST_METHOD_BYTES), "/", b"").is_ok());
        assert!(request_digest(&"A".repeat(MAX_REQUEST_METHOD_BYTES + 1), "/", b"").is_err());
        for route in ["", "/\n", "/\u{85}"] {
            assert!(request_digest("GET", route, b"").is_err());
        }
        assert!(request_digest("GET", &"é".repeat(MAX_REQUEST_ROUTE_BYTES / 2), b"").is_ok());
        assert!(request_digest("GET", &"a".repeat(MAX_REQUEST_ROUTE_BYTES + 1), b"").is_err());
        assert!(request_digest("POST", "/", &vec![0; MAX_REQUEST_BODY_BYTES]).is_ok());
        assert!(request_digest("POST", "/", &vec![0; MAX_REQUEST_BODY_BYTES + 1]).is_err());
    }

    #[test]
    fn binding_field_validation() {
        for (field, max) in [
            ("site", MAX_SITE_BYTES),
            ("session", MAX_SESSION_BYTES),
            ("action", MAX_ACTION_BYTES),
            ("nonce", MAX_NONCE_BYTES),
        ] {
            for (size, valid) in [(0, false), (1, true), (max, true), (max + 1, false)] {
                let mut value = serde_json::to_value(binding()).unwrap();
                value[field] = json!("a".repeat(size));
                let parsed: BusinessBinding = serde_json::from_value(value).unwrap();
                assert_eq!(parsed.validate().is_ok(), valid, "{field}: {size}");
            }
        }
        let mut b = binding();
        for site in ["f6g7h8i9j0", "site_-ABC", "0"] {
            b.site = site.into();
            assert!(b.validate().is_ok());
        }
        for site in [" a", "a ", "a/b", "a:b", "a.b", "站点"] {
            b.site = site.into();
            assert!(b.validate().is_err());
        }
        for field in ["session", "action"] {
            for invalid in [" a", "a ", "a\t", "é", "\u{7f}"] {
                let mut value = serde_json::to_value(binding()).unwrap();
                value[field] = json!(invalid);
                assert!(
                    serde_json::from_value::<BusinessBinding>(value)
                        .unwrap()
                        .validate()
                        .is_err()
                );
            }
        }
        let mut b = binding();
        for nonce in ["业务 nonce:42/abc", " uuid ", "é"] {
            b.nonce = nonce.into();
            assert!(b.validate().is_ok());
            assert_eq!(b.nonce, nonce);
        }
        for nonce in ["\0", "a\n", "a\u{85}", "\u{7f}"] {
            b.nonce = nonce.into();
            assert!(b.validate().is_err());
        }
        let mut b = binding();
        for digest in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            format!("{} ", "0".repeat(63)),
        ] {
            b.request_digest = digest;
            assert!(b.validate().is_err());
        }
    }

    #[test]
    fn strict_serde_schema() {
        let value = serde_json::to_value(binding()).unwrap();
        assert!(value.get("requestDigest").is_some());
        for field in ["site", "session", "action", "nonce", "requestDigest"] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<BusinessBinding>(missing).is_err());
            for invalid in [json!(null), json!(42), json!([]), json!(true)] {
                let mut wrong = value.clone();
                wrong[field] = invalid;
                assert!(serde_json::from_value::<BusinessBinding>(wrong).is_err());
            }
        }
        let mut unknown = value;
        unknown["extra"] = json!(1);
        assert!(serde_json::from_value::<BusinessBinding>(unknown).is_err());
    }

    #[test]
    fn nonce_generator_has_128_bits_of_output() {
        let nonce = new_business_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(
            nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        let mut b = binding();
        b.nonce = nonce;
        assert!(b.validate().is_ok());
    }

    #[test]
    fn token_roundtrip_time_boundaries_and_signature() {
        let now = 1_900_000_000_000;
        let token = sign_business_token(binding(), "key", now, None).unwrap();
        let claims = verify_business_token(&token, "key", now).unwrap();
        assert_eq!(claims.binding, binding());
        assert_eq!(claims.typ, BUSINESS_TOKEN_TYPE);
        assert_eq!(claims.v, 1);
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, now + DEFAULT_BUSINESS_TTL_MS);
        assert!(verify_business_token(&token, "key", claims.exp - 1).is_ok());
        for time in [-1, now - 1, claims.exp, claims.exp + 1] {
            assert!(verify_business_token(&token, "key", time).is_err());
        }
        assert!(verify_business_token(&token, "wrong-key", now).is_err());
        assert!(verify_business_token(&(token + "x"), "key", now).is_err());
        for ttl in [1, MAX_BUSINESS_TTL_MS] {
            assert!(sign_business_token(binding(), "key", now, Some(ttl)).is_ok());
        }
        for ttl in [i64::MIN, -1, 0, MAX_BUSINESS_TTL_MS + 1, i64::MAX] {
            assert!(sign_business_token(binding(), "key", now, Some(ttl)).is_err());
        }
        for time in [i64::MIN, -1, i64::MAX] {
            assert!(sign_business_token(binding(), "key", time, None).is_err());
        }
        assert!(sign_business_token(binding(), "key", i64::MAX - 1, Some(1)).is_ok());
        let mut invalid = binding();
        invalid.session.clear();
        assert!(sign_business_token(invalid, "key", now, None).is_err());
    }

    #[test]
    fn signed_invalid_claims_and_challenge_are_rejected() {
        let now = 1000;
        let token = sign_business_token(binding(), "key", now, None).unwrap();
        let payload = jwt_verify(&token, "key").unwrap();
        for (field, bad) in [
            ("typ", json!("JWT")),
            ("v", json!(2)),
            ("v", json!("1")),
            ("iat", json!(now + 1)),
            ("iat", json!(-1)),
            ("iat", json!(i64::MIN)),
            ("exp", json!(now)),
            ("exp", json!(0)),
            ("exp", json!(i64::MAX)),
            ("exp", json!(now + MAX_BUSINESS_TTL_MS + 1)),
            ("iat", json!(1.5)),
            ("exp", json!("121000")),
            ("extra", json!(1)),
        ] {
            let mut bad_payload = payload.clone();
            bad_payload[field] = bad;
            assert!(
                verify_business_token(&jwt_sign(&bad_payload, "key"), "key", now).is_err(),
                "{field}"
            );
        }
        for field in ["typ", "v", "binding", "iat", "exp"] {
            let mut bad_payload = payload.clone();
            bad_payload.as_object_mut().unwrap().remove(field);
            assert!(verify_business_token(&jwt_sign(&bad_payload, "key"), "key", now).is_err());
        }
        for field in [
            "site",
            "session",
            "action",
            "nonce",
            "requestDigest",
            "extra",
        ] {
            let mut bad_payload = payload.clone();
            bad_payload["binding"][field] = json!("");
            assert!(verify_business_token(&jwt_sign(&bad_payload, "key"), "key", now).is_err());
        }
        let challenge = jwt_sign(
            &json!({"n":"abc", "c":2, "s":8, "d":1, "exp":121000, "iat":1000}),
            "key",
        );
        assert!(verify_business_token(&challenge, "key", now).is_err());
        for size in [0, MAX_BUSINESS_TOKEN_BYTES, MAX_BUSINESS_TOKEN_BYTES + 1] {
            assert!(verify_business_token(&"a".repeat(size), "key", now).is_err());
        }
        assert_eq!(
            verify_business_token(&"a".repeat(MAX_BUSINESS_TOKEN_BYTES + 1), "key", now),
            Err(BusinessError::TokenTooLong)
        );
    }

    #[test]
    fn maximum_binding_fits_token_limit() {
        let b = BusinessBinding {
            site: "a".repeat(MAX_SITE_BYTES),
            session: "\"".repeat(MAX_SESSION_BYTES),
            action: "\\".repeat(MAX_ACTION_BYTES),
            nonce: "\"".repeat(MAX_NONCE_BYTES),
            request_digest: "f".repeat(64),
        };
        let token = sign_business_token(b.clone(), "key", 0, None).unwrap();
        assert!(token.len() <= MAX_BUSINESS_TOKEN_BYTES);
        assert_eq!(verify_business_token(&token, "key", 0).unwrap().binding, b);
    }
}
