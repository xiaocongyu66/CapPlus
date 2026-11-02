//! Business nonce tombstones live for 24h from first issue, without renewal.
//! After that bounded replay window callers MUST choose a fresh nonce.
//! Authentication/signature verification belongs to the caller; this module
//! compares the verified candidate to authoritative storage, never just markers.
use crate::{Store, now_ms};
use cap_core::business::{BusinessBinding, BusinessClaims, MAX_BUSINESS_TOKEN_BYTES};
use cap_core::sha256_hex;

#[derive(Debug)]
pub enum BusinessStoreError {
    Busy,
    Invalid,
    Conflict,
    Mismatch,
    Expired,
    Used,
    Storage(cap_kv::KvError),
}
impl std::fmt::Display for BusinessStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "business storage: {e}"),
            other => write!(f, "business {other:?}"),
        }
    }
}
impl std::error::Error for BusinessStoreError {}
type Result<T> = std::result::Result<T, BusinessStoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedBusiness {
    pub claims: BusinessClaims,
    pub token: String,
}

/// Authoritative snapshot. Pass bind_json unchanged to consume_business after
/// checking its SessionBind; this read alone never authorizes execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusinessTokenState {
    pub bind_json: String,
    pub expires_ms: i64,
}

/// Result-token material, generated only after challenge cryptographic checks.
/// `challenge_expires_ms` must be the signed challenge expiry, not a fresh TTL.
/// `token_ttl_ms` is the configured result lifetime (1..=86400000),
/// clamped at commit to business expiry (at most 300s). Challenge expiry must
/// be at most 24h ahead; its nonce marker survives until that signed expiry.
pub struct CompleteBusiness<'a> {
    pub challenge_nonce: &'a str,
    pub challenge_expires_ms: i64,
    pub token: &'a str,
    pub bind_json: &'a str,
    pub token_ttl_ms: i64,
}

fn canonical(prefix: &[u8], parts: &[&str]) -> String {
    let mut bytes = prefix.to_vec();
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    sha256_hex(bytes)
}
fn identity(b: &BusinessBinding) -> Result<(String, String)> {
    b.validate().map_err(|_| BusinessStoreError::Invalid)?;
    Ok((
        format!(
            "business:v1:{}",
            canonical(b"cap-business-key-v1\0", &[&b.site, &b.nonce])
        ),
        canonical(
            b"cap-business-binding-v1\0",
            &[&b.site, &b.session, &b.action, &b.nonce, &b.request_digest],
        ),
    ))
}
fn candidate(c: &BusinessClaims, token: &str) -> Result<String> {
    // Validate structure separately: authority/expiry is rechecked by Redis TIME.
    c.validate_at(c.iat)
        .map_err(|_| BusinessStoreError::Invalid)?;
    if token.is_empty() || token.len() > MAX_BUSINESS_TOKEN_BYTES {
        return Err(BusinessStoreError::Invalid);
    }
    // Lua integers are exact only below 2^53; reject unrealistic timestamps.
    if c.exp > 8_000_000_000_000_000 {
        return Err(BusinessStoreError::Invalid);
    }
    serde_json::to_string(c).map_err(|_| BusinessStoreError::Invalid)
}
fn result_keys(key: String, challenge: &str, token: &str) -> Result<Vec<String>> {
    if token.is_empty() || token.len() > 256 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(BusinessStoreError::Invalid);
    }
    Ok(vec![
        key,
        format!("blocklist:{challenge}"),
        format!("business-result:v1:token:{token}"),
        format!("business-result:v1:bind:{token}"),
        format!("business-result:v1:verified:{token}"),
    ])
}
fn args(op: &str, fp: String) -> Vec<String> {
    let mut args = vec![String::new(); 10];
    args[0] = op.into();
    args[1] = fp;
    args
}
impl Store {
    async fn business_call(&self, keys: Vec<String>, args: Vec<String>) -> Result<Vec<String>> {
        let reply = self
            .kv
            .business_transition(&keys, &args)
            .await
            .map_err(BusinessStoreError::Storage)?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(reply),
            Some("invalid") => Err(BusinessStoreError::Invalid),
            Some("conflict") => Err(BusinessStoreError::Conflict),
            Some("mismatch") => Err(BusinessStoreError::Mismatch),
            Some("expired") => Err(BusinessStoreError::Expired),
            Some("used") => Err(BusinessStoreError::Used),
            _ => Err(BusinessStoreError::Storage(cap_kv::KvError(
                "invalid business reply".into(),
            ))),
        }
    }

    /// Pass claims obtained by verifying the candidate signed credential.
    /// Concurrent identical bindings return the ORIGINAL token/claims/expiry.
    /// Solved, consumed and expired records cannot be reactivated within 24h.
    pub async fn issue_business(
        &self,
        claims: &BusinessClaims,
        token: &str,
    ) -> Result<IssuedBusiness> {
        let (key, fp) = identity(&claims.binding)?;
        let mut a = args("issue", fp);
        a[2] = candidate(claims, token)?;
        a[3] = token.into();
        a[4] = claims.iat.to_string();
        a[5] = claims.exp.to_string();
        let reply = self.business_call(vec![key], a).await?;
        let stored: BusinessClaims = reply
            .get(1)
            .and_then(|s| serde_json::from_str(s).ok())
            .ok_or_else(|| {
                BusinessStoreError::Storage(cap_kv::KvError("invalid stored claims".into()))
            })?;
        let token = reply.get(2).cloned().ok_or(BusinessStoreError::Invalid)?;
        candidate(&stored, &token).map_err(|_| {
            BusinessStoreError::Storage(cap_kv::KvError("invalid stored credential".into()))
        })?;
        if stored.binding != claims.binding {
            return Err(BusinessStoreError::Mismatch);
        }
        Ok(IssuedBusiness {
            claims: stored,
            token,
        })
    }

    /// Must follow cryptographic verification; only authoritative issued accepted.
    pub async fn check_business(&self, claims: &BusinessClaims, token: &str) -> Result<()> {
        let (key, fp) = identity(&claims.binding)?;
        let mut a = args("check", fp);
        a[2] = candidate(claims, token)?;
        a[3] = token.into();
        self.business_call(vec![key], a).await?;
        Ok(())
    }

    /// Atomically claim challenge + issued business, then publish result authority.
    /// Returns result expiry in milliseconds. Never retry by clearing markers on
    /// Storage: a lost reply means the outcome is unknown, not failure to commit.
    pub async fn complete_business(
        &self,
        claims: &BusinessClaims,
        credential: &str,
        result: CompleteBusiness<'_>,
    ) -> Result<i64> {
        let (key, fp) = identity(&claims.binding)?;
        if result.challenge_nonce.is_empty()
            || result.challenge_nonce.len() > 256
            || !result.challenge_nonce.bytes().all(|b| b.is_ascii_graphic())
            || !(1..=86_400_000).contains(&result.token_ttl_ms)
            || result.challenge_expires_ms > now_ms().saturating_add(86_400_000)
            || result.bind_json.len() > 8192
            || !serde_json::from_str::<serde_json::Value>(result.bind_json)
                .is_ok_and(|v| v.is_object())
        {
            return Err(BusinessStoreError::Invalid);
        }
        let keys = result_keys(key, result.challenge_nonce, result.token)?;
        let mut a = args("complete", fp);
        a[2] = candidate(claims, credential)?;
        a[3] = credential.into();
        a[6] = result.token.into();
        a[7] = result.bind_json.into();
        a[8] = result.challenge_expires_ms.to_string();
        a[9] = result.token_ttl_ms.to_string();
        let reply = self.business_call(keys, a).await?;
        reply.get(1).and_then(|s| s.parse().ok()).ok_or_else(|| {
            BusinessStoreError::Storage(cap_kv::KvError("invalid result expiry".into()))
        })
    }

    /// Read only a fully committed, live business result. Legacy token APIs do
    /// not read this namespace. Storage failures are never reported as absence.
    pub async fn business_token_state(
        &self,
        binding: &BusinessBinding,
        token: &str,
    ) -> Result<BusinessTokenState> {
        let (key, fp) = identity(binding)?;
        let keys = result_keys(key, "unused-business-state", token)?;
        let mut a = args("state", fp);
        a[6] = token.into();
        let reply = self.business_call(keys, a).await.map_err(|e| match e {
            BusinessStoreError::Conflict => BusinessStoreError::Mismatch,
            other => other,
        })?;
        let invalid =
            || BusinessStoreError::Storage(cap_kv::KvError("invalid business state reply".into()));
        let bind_json = reply
            .get(1)
            .filter(|s| s.len() <= 8192)
            .cloned()
            .ok_or_else(invalid)?;
        if !serde_json::from_str::<serde_json::Value>(&bind_json).is_ok_and(|v| v.is_object()) {
            return Err(invalid());
        }
        let expires_ms = reply
            .get(2)
            .and_then(|s| s.parse().ok())
            .ok_or_else(invalid)?;
        Ok(BusinessTokenState {
            bind_json,
            expires_ms,
        })
    }

    /// Compare ALL backend-confirmed binding fields before single-use mutation.
    /// `expected_bind_json` MUST be the exact raw snapshot whose SessionBind was
    /// checked by the caller, not reserialized JSON. CAS compares bytes against
    /// both authority and marker before mutation. A mismatch never burns token.
    pub async fn consume_business(
        &self,
        binding: &BusinessBinding,
        token: &str,
        expected_bind_json: &str,
    ) -> Result<String> {
        if expected_bind_json.len() > 8192
            || !serde_json::from_str::<serde_json::Value>(expected_bind_json)
                .is_ok_and(|v| v.is_object())
        {
            return Err(BusinessStoreError::Invalid);
        }
        let (key, fp) = identity(binding)?;
        let keys = result_keys(key, "unused-business-consume", token)?;
        let mut a = args("consume", fp);
        a[6] = token.into();
        a[7] = expected_bind_json.into();
        let reply = self.business_call(keys, a).await.map_err(|e| match e {
            BusinessStoreError::Conflict => BusinessStoreError::Mismatch,
            other => other,
        })?;
        reply.get(1).cloned().ok_or_else(|| {
            BusinessStoreError::Storage(cap_kv::KvError("missing result bind".into()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> BusinessBinding {
        BusinessBinding {
            site: "site".into(),
            session: "session".into(),
            action: "act".into(),
            nonce: "nonce".into(),
            request_digest: "a".repeat(64),
        }
    }
    #[tokio::test]
    #[ignore = "requires explicit isolated Redis URLs"]
    async fn isolated_business_state_machine() {
        let url = std::env::var("CAP_TEST_REDIS_URL").expect("isolated URL");
        assert_eq!(std::env::var("REDIS_URL").unwrap(), url);
        let store = Store::connect(&url).await.unwrap();
        let mut b = binding();
        b.nonce = format!("test-{}-{}", std::process::id(), now_ms());
        let now = now_ms();
        let credential =
            cap_core::business::sign_business_token(b.clone(), "test-secret", now, Some(60000))
                .unwrap();
        let c = cap_core::business::verify_business_token(&credential, "test-secret", now).unwrap();
        let (a, z) = tokio::join!(
            store.issue_business(&c, &credential),
            store.issue_business(&c, &credential)
        );
        assert_eq!(a.unwrap(), z.unwrap());
        let newer =
            cap_core::business::sign_business_token(b.clone(), "test-secret", now, Some(70000))
                .unwrap();
        let nc = cap_core::business::verify_business_token(&newer, "test-secret", now).unwrap();
        assert_eq!(
            store.issue_business(&nc, &newer).await.unwrap().token,
            credential
        );
        let mut wrong = c.clone();
        wrong.binding.action = "wrong".into();
        assert!(matches!(
            store.issue_business(&wrong, &credential).await,
            Err(BusinessStoreError::Conflict)
        ));
        store.check_business(&c, &credential).await.unwrap();
        let token = format!("result-{}", b.nonce);
        let challenge = format!("challenge-{}", b.nonce);
        let make = || CompleteBusiness {
            challenge_nonce: &challenge,
            challenge_expires_ms: now + 60000,
            token: &token,
            bind_json: "{}",
            token_ttl_ms: 60000,
        };
        // Bad type preflight cannot consume the challenge or business.
        store
            .kv
            .hset_pairs(
                &format!("business-result:v1:bind:{token}"),
                &[("bad", "type".into())],
            )
            .await
            .unwrap();
        assert!(matches!(
            store.complete_business(&c, &credential, make()).await,
            Err(BusinessStoreError::Storage(_))
        ));
        assert!(
            !store
                .kv
                .exists(&format!("blocklist:{challenge}"))
                .await
                .unwrap()
        );
        store.check_business(&c, &credential).await.unwrap();
        store
            .kv
            .del(&format!("business-result:v1:bind:{token}"))
            .await
            .unwrap();
        let (a, z) = tokio::join!(
            store.complete_business(&c, &credential, make()),
            store.complete_business(&c, &credential, make())
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(z.is_ok()), 1);
        let mut wrong = b.clone();
        wrong.request_digest = "b".repeat(64);
        assert!(matches!(
            store.consume_business(&wrong, &token, "{}").await,
            Err(BusinessStoreError::Mismatch)
        ));
        // Deterministic A-read / B-replace-both / A-consume interleaving.
        assert_eq!(
            store.token_state(&token).await.unwrap(),
            (None, None, false)
        );
        assert!(!store.consume_verified(&token).await.unwrap());
        let snapshot = store.business_token_state(&b, &token).await.unwrap();
        assert!(snapshot.expires_ms <= c.exp);
        assert!(matches!(
            store.business_token_state(&wrong, &token).await,
            Err(BusinessStoreError::Mismatch)
        ));
        assert!(matches!(
            store.business_token_state(&b, "other-token").await,
            Err(BusinessStoreError::Mismatch)
        ));
        // Even solved authority cannot compensate for missing/inconsistent markers.
        for key in &result_keys(identity(&b).unwrap().0, &challenge, &token).unwrap()[2..] {
            let original = store.kv.get(key).await.unwrap().unwrap();
            store.kv.del(key).await.unwrap();
            assert!(matches!(
                store.business_token_state(&b, &token).await,
                Err(BusinessStoreError::Invalid)
            ));
            store.kv.set_ex(key, "inconsistent", 60).await.unwrap();
            assert!(matches!(
                store.business_token_state(&b, &token).await,
                Err(BusinessStoreError::Invalid)
            ));
            store.kv.set_ex(key, &original, 60).await.unwrap();
        }
        let checked = snapshot.bind_json;
        let replacement = "{ \"changed\": true }";
        let authority = identity(&b).unwrap().0;
        store
            .kv
            .hset_pairs(&authority, &[("bind", replacement.into())])
            .await
            .unwrap();
        store
            .kv
            .set_ex(&format!("business-result:v1:bind:{token}"), replacement, 60)
            .await
            .unwrap();
        assert!(matches!(
            store.consume_business(&b, &token, &checked).await,
            Err(BusinessStoreError::Mismatch)
        ));
        assert_eq!(
            store.kv.hget(&authority, "state").await.unwrap().as_deref(),
            Some("solved")
        );
        assert!(
            store
                .kv
                .exists(&format!("business-result:v1:token:{token}"))
                .await
                .unwrap()
        );
        assert!(
            store
                .kv
                .exists(&format!("business-result:v1:verified:{token}"))
                .await
                .unwrap()
        );
        // Bytewise comparison, not semantic JSON equality.
        assert!(matches!(
            store
                .consume_business(&b, &token, "{\"changed\":true}")
                .await,
            Err(BusinessStoreError::Mismatch)
        ));
        // Restore the original snapshot so the existing single-winner assertion
        // also proves the failed CAS did not burn the result.
        store
            .kv
            .hset_pairs(&authority, &[("bind", checked.clone())])
            .await
            .unwrap();
        store
            .kv
            .set_ex(&format!("business-result:v1:bind:{token}"), &checked, 60)
            .await
            .unwrap();
        let (a, z) = tokio::join!(
            store.consume_business(&b, &token, "{}"),
            store.consume_business(&b, &token, "{}")
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(z.is_ok()), 1);
        assert!(matches!(
            store.issue_business(&c, &credential).await,
            Err(BusinessStoreError::Used)
        ));
        // A second business cannot solve with the already claimed challenge.
        let mut b2 = b.clone();
        b2.nonce.push('2');
        let t2 =
            cap_core::business::sign_business_token(b2.clone(), "test-secret", now, Some(60000))
                .unwrap();
        let c2 = cap_core::business::verify_business_token(&t2, "test-secret", now).unwrap();
        store.issue_business(&c2, &t2).await.unwrap();
        assert!(matches!(
            store.complete_business(&c2, &t2, make()).await,
            Err(BusinessStoreError::Used)
        ));
        store.check_business(&c2, &t2).await.unwrap();
        // Commit-time expiry, including a still-present authoritative tombstone.
        let mut expired = c2.clone();
        expired.iat = now - 60000;
        expired.exp = now - 1;
        store
            .kv
            .hset_pairs(
                &identity(&b2).unwrap().0,
                &[
                    ("exp", expired.exp.to_string()),
                    ("iat", expired.iat.to_string()),
                    ("claims", serde_json::to_string(&expired).unwrap()),
                ],
            )
            .await
            .unwrap();
        assert!(matches!(
            store.check_business(&c2, &t2).await,
            Err(BusinessStoreError::Expired)
        ));
        // Simulate markers left by an interrupted commit: issued cannot consume.
        store
            .kv
            .hset_pairs(
                &identity(&b2).unwrap().0,
                &[
                    ("exp", c2.exp.to_string()),
                    ("iat", c2.iat.to_string()),
                    ("claims", serde_json::to_string(&c2).unwrap()),
                ],
            )
            .await
            .unwrap();
        let orphan_keys = result_keys(identity(&b2).unwrap().0, &challenge, &token).unwrap();
        // Each possible interrupted prefix before authority publication: no
        // marker, token only, token+bind, and token+bind+verified.
        for stage in 0..=3 {
            if stage > 0 {
                let value = match stage {
                    1 => (now + 60000).to_string(),
                    2 => "{}".into(),
                    _ => "1".into(),
                };
                store
                    .kv
                    .set_ex(&orphan_keys[stage + 1], &value, 60)
                    .await
                    .unwrap();
            }
            assert!(matches!(
                store.business_token_state(&b2, &token).await,
                Err(BusinessStoreError::Invalid)
            ));
            assert!(matches!(
                store.consume_business(&b2, &token, "{}").await,
                Err(BusinessStoreError::Invalid)
            ));
            assert_eq!(
                store.token_state(&token).await.unwrap(),
                (None, None, false)
            );
            assert!(!store.consume_verified(&token).await.unwrap());
            for key in &orphan_keys[2..2 + stage] {
                assert!(
                    store.kv.exists(key).await.unwrap(),
                    "legacy consume must not delete business marker"
                );
            }
        }
        // Read-side type corruption is Storage, never a false/absent result.
        store.kv.del(&orphan_keys[3]).await.unwrap();
        store
            .kv
            .hset_pairs(&orphan_keys[3], &[("bad", "type".into())])
            .await
            .unwrap();
        assert!(matches!(
            store.business_token_state(&b2, &token).await,
            Err(BusinessStoreError::Storage(_))
        ));
        let mut keys = result_keys(identity(&b).unwrap().0, &challenge, &token).unwrap();
        keys.push(identity(&b2).unwrap().0);
        store.kv.del_many(&keys).await.unwrap();
    }

    #[test]
    fn canonical_fields_and_budgets() {
        assert_ne!(canonical(b"x", &["ab", "c"]), canonical(b"x", &["a", "bc"]));
        let b = binding();
        let (key, fp) = identity(&b).unwrap();
        for field in ["session", "action", "requestDigest"] {
            let mut v = serde_json::to_value(&b).unwrap();
            v[field] = if field == "requestDigest" {
                "b".repeat(64).into()
            } else {
                "different".into()
            };
            let other = identity(&serde_json::from_value(v).unwrap()).unwrap();
            assert_eq!(key, other.0);
            assert_ne!(fp, other.1);
        }
        let mut b = b;
        b.nonce = "x".repeat(257);
        assert!(identity(&b).is_err());
        assert!(result_keys(key, "challenge", &"x".repeat(257)).is_err());
    }
}
