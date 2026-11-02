//! `POST /:siteKey/redeem`: verify the proof, consume the challenge, issue the
//! verification token and compute the trust verdict.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cap_core::{jwt_sig_hex, jwt_verify, random_hex, verify_pow, PowParams, SessionBind};
use cap_store::now_ms;
use serde_json::{json, Value};

use crate::http_util::{
    client_ip, cors_origins, header_str, hourly_bucket, network_signals, same_origin,
};
use crate::integrity::{check_challenge_env, check_integrity, embed_parent};
use crate::{
    rate_allowed, record_geo, settings, v2, AppState, CHALLENGE_TTL_MS, REDEEM_MAX_FAILS,
    REDEEM_RL_MAX, REDEEM_RL_WINDOW_MS, TOKEN_TTL_MS,
};

fn parse_redeem_body(body: &[u8]) -> Result<Value, ()> {
    if body.len() > 1024 * 1024 { return Err(()); }
    struct StrictValue(Value);
    impl<'de> serde::Deserialize<'de> for StrictValue {
        fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
            de.deserialize_any(UniqueObject).map(Self)
        }
    }
    struct UniqueObject;
    impl<'de> serde::de::Visitor<'de> for UniqueObject {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("unique request fields") }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
            let mut map = serde_json::Map::new();
            while let Some((key, StrictValue(value))) = input.next_entry::<String, StrictValue>()? {
                if map.insert(key, value).is_some() { return Err(serde::de::Error::custom("duplicate field")); }
            }
            Ok(Value::Object(map))
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
            let mut values = Vec::new();
            while let Some(StrictValue(value)) = input.next_element::<StrictValue>()? { values.push(value); }
            Ok(Value::Array(values))
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> { Ok(Value::Bool(value)) }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> { Ok(value.into()) }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> { Ok(value.into()) }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
            serde_json::Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("invalid number"))
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> { Ok(Value::String(value.into())) }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> { Ok(Value::String(value)) }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    }
    let mut de = serde_json::Deserializer::from_slice(body);
    let value = serde::Deserializer::deserialize_map(&mut de, UniqueObject).map_err(|_| ())?;
    de.end().map_err(|_| ())?;
    Ok(value)
}

pub(crate) async fn redeem(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !cap_embed::validate_site_key(&site_key) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
    }
    if !same_origin(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "verified_session_required",
                "reason": "solve challenges inside the Cap-hosted iframe (embed.js)"
            })),
        )
            .into_response();
    }

    let ip = client_ip(&headers, &addr.ip().to_string());
    if !rate_allowed(&st, &format!("redeem:{site_key}"), &ip, REDEEM_RL_WINDOW_MS, REDEEM_RL_MAX).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "Rate limit exceeded"})),
        )
            .into_response();
    }

    if body.len() > 1024 * 1024 {
        return crate::business::failure(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    // Typed credential extraction rejects duplicate credential fields rather
    // than letting a JSON map silently choose the last value.
    #[derive(serde::Deserialize)]
    struct CredentialInput {
        #[serde(rename = "businessToken")]
        business_token: String,
    }
    let Ok(credential_input) = serde_json::from_slice::<CredentialInput>(&body) else {
        return crate::business::failure(StatusCode::BAD_REQUEST, "business_token_required");
    };
    if credential_input.business_token.len() > cap_core::business::MAX_BUSINESS_TOKEN_BYTES {
        return crate::business::failure(StatusCode::BAD_REQUEST, "invalid_business_token");
    }
    let Ok(payload) = parse_redeem_body(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_body"}))).into_response();
    };
    let token = payload.get("token").and_then(Value::as_str).unwrap_or("");
    if token.is_empty() || token.len() > 512 * 1024 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing_token"}))).into_response();
    }
    let Some(sols) = payload.get("solutions").and_then(Value::as_array) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "missing_solutions"})),
        )
            .into_response();
    };
    // v1 solutions are bare integers; v2 solutions are objects per challenge.
    if sols.len() > 4096 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid solutions"})),
        )
            .into_response();
    }
    let solutions_raw: Vec<Value> = sols.clone();

    let key = match st.cache.key_checked(&st.store, &site_key).await {
        Err(_) => return crate::business::failure(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
        Ok(Some(k)) => Arc::unwrap_or_clone(k),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Invalid site key or secret"})),
            )
                .into_response()
        }
    };

    let Some(claims) = jwt_verify(token, &key.jwt_secret) else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
    };
    // A challenge JWT is only good for redeeming a challenge of the site key
    // it was minted for; `typ` keeps any other token signed with the same
    // per-key secret from being presented here.
    if claims.get("sk").and_then(Value::as_str) != Some(site_key.as_str())
        || claims.get("typ").and_then(Value::as_str) != Some("chal")
    {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "scope_mismatch"}))).into_response();
    }
    let Some(credential) = payload.get("businessToken").and_then(Value::as_str) else {
        return crate::business::failure(StatusCode::BAD_REQUEST, "business_token_required");
    };
    let business = match crate::business::checked_credential(&st, &site_key, &key.jwt_secret, credential).await {
        Ok(claims) => claims,
        Err(response) => return *response,
    };
    if claims.get("businessHash").and_then(Value::as_str) != Some(cap_core::sha256_hex(credential).as_str())
        || claims.get("businessBinding") != Some(&json!(business.binding)) {
        return crate::business::failure(StatusCode::BAD_REQUEST, "business_mismatch");
    }
    // 验证前原子预占次数，确保并发请求也不能突破计算预算。
    let attempt_key = format!("redeem-attempt:{}", jwt_sig_hex(token).unwrap_or_default());
    let allowed = if st.redis_ratelimit {
        st.kv
            .incr_with_expire(&attempt_key, CHALLENGE_TTL_MS / 1000)
            .await
            .map(|count| count <= REDEEM_MAX_FAILS)
            .unwrap_or(false)
    } else {
        st.limiter.claim_attempt(&attempt_key, CHALLENGE_TTL_MS, REDEEM_MAX_FAILS)
    };
    if !allowed {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "too_many_attempts"}))).into_response();
    }
    let env = match
        check_challenge_env(&st, token, &headers, &addr, key.config.require_session_bind).await
    {
        Ok(env) => env,
        Err(reason) => {
            st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now_ms()).to_string(), 1);
            let status = if reason == "store_unavailable" {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_REQUEST
            };
            return (status, Json(json!({ "error": reason }))).into_response();
        }
    };
    // Server-side embed session: the redeem must come from the same signed
    // embed context (same sid) that fetched the challenge. A stolen token is
    // useless in another framing because its chalenv sid no longer matches.
    let embed = match embed_parent(&headers, &site_key, &key.jwt_secret, &cors_origins(&key.config))
    {
        Ok(embed) => embed,
        Err(reason) => {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
        }
    };
    let sent_sid = embed.as_ref().map(|e| e.sid.as_str());
    if !session_matches(env.sid.as_deref(), sent_sid,
        settings().require_verify_session && !cors_origins(&key.config).is_empty()) {
        st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now_ms()).to_string(), 1);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "verified_session_required",
                "reason": "the challenge requires its original embed session",
            })),
        ).into_response();
    }
    let parent = env.parent;
    if let Err(reason) = check_integrity(&claims, &payload, &key.jwt_secret) {
        st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now_ms()).to_string(), 1);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "integrity", "reason": reason })),
        )
            .into_response();
    }
    let now = now_ms();
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if exp <= now {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "expired"}))).into_response();
    }
    let is_v2 = claims.get("f").and_then(Value::as_u64) == Some(2);
    // Observation work is opt-in. A missing/unavailable service must not alter
    // verification. try_record checks the gate again before enqueueing.
    let training_enabled = st.training.as_ref()
        .is_some_and(|service| service.enabled(&site_key));
    // Server wall-time observation: proof/admission/detection/nonce waits,
    // ending at policy evaluation; not client timing or pure CPU/GPU duration.
    let training_started = std::time::Instant::now();
    let mut training_client = None;
    let mut v2_trust: Option<(cap_detect::Trust, cap_detect::Action)> = None;
    // Protocol-layer findings from the trusted proxy. Present for both
    // protocols: these describe the connection, not the client's claims.
    let net = match network_signals(&headers, &addr.ip().to_string()) {
        Ok(net) => net,
        Err(_) => return (StatusCode::FORBIDDEN, Json(json!({"error": "verification_failed"}))).into_response(),
    };
    if !is_v2 {
        // As with v2, verify the proof before spending CPU on detection.
        let token_cpu = token.to_owned();
        let claims_cpu = claims.clone();
        let solutions_cpu = solutions_raw.clone();
        let work = move || verify_v1_pow(&token_cpu, &claims_cpu, &solutions_cpu);
        #[cfg(test)]
        let result = interleaving_tests::run(work).await;
        #[cfg(not(test))]
        let result = cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::General, work).await;
        let verdict = match result {
            Ok(verdict) => verdict,
            Err(error) => return crate::cpu_error_response(error),
        };
        if let Err(reason) = verdict {
            let status = if reason == "invalid_solutions" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::FORBIDDEN
            };
            if reason == "Invalid solution" {
                st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now_ms()).to_string(), 1);
            }
            return (status, Json(json!({"error": reason}))).into_response();
        }
        // v1 carries its instrumentation meta sealed in `ei`. Without it an
        // automated client on the old protocol would never be fingerprinted.
        let mut sigs: Vec<cap_detect::Signal> = Vec::new();
        let mut judged = false;
        if let Some(ei) = claims.get("ei").and_then(Value::as_str) {
            let Some(meta) = v2::decrypt_gcm(ei, &key.jwt_secret, v2::INFO_FMT2) else {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "instr_corrupted"})),
                )
                    .into_response();
            };
            if payload.get("instr_blocked").and_then(Value::as_bool) == Some(true) {
                return (StatusCode::FORBIDDEN, Json(json!({"error": "instr_blocked"})))
                    .into_response();
            }
            if payload.get("instr_timeout").and_then(Value::as_bool) == Some(true) {
                return (StatusCode::FORBIDDEN, Json(json!({"error": "instr_timeout"})))
                    .into_response();
            }
            let Some(instr) = payload.get("instr") else {
                return (StatusCode::FORBIDDEN, Json(json!({"error": "instr_missing"})))
                    .into_response();
            };
            let meta_cpu = meta.clone();
            let instr_cpu = instr.clone();
            let verdict = match cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::General,
                move || v2::verify_instr_observation(&meta_cpu, &instr_cpu)).await {
                Ok(verdict) => verdict,
                Err(error) => return crate::cpu_error_response(error),
            };
            let verified = match verdict {
                Ok(verified) => verified,
                Err(reason) => return (StatusCode::FORBIDDEN, Json(json!({"error": reason}))).into_response(),
            };
            // Only compact whitelist features survive the capture lifetime;
            // do not queue or retain a second raw probe for observation.
            if training_enabled && verified.mac_verified
                && let Some(probe) = instr.get("p")
            {
                training_client = Some(crate::training_capture::extract(probe, None));
            }
            // The challenge asked for instrumentation; a result without a
            // probe would skip detection entirely, so refuse it.
            let Some(captured) = v2::capture_instr(&meta, instr) else {
                st.metrics
                    .incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "instr_probe_missing", "instr_error": true})),
                )
                    .into_response();
            };

            // Honeypot: a filled hidden field is a decisive bot signal.
            if payload
                .get("integrity")
                .and_then(|i| i.get("filled"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                sigs.push(cap_detect::Signal::gating("honeypot_triggered"));
            }
            {
                let opts = cap_detect::DetectOpts {
                    font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
                    optional_fields: &captured.optional_fields,
                    accept_language: None,
                };
                let outcome = cap_detect::detect_automation(&captured.p, &opts);
                sigs.extend(outcome.signals.iter().map(|s| s.as_signal()));
                let trust =
                    cap_detect::compute_trust_signals(&sigs, net.as_ref(), Some(outcome.pass));
                let action = cap_detect::trust_action(&trust);
                v2_trust = Some((trust, action));
                judged = true;
            }
        }
        // No instrumentation to judge (or none installed): the protocol-layer
        // findings still produce a verdict on their own.
        if !judged
            && let Some(net) = net.as_ref()
        {
            let trust = cap_detect::compute_trust_signals(&[], Some(net), None);
            let action = cap_detect::trust_action(&trust);
            v2_trust = Some((trust, action));
        }
    }
    if is_v2 {
        let Some(ev) = claims.get("ev").and_then(Value::as_str) else {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        };
        let Some(expected) = v2::decrypt_gcm(ev, &key.jwt_secret, v2::INFO_FMT2) else {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        };
        // Instrumentation outcomes the widget reports explicitly.
        let blocked_flag = payload
            .get("instr_blocked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let timeout_flag = payload
            .get("instr_timeout")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let instr_meta = v2::expected_entries(&expected)
            .ok()
            .and_then(|list| {
                list.iter()
                    .find(|c| c.get("protocol").and_then(Value::as_str) == Some("instrumentation"))
            })
            .and_then(|c| c.get("instrMeta"));
        if let Some(meta) = instr_meta
            && let Some(sealed_exp) = meta.get("expires").and_then(Value::as_i64)
            && sealed_exp <= now
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "instr_expired"})),
            )
                .into_response();
        }
        if blocked_flag {
            let automated = instr_meta
                .and_then(|m| m.get("blockAutomatedBrowsers"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": if automated { "instr_automated_browser" } else { "instr_failed" },
                    "instr_error": true,
                })),
            )
                .into_response();
        }
        if timeout_flag {
            st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "instr_timeout", "instr_error": true})),
            )
                .into_response();
        }

        // Verify first: the probe payload is client-supplied, so running the
        // detector on unverified input only spends CPU for a request that is
        // about to be rejected anyway.
        // hashwx verification runs the interpreter; keep it off the async
        // workers so a redeem flood cannot starve unrelated endpoints.
        let expected_c = expected.clone();
        let sols_c = solutions_raw.clone();
        let verdict = match cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::General, move || {
            v2::verify_solutions_observation(&expected_c, &sols_c)
        }).await {
            Ok(verdict) => verdict,
            Err(error) => return crate::cpu_error_response(error),
        };
        let verified = match verdict {
            Ok(verified) => verified,
            Err(reason) => {
                st.metrics
                    .incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "Invalid solution", "reason": reason})),
                ).into_response();
            }
        };

        // Run the probe detector on the captured instrumentation payload and
        // remember the verdict; the deny decision is enforced after the nonce
        // has been consumed. A challenge that asked for instrumentation must
        // come back with a probe: omitting it would otherwise skip detection
        // entirely.
        let captured = v2::take_probe(&expected, &solutions_raw);
        if captured.is_none() && instr_meta.is_some() {
            st.metrics
                .incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "instr_probe_missing", "instr_error": true})),
            )
                .into_response();
        }
        if captured.is_none() && net.is_some() {
            let trust = cap_detect::compute_trust_signals(&[], net.as_ref(), None);
            let action = cap_detect::trust_action(&trust);
            v2_trust = Some((trust, action));
        }
        if let Some(cap) = captured {
            if training_enabled && verified.mac_verified {
                training_client = Some(crate::training_capture::extract(&cap.p, None));
            }
            let accept_language = header_str(&headers, "accept-language");
            let primary_lang = accept_language
                .split(',')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let opts = cap_detect::DetectOpts {
                font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
                optional_fields: &cap.optional_fields,
                accept_language: primary_lang,
            };
            let outcome = cap_detect::detect_automation(&cap.p, &opts);
            let owned = outcome.signals.clone();
            let mut sigs: Vec<cap_detect::Signal> =
                owned.iter().map(|s| s.as_signal()).collect();
            // Same decisive signal as v1: a filled honeypot field.
            if payload
                .get("integrity")
                .and_then(|i| i.get("filled"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                sigs.push(cap_detect::Signal::gating("honeypot_triggered"));
            }
            let trust = cap_detect::compute_trust_signals(&sigs, net.as_ref(), Some(outcome.pass));
            let action = cap_detect::trust_action(&trust);
            v2_trust = Some((trust, action));
        }
    }

    let Some(sig) = jwt_sig_hex(token) else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
    };
    // Admission and verification may outlive the challenge. Never consume a
    // nonce using the timestamp taken before waiting for CPU capacity.
    let Some(nonce_ttl) = remaining_nonce_ttl(exp, now_ms()) else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "expired"}))).into_response();
    };
    if business.validate_at(now_ms()).is_err() {
        return crate::business::failure(StatusCode::BAD_REQUEST, "business_expired");
    }
    let denied = v2_trust.as_ref().is_some_and(|(_, action)| matches!(action, cap_detect::Action::Deny)) && key.config.block_on_deny;
    let redeem_token = format!("{site_key}:{}:{}", random_hex(8), random_hex(15));
    let ua = header_str(&headers, "user-agent");
    let mut bind = SessionBind::new(if ip.is_empty() { None } else { Some(ip) }, &ua, now);
    bind.host = parent.as_deref().and_then(cap_embed::origin_hostname);
    let token_expires = if denied {
        // Preserve existing deny replay policy: burn only challenge, never solve business.
        match st.store.consume_nonce(&sig, nonce_ttl).await {
            Ok(true) => {},
            Ok(false) => return crate::business::failure(StatusCode::FORBIDDEN, "Challenge already redeemed"),
            Err(_) => return crate::business::failure(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable"),
        }
        0
    } else {
        #[cfg(test)]
        interleaving_tests::checkpoint("before_commit").await;
        match st.store.complete_business(&business, credential, cap_store::CompleteBusiness {
            challenge_nonce: &sig, challenge_expires_ms: exp,
            token: &redeem_token, bind_json: &bind.to_json(), token_ttl_ms: TOKEN_TTL_MS,
        }).await {
            Ok(expires) => expires,
            Err(error) => return crate::business::store_failure(error),
        }
    };
    #[cfg(test)]
    interleaving_tests::checkpoint("after_commit").await;
    let nonce_consumed = true;

    // This point is reachable only after successful atomic nonce consumption.
    // training_client can exist only when MAC verification actually succeeded.
    let mut training_sample = if crate::training_capture::eligible(
        training_enabled, training_client.is_some(), nonce_consumed,
    ) {
        training_client.zip(v2_trust.as_ref()).map(|(client, (trust, action))| {
            crate::training_capture::sample(client, net.as_ref(), trust, *action,
                key.config.block_on_deny, training_started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                if is_v2 { crate::training::Protocol::V2 } else { crate::training::Protocol::V1 })
        })
    } else { None };

    if let Some((trust, action)) = &v2_trust {
        eprintln!(
            "[redeem] site={site_key} trust score={} level={:?} action={action:?}",
            trust.score, trust.level
        );
        if matches!(action, cap_detect::Action::Deny) && key.config.block_on_deny {
            if let (Some(service), Some(sample)) = (st.training.as_ref(), training_sample.take()) {
                let _ = service.try_record(&site_key, sample);
            }
            st.metrics.incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
            let mut doc = json!({ "success": false, "error": "trust_denied" });
            if st.admin_cfg.demo {
                doc["trust"] = trust_json(trust);
                doc["action"] = json!(action_str(*action));
            }
            return (StatusCode::FORBIDDEN, Json(doc)).into_response();
        }
    }

    // complete_business above committed the result and challenge atomically.
    // An allowed policy decision is recorded only after issue succeeds. Thus an
    // issue-store failure never masquerades as successful redemption. This is
    // still an observation, not evidence of a later siteverify or of humanity.
    if let (Some(service), Some(sample)) = (st.training.as_ref(), training_sample.take()) {
        let _ = service.try_record(&site_key, sample);
    }
    let _ = st.kv.del(&crate::integrity::chalenv_key(token)).await;
    eprintln!("[redeem] site={site_key} issued token (verified)");
    st.metrics
        .incr(
            &format!("metrics:verified:{site_key}"),
            &hourly_bucket(now).to_string(),
            1,
        );

    record_geo(&st, &site_key, &headers, &addr).await;

    // Detection details are a probe oracle: only the demo mode exposes them.
    let demo = st.admin_cfg.demo;
    if demo
        && let Some((trust, action)) = &v2_trust
    {
        let _ = st
            .kv
            .set_ex(
                &format!("demo:last-trust:{site_key}"),
                &json!({ "trust": trust_json(trust), "action": action_str(*action) })
                    .to_string(),
                120,
            )
            .await;
    }
    let mut doc = json!({
        "success": true,
        "token": redeem_token,
        "expires": token_expires,
        "scope": site_key,
    });
    // Detection details are a probe oracle: the fields do not exist at all
    // outside demo mode.
    if demo
        && let Some((trust, action)) = &v2_trust
    {
        doc["trust"] = trust_json(trust);
        doc["action"] = json!(action_str(*action));
    }
    Json(doc).into_response()
}

// Configuration only permits initially unbound challenges; it never removes
// an existing binding when enforcement is disabled or the allowlist is cleared.
fn session_matches(bound: Option<&str>, sent: Option<&str>, require_bound: bool) -> bool {
    match bound {
        Some(sid) => sent == Some(sid),
        None => !require_bound,
    }
}

#[cfg(test)]
#[path = "redeem_interleaving_tests.rs"]
mod interleaving_tests;


fn remaining_nonce_ttl(exp: i64, now: i64) -> Option<i64> {
    exp.checked_sub(now).filter(|ttl| *ttl > 0)
}

fn verify_v1_pow(token: &str, claims: &Value, raw: &[Value]) -> Result<(), &'static str> {
    let solutions: Vec<u64> = raw.iter().map(|v| v.as_u64().ok_or("invalid_solutions"))
        .collect::<Result<_, _>>()?;
    let params = PowParams {
        c: claims.get("c").and_then(Value::as_u64).unwrap_or(0) as u32,
        s: claims.get("s").and_then(Value::as_u64).unwrap_or(0) as u32,
        d: claims.get("d").and_then(Value::as_u64).unwrap_or(0) as u32,
    };
    if !params.valid() {
        return Err("invalid_token");
    }
    if !verify_pow(token, params, &solutions) {
        return Err("Invalid solution");
    }
    Ok(())
}

/// Trust result in the shape the dashboard/test page expects
/// (`{score, level, reasons, gatingFailure}`), with the JS level names.
pub(crate) fn trust_json(trust: &cap_detect::Trust) -> Value {
    let level = match trust.level {
        cap_detect::Level::Clean => "trusted",
        cap_detect::Level::Restricted => {
            // trust.js:levelFor splits neutral/suspicious at 55.
            if trust.score >= 55 {
                "neutral"
            } else {
                "suspicious"
            }
        }
        cap_detect::Level::Hostile => "hostile",
    };
    json!({
        "score": trust.score,
        "level": level,
        "reasons": trust.reasons,
        "gatingFailure": trust.gating_failure,
    })
}

pub(crate) fn action_str(action: cap_detect::Action) -> &'static str {
    match action {
        cap_detect::Action::Allow => "allow",
        cap_detect::Action::Deny => "deny",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rejects_ambiguous_or_oversized_redeem_json() {
        for field in ["token", "businessToken", "businessBinding", "solutions", "context"] {
            let body = format!(r#"{{"{field}":"a","{field}":"b"}}"#);
            assert!(super::parse_redeem_body(body.as_bytes()).is_err());
        }
        for body in [b"[]".as_slice(), b"{}{}", b"{\"a\":\"\xff\"}"] {
            assert!(super::parse_redeem_body(body).is_err());
        }
        assert!(super::parse_redeem_body(&vec![b' '; 1024 * 1024 + 1]).is_err());
        assert!(super::parse_redeem_body(br#"{"businessToken":"abc","solutions":[]}"#).is_ok());
    }
    #[test]
    fn recursively_rejects_duplicates_even_when_last_value_is_valid() {
        for body in [
            r#"{"solutions":[{"nonce":null,"nonce":42}]}"#,
            r#"{"solutions":[{"instr":{"mac":null,"mac":"valid"}}]}"#,
            r#"{"instr":{"p":{"webdriver":true,"webdriver":false}}}"#,
            r#"{"solutions":[[{"x":0,"x":1}]]}"#,
            r#"{"context":{"nested":{"a":null,"\u0061":true}}}"#,
        ] {
            // The old Value parser would silently retain the final value.
            assert!(serde_json::from_str::<serde_json::Value>(body).is_ok());
            assert!(super::parse_redeem_body(body.as_bytes()).is_err(), "{body}");
        }
        let valid = br#"{"solutions":[{"n":42,"instr":{"p":[true,false,null,-1,1.25,"text",{"x":1}]}}]}"#;
        assert_eq!(super::parse_redeem_body(valid).unwrap(), serde_json::from_slice::<serde_json::Value>(valid).unwrap());
        let deep = format!("{{\"x\":{}0{}}}", "[".repeat(130), "]".repeat(130));
        assert!(super::parse_redeem_body(deep.as_bytes()).is_err());
        let shallow = format!("{{\"x\":{}0{}}}", "[".repeat(16), "]".repeat(16));
        assert!(super::parse_redeem_body(shallow.as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn expiry_is_rechecked_after_cpu_wait_before_consumption() {
        use cap_kv::cpu::{CpuClass, CpuConfig, CpuScheduler};
        use std::{future::Future, sync::Arc, task::Poll};
        let scheduler = Arc::new(CpuScheduler::new(CpuConfig {
            total: 1, argon: 1, waiters: 1, ..Default::default()
        }).unwrap());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_scheduler = scheduler.clone();
        let running = tokio::spawn(async move {
            worker_scheduler.run(CpuClass::General, move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            }).await.unwrap();
        });
        started_rx.await.unwrap();
        let exp = 200;
        assert_eq!(super::remaining_nonce_ttl(exp, 100), Some(100));
        let mut queued = Box::pin(scheduler.run(CpuClass::General, || true));
        std::future::poll_fn(|cx| {
            assert!(queued.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        }).await;
        // Advance the injected wall clock while the real CPU admission waits.
        let after_queue = 200;
        release_tx.send(()).unwrap();
        assert!(queued.await.unwrap()); // valid proof stays valid
        assert_eq!(super::remaining_nonce_ttl(exp, after_queue), None);
        assert_eq!(super::remaining_nonce_ttl(exp, 201), None);
        running.await.unwrap();
    }

    use super::session_matches;

    #[test]
    fn existing_sid_binding_survives_configuration_changes() {
        for require_bound in [false, true] {
            assert!(session_matches(Some("original"), Some("original"), require_bound));
            assert!(!session_matches(Some("original"), Some("other"), require_bound));
            assert!(!session_matches(Some("original"), None, require_bound));
        }
        for sent in [None, Some("new")] {
            assert!(session_matches(None, sent, false));
            assert!(!session_matches(None, sent, true));
        }
    }
}
