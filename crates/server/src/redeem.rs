//! `POST /:siteKey/redeem`: verify the proof, consume the challenge, issue the
//! verification token and compute the trust verdict.

use super::*;

pub(crate) async fn redeem(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(site_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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

    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_body"}))).into_response();
    };
    let token = payload.get("token").and_then(Value::as_str).unwrap_or("");
    if token.is_empty() {
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

    let key = match st.cache.key(&st.store, &site_key).await {
        Some(k) => Arc::unwrap_or_clone(k),
        None => {
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
    if claims.get("sk").and_then(Value::as_str) != Some(site_key.as_str()) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "scope_mismatch"}))).into_response();
    }
    if let Err(reason) =
        check_challenge_env(&st, token, &headers, &addr, key.config.require_session_bind).await
    {
        let _ = st
            .kv
            .hincrby(
                &format!("metrics:failed:{site_key}"),
                &hourly_bucket(now_ms()).to_string(),
                1,
            )
            .await;
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": reason }))).into_response();
    }
    if let Err(reason) = check_integrity(&claims, &payload, &key.jwt_secret) {
        let _ = st
            .kv
            .hincrby(
                &format!("metrics:failed:{site_key}"),
                &hourly_bucket(now_ms()).to_string(),
                1,
            )
            .await;
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
    let mut v2_trust: Option<(cap_detect::Trust, cap_detect::Action)> = None;
    if !is_v2 {
        // v1 carries its instrumentation meta sealed in `ei`. Without it an
        // automated client on the old protocol would never be fingerprinted.
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
            if let Err(reason) = v2::verify_instr(&meta, instr) {
                return (StatusCode::FORBIDDEN, Json(json!({"error": reason}))).into_response();
            }

            let mut sigs: Vec<cap_detect::Signal> = Vec::new();
            // Honeypot: a filled hidden field is a decisive bot signal.
            if payload
                .get("integrity")
                .and_then(|i| i.get("filled"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                sigs.push(cap_detect::Signal::gating("honeypot_triggered"));
            }
            if let Some(p) = instr.get("p") {
                let optional: Vec<String> = meta
                    .get("extendedFields")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                let opts = cap_detect::DetectOpts {
                    font_stack_count: Some(cap_detect::PROBE_FONT_STACK_COUNT),
                    optional_fields: &optional,
                    accept_language: None,
                };
                let outcome = cap_detect::detect_automation(p, &opts);
                sigs.extend(outcome.signals.iter().map(|s| s.as_signal()));
                let trust = cap_detect::compute_trust_signals(&sigs, None, Some(outcome.pass));
                let action = cap_detect::trust_action(&trust);
                v2_trust = Some((trust, action));
            } else if !sigs.is_empty() {
                let trust = cap_detect::compute_trust_signals(&sigs, None, None);
                let action = cap_detect::trust_action(&trust);
                v2_trust = Some((trust, action));
            }
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
        let instr_meta = expected
            .as_array()
            .and_then(|list| {
                list.iter()
                    .find(|c| c.get("protocol").and_then(Value::as_str) == Some("instrumentation"))
            })
            .and_then(|c| c.get("instrMeta"));
        if let Some(meta) = instr_meta {
            if let Some(sealed_exp) = meta.get("expires").and_then(Value::as_i64) {
                if sealed_exp <= now {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "instr_expired"})),
                    )
                        .into_response();
                }
            }
        }
        if blocked_flag {
            let automated = instr_meta
                .and_then(|m| m.get("blockAutomatedBrowsers"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let _ = st
                .kv
                .hincrby(
                    &format!("metrics:failed:{site_key}"),
                    &hourly_bucket(now).to_string(),
                    1,
                )
                .await;
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
            let _ = st
                .kv
                .hincrby(
                    &format!("metrics:failed:{site_key}"),
                    &hourly_bucket(now).to_string(),
                    1,
                )
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "instr_timeout", "instr_error": true})),
            )
                .into_response();
        }

        // Run the probe detector on the captured instrumentation payload and
        // remember the verdict; the deny decision is enforced after the nonce
        // has been consumed (same ordering as the JS server).
        let captured = v2::take_probe(&expected, &solutions_raw);
        if captured.is_none() {
            eprintln!("[redeem] no probe captured (solutions={})", solutions_raw.len());
        }
        if let Some(cap) = captured {
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
            let sigs: Vec<cap_detect::Signal> =
                owned.iter().map(|s| s.as_signal()).collect();
            let trust = cap_detect::compute_trust_signals(&sigs, None, Some(outcome.pass));
            let action = cap_detect::trust_action(&trust);
            v2_trust = Some((trust, action));
        }
        // hashwx verification runs the interpreter; keep it off the async
        // workers so a redeem flood cannot starve unrelated endpoints.
        let expected_c = expected.clone();
        let sols_c = solutions_raw.clone();
        let verdict = tokio::task::spawn_blocking(move || {
            v2::verify_solutions(&expected_c, &sols_c)
        })
        .await
        .unwrap_or_else(|_| Err("verify_panicked".to_string()));
        if let Err(reason) = verdict {
            st.metrics
                .incr(&format!("metrics:failed:{site_key}"), &hourly_bucket(now).to_string(), 1);
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Invalid solution", "reason": reason})),
            )
                .into_response();
        }
    } else {
        let mut solutions = Vec::with_capacity(solutions_raw.len());
        for v in &solutions_raw {
            match v.as_u64() {
                Some(n) => solutions.push(n),
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "invalid_solutions"})),
                    )
                        .into_response()
                }
            }
        }
        let params = PowParams {
            c: claims.get("c").and_then(Value::as_u64).unwrap_or(0) as u32,
            s: claims.get("s").and_then(Value::as_u64).unwrap_or(0) as u32,
            d: claims.get("d").and_then(Value::as_u64).unwrap_or(0) as u32,
        };
        if !params.valid() {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
        }
        if !verify_pow(token, params, &solutions) {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), hourly_bucket(now))
                .await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Invalid solution"})),
            )
                .into_response();
        }
    }

    let Some(sig) = jwt_sig_hex(token) else {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "invalid_token"}))).into_response();
    };
    match st.store.consume_nonce(&sig, exp - now).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Challenge already redeemed"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("nonce_store_error: {e}")})),
            )
                .into_response()
        }
    }

    if let Some((trust, action)) = &v2_trust {
        eprintln!(
            "[redeem] site={site_key} trust score={} level={:?} action={action:?}",
            trust.score, trust.level
        );
        if matches!(action, cap_detect::Action::Deny) && key.config.block_on_deny {
            let _ = st
                .store
                .incr_metric(&format!("metrics:failed:{site_key}"), hourly_bucket(now))
                .await;
            let mut doc = json!({ "success": false, "error": "trust_denied" });
            if st.admin_cfg.demo {
                doc["trust"] = trust_json(trust);
                doc["action"] = json!(action_str(*action));
            }
            return (StatusCode::FORBIDDEN, Json(doc)).into_response();
        }
    }

    let redeem_token = format!("{site_key}:{}:{}", random_hex(8), random_hex(15));
    let ua = header_str(&headers, "user-agent");
    let ip = client_ip(&headers, &addr.ip().to_string());
    let bind = SessionBind::new(if ip.is_empty() { None } else { Some(ip) }, &ua, now);
    let token_expires = now + TOKEN_TTL_MS;
    if let Err(e) = st
        .store
        .issue(&redeem_token, &bind.to_json(), token_expires, TOKEN_TTL_MS)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("bind_failed: {e}")})),
        )
            .into_response();
    }
    let _ = st.kv.del(&format!("chalenv:{token}")).await;
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
    if demo {
        if let Some((trust, action)) = &v2_trust {
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
    }
    let mut doc = json!({
        "success": true,
        "token": redeem_token,
        "expires": token_expires,
        "scope": site_key,
    });
    // Detection details are a probe oracle: the fields do not exist at all
    // outside demo mode.
    if demo {
        if let Some((trust, action)) = &v2_trust {
            doc["trust"] = trust_json(trust);
            doc["action"] = json!(action_str(*action));
        }
    }
    Json(doc).into_response()
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
