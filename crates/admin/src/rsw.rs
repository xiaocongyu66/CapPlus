//! `/settings/rsw` and `/settings/rsw/ensure` — the RSW time-lock keypair the
//! `rsw` challenge protocol signs against.
//!
//! The JS server keeps it in `settings:rsw_keypair`; this port uses the same
//! hash and generates the pair through `cap_proto`.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::{AdminStore, internal, ok, resp};

const KEYPAIR: &str = "settings:rsw_keypair";
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn status_doc(exists: bool, fields: &HashMap<String, String>) -> Value {
    json!({
        "success": true,
        "exists": exists,
        "bits": fields.get("bits").and_then(|b| b.parse::<u32>().ok()),
        "created": fields.get("created").and_then(|b| b.parse::<i64>().ok()),
    })
}

pub(crate) async fn status(store: &AdminStore) -> crate::AdminResponse {
    match store.hgetall(KEYPAIR).await {
        Ok(fields) => ok(status_doc(!fields.is_empty(), &fields)),
        Err(_) => internal(),
    }
}

/// `POST /settings/rsw/ensure` — generate the pair when it is missing.
pub(crate) async fn ensure(store: &AdminStore) -> crate::AdminResponse {
    ensure_with(store, || cap_proto::generate_keypair(2048)).await
}

async fn ensure_with<F>(store: &AdminStore, generate: F) -> crate::AdminResponse
where F: FnOnce() -> cap_proto::RswKeypair + Send + 'static {
    // Process-local single flight, not a distributed lock. Move ownership to
    // a detached task so request cancellation cannot unlock running keygen.
    let guard = match LOCK.try_lock() {
        Ok(guard) => guard,
        Err(_) => return resp(503, json!({"success": false, "error": "rsw generation busy"})),
    };
    let store = store.clone();
    match tokio::spawn(async move {
        let _guard = guard;
        ensure_locked(&store, generate).await
    }).await {
        Ok(response) => response,
        Err(_) => internal(),
    }
}

async fn ensure_locked<F>(store: &AdminStore, generate: F) -> crate::AdminResponse
where F: FnOnce() -> cap_proto::RswKeypair + Send + 'static {
    match store.hgetall(KEYPAIR).await {
        Ok(fields) if !fields.is_empty() => return ok(status_doc(true, &fields)),
        Ok(_) => {},
        Err(_) => return internal(),
    }
    let pair = match cap_kv::cpu::run_cpu(cap_kv::cpu::CpuClass::General,
        generate).await {
        Ok(kp) => kp,
        Err(error) => return crate::util::argon2_error_response(crate::util::ArgonError::Cpu(error)),
    };

    let pairs = [
        ("N", pair.n.to_str_radix(10)),
        ("p", pair.p.to_str_radix(10)),
        ("q", pair.q.to_str_radix(10)),
        ("bits", pair.bits.to_string()),
        ("created", crate::util::now_ms().to_string()),
    ];
    // Existing atomic create prevents overwriting a server-generated pair or
    // configuration published while we computed. The index is bookkeeping only.
    if store.hcreate_indexed(KEYPAIR, &pairs, "settings:generated-keypairs", KEYPAIR).await.is_err() {
        return internal();
    }
    match store.hgetall(KEYPAIR).await {
        Ok(fields) if !fields.is_empty() => ok(status_doc(true, &fields)),
        _ => internal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires matching explicit isolated Redis URLs"]
    async fn cancellation_keeps_singleflight_and_publication_does_not_overwrite() {
        let url = std::env::var("CAP_TEST_REDIS_URL").unwrap();
        assert!(!url.is_empty());
        assert_eq!(std::env::var("REDIS_URL").unwrap(), url);
        let store = AdminStore::connect(&url).await.unwrap();
        cap_kv::cpu::init(cap_kv::cpu::CpuConfig::default()).unwrap();
        assert!(!store.exists(KEYPAIR).await.unwrap());
        // Wrong-type reads are failures, not an invitation to generate.
        store.set(KEYPAIR, "wrong-type").await.unwrap();
        assert_eq!(ensure_with(&store, || panic!("must not generate")).await.status, 500);
        store.del(KEYPAIR).await.unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task_store = store.clone();
        let request = tokio::spawn(async move {
            ensure_with(&task_store, move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                cap_proto::generate_keypair(64) // test fixture only
            }).await
        });
        started_rx.await.unwrap();
        request.abort();
        let _ = request.await;
        let duplicate = ensure_with(&store, || panic!("duplicate generation")).await;
        // Simulate server publication while the original computation is live.
        store.hset_pairs(KEYPAIR, &[("N", "newer".into()), ("bits", "2048".into())]).await.unwrap();
        release_tx.send(()).unwrap();
        let _finished = LOCK.lock().await;
        assert_eq!(duplicate.status, 503);
        assert_eq!(store.hget(KEYPAIR, "N").await.unwrap().as_deref(), Some("newer"));
        assert!(store.hget(KEYPAIR, "p").await.unwrap().is_none());
        store.del(KEYPAIR).await.unwrap();
    }
}
