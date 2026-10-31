//! `/settings/rsw` and `/settings/rsw/ensure` — the RSW time-lock keypair the
//! `rsw` challenge protocol signs against.
//!
//! The JS server keeps it in `settings:rsw_keypair`; this port uses the same
//! hash and generates the pair through `cap_proto`.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::{AdminStore, internal, ok, resp};

const KEYPAIR: &str = "settings:rsw_keypair";

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
    if let Ok(fields) = store.hgetall(KEYPAIR).await {
        if !fields.is_empty() {
            return ok(status_doc(true, &fields));
        }
    }

    // Keygen is CPU-bound; keep it off the async worker.
    let pair = match tokio::task::spawn_blocking(|| cap_proto::generate_keypair(2048)).await {
        Ok(kp) => kp,
        Err(_) => {
            return resp(
                500,
                json!({ "success": false, "error": "rsw keypair generation failed" }),
            )
        }
    };

    let pairs = [
        ("N", pair.n.to_str_radix(10)),
        ("p", pair.p.to_str_radix(10)),
        ("q", pair.q.to_str_radix(10)),
        ("bits", pair.bits.to_string()),
        ("created", crate::util::now_ms().to_string()),
    ];
    if store.hset_pairs(KEYPAIR, &pairs).await.is_err() {
        return internal();
    }
    match store.hgetall(KEYPAIR).await {
        Ok(fields) => ok(status_doc(true, &fields)),
        Err(_) => internal(),
    }
}
