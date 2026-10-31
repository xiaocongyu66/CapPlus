use std::io::Read;
use std::time::Duration;

/// Hard cap on any fetched (or cached) asset body: 32MB.
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Per-request timeout for upstream fetches.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// HTTP fetcher backed by `ureq` with a 20s timeout and a 32MB body cap.
///
/// Never panics: network, status and body errors all come back as `Err`.
pub fn http_fetcher(url: &str) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new().timeout(FETCH_TIMEOUT).build();
    let resp = match agent.get(url).call() {
        Ok(resp) => resp,
        Err(ureq::Error::Status(code, _)) => {
            return Err(format!("{url} responded with {code}"));
        }
        Err(err) => return Err(format!("{url} request failed: {err}")),
    };
    read_capped(resp.into_reader()).map_err(|e| format!("{url}: {e}"))
}

/// Read at most `MAX_BODY_BYTES` from `reader`, failing if the body is larger.
///
/// We read one extra byte past the cap so we can distinguish "exactly at the
/// cap" (fine) from "over the cap" (rejected) without buffering the whole body.
pub fn read_capped<R: Read>(reader: R) -> Result<Vec<u8>, String> {
    let limit = MAX_BODY_BYTES as u64 + 1;
    let mut out = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| format!("read error: {e}"))?;
    if out.len() > MAX_BODY_BYTES {
        return Err(format!(
            "body exceeds the {MAX_BODY_BYTES} byte cap"
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_capped_accepts_small_body() {
        let body = read_capped(&b"hello"[..]).unwrap();
        assert_eq!(body, b"hello");
    }

    #[test]
    fn read_capped_accepts_body_exactly_at_cap() {
        let data = vec![0u8; MAX_BODY_BYTES];
        let body = read_capped(&data[..]).unwrap();
        assert_eq!(body.len(), MAX_BODY_BYTES);
    }

    #[test]
    fn read_capped_rejects_33mb_body_offline() {
        // No network: a synthetic in-memory reader standing in for a body.
        let data = vec![7u8; 33 * 1024 * 1024];
        let err = read_capped(&data[..]).unwrap_err();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn fetch_timeout_is_twenty_seconds() {
        assert_eq!(FETCH_TIMEOUT, Duration::from_secs(20));
        assert_eq!(MAX_BODY_BYTES, 32 * 1024 * 1024);
    }
}
