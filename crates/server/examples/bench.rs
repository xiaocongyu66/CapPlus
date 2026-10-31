//! Minimal HTTP throughput bench: N keep-alive connections, fixed duration.
//!
//! ```text
//! cargo run --release -p cap-server --example bench -- <url> <concurrency> <seconds>
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let url = args.next().expect("usage: bench <url> [concurrency] [seconds]");
    let conc: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(64);
    let secs: u64 = args.next().and_then(|v| v.parse().ok()).unwrap_or(5);
    let method = if std::env::var("BENCH_GET").is_ok() { Method::GET } else { Method::POST };

    let uri: hyper::Uri = url.parse().expect("url");
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let ok = Arc::new(AtomicU64::new(0));
    let err = Arc::new(AtomicU64::new(0));
    let lat = Arc::new(std::sync::Mutex::new(Vec::<u128>::new()));
    let deadline = Instant::now() + Duration::from_secs(secs);

    let mut tasks = Vec::new();
    for _ in 0..conc {
        let client = client.clone();
        let uri = uri.clone();
        let ok = ok.clone();
        let err = err.clone();
        let lat = lat.clone();
        let method = method.clone();
        tasks.push(tokio::spawn(async move {
            let mut local = Vec::new();
            while Instant::now() < deadline {
                let req = Request::builder()
                    .method(method.clone())
                    .uri(uri.clone())
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "10.1.1.1")
                    .body(Empty::new())
                    .unwrap();
                let t0 = Instant::now();
                match client.request(req).await {
                    Ok(resp) => {
                        let status = resp.status();
                        let _ = resp.into_body().collect().await;
                        if status.is_success() {
                            ok.fetch_add(1, Ordering::Relaxed);
                        } else {
                            err.fetch_add(1, Ordering::Relaxed);
                        }
                        local.push(t0.elapsed().as_micros());
                    }
                    Err(_) => {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            lat.lock().unwrap().extend(local);
        }));
    }
    for t in tasks {
        let _ = t.await;
    }

    let total = ok.load(Ordering::Relaxed);
    let errors = err.load(Ordering::Relaxed);
    let mut v = lat.lock().unwrap().clone();
    v.sort_unstable();
    let pct = |p: f64| -> f64 {
        if v.is_empty() {
            0.0
        } else {
            v[((v.len() as f64 * p) as usize).min(v.len() - 1)] as f64 / 1000.0
        }
    };
    println!(
        "rps={:.0} ok={} err={} p50={:.2}ms p95={:.2}ms p99={:.2}ms",
        total as f64 / secs as f64,
        total,
        errors,
        pct(0.5),
        pct(0.95),
        pct(0.99)
    );
}
