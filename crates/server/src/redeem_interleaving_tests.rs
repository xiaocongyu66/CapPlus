//! Deterministic handler-future cancellation, not a claim about TCP disconnects
//! or humanity. Signed legacy PoW fixture uses unchanged KeyConfig defaults.
use super::*;
use cap_kv::cpu::{CpuClass, CpuConfig, CpuError, CpuScheduler};
use std::{future::Future, task::Poll, time::Duration};
use tokio::sync::{mpsc, oneshot};

const BOUND: Duration = Duration::from_secs(45);
struct Control {
    scheduler: Arc<CpuScheduler>,
    events: mpsc::UnboundedSender<&'static str>,
    stage: &'static str,
    release: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    worker: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
tokio::task_local! { static CONTROL: Arc<Control>; }

pub(super) async fn checkpoint(stage: &'static str) {
    let Ok(control) = CONTROL.try_with(Arc::clone) else {
        return;
    };
    control.events.send(stage).unwrap();
    if control.stage == stage {
        let rx = control.release.lock().unwrap().take().unwrap();
        tokio::time::timeout(BOUND, rx).await.unwrap().unwrap();
    }
}
pub(super) async fn run<F, T>(work: F) -> Result<T, CpuError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let Ok(control) = CONTROL.try_with(Arc::clone) else {
        return cap_kv::cpu::run_cpu(CpuClass::General, work).await;
    };
    let c = control.clone();
    let mut future = Box::pin(control.scheduler.run(CpuClass::General, move || {
        let result = work(); // execute real proof verification inside the permit
        c.events.send("running").unwrap();
        if let Some(rx) = c.worker.lock().unwrap().take() {
            rx.recv_timeout(BOUND).unwrap();
        }
        result
    }));
    // The test holds all capacity: Pending here proves actual admission wait,
    // rather than a hook placed before the scheduler was polled.
    if let Some(result) = std::future::poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Pending => {
            control.events.send("pending").unwrap();
            Poll::Ready(None)
        }
        Poll::Ready(result) => Poll::Ready(Some(result)),
    })
    .await
    {
        return result;
    }
    future.await
}

struct OwnedRedis {
    child: std::process::Child,
    root: std::path::PathBuf,
}
impl Drop for OwnedRedis {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
async fn setup() -> (OwnedRedis, AppState) {
    let url = std::env::var("CAP_REDEEM_TEST_REDIS_URL").expect("explicit owned Redis URL");
    for name in ["REDIS_URL", "CAP_TEST_REDIS_URL"] {
        assert_eq!(std::env::var(name).unwrap(), url);
    }
    let (port, db) = url
        .strip_prefix("redis://127.0.0.1:")
        .unwrap()
        .split_once('/')
        .unwrap();
    let port: u16 = port.parse().unwrap();
    assert!(port > 1024 && ![6379, 8401].contains(&port));
    assert_eq!(db, "15");
    let reservation = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let root = std::env::temp_dir().join(format!("cap-redeem-{}", random_hex(24)));
    std::fs::create_dir(&root).unwrap();
    let password = random_hex(48);
    drop(reservation);
    let child = std::process::Command::new("redis-server")
        .args([
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--save",
            "",
            "--appendonly",
            "no",
            "--requirepass",
            &password,
        ])
        .arg("--dir")
        .arg(&root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut owned = OwnedRedis {
        child,
        root: root.clone(),
    };
    let private = format!("redis://:{password}@127.0.0.1:{port}/15");
    let kv = tokio::time::timeout(BOUND, async {
        loop {
            assert!(owned.child.try_wait().unwrap().is_none());
            if let Ok(kv) = cap_kv::Kv::connect_redis(&private).await {
                break kv;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    crate::SETTINGS
        .set(crate::config::Settings {
            data_dir: root.clone(),
            hostname: "127.0.0.1".into(),
            demo_allowed_domains: None,
            port: 0,
            ip_header: String::new(),
            rsw_bits: 2048,
            admin_key: String::new(),
            demo: false,
            redis_url: private,
            dashboard_dir: None,
            cdn_fallback: false,
            embed_widget_url: String::new(),
            trust_proxy: false,
            proxy_secret: String::new(),
            require_network_fingerprint: false,
            trusted_proxy_cidrs: vec![],
            trusted_peer_cidrs: vec![],
            require_verify_session: false,
        })
        .expect("run separately from other global settings tests");
    let st = AppState {
        store: cap_store::Store::new(kv.clone()),
        kv,
        embed_widget_url: String::new(),
        admin: None,
        admin_cfg: Arc::new(cap_admin::AdminConfig {
            admin_key: String::new(),
            demo: false,
        }),
        releases: Arc::new(cap_assets::ReleaseStore::open(&root).unwrap()),
        ipdb: Arc::new(cap_ipdb::IpDb::open(&root.join("ipdb"), &root.join("tmp")).unwrap()),
        cache: Arc::new(crate::cache::ConfigCache::new()),
        limiter: Arc::new(crate::ratelimit::LocalLimiter::new()),
        metrics: Arc::new(crate::metrics_buf::MetricsBuffer::new()),
        training: None,
        redis_ratelimit: false,
        rsw_minters: moka::future::Cache::new(32),
        rsw_keygen: Default::default(),
    };
    (owned, st)
}
struct Fixture {
    body: Bytes,
    headers: HeaderMap,
    token: String,
    business: cap_core::business::BusinessClaims,
    credential: String,
}
const SITE: &str = "a1b2c3d4e5";
const SECRET: &str = "redeem-test-secret-not-production";
fn address() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}
async fn fixture(st: &AppState) -> Fixture {
    fixture_ttl(st, None).await
}
async fn fixture_ttl(st: &AppState, ttl: Option<i64>) -> Fixture {
    let config = cap_store::KeyConfig::default();
    st.kv
        .hset_pairs(&format!("key:{SITE}"), &[("jwtSecret", SECRET.into())])
        .await
        .unwrap();
    let now = now_ms();
    let binding = cap_core::business::BusinessBinding {
        site: SITE.into(),
        session: "fixture-session".into(),
        action: "test".into(),
        nonce: random_hex(32),
        request_digest: cap_core::sha256_hex("fixture-body"),
    };
    let credential = cap_core::business::sign_business_token(binding, SECRET, now, ttl).unwrap();
    let business = cap_core::business::verify_business_token(&credential, SECRET, now).unwrap();
    st.store
        .issue_business(&business, &credential)
        .await
        .unwrap();
    let claims = json!({"typ":"chal", "sk":SITE, "exp":now + CHALLENGE_TTL_MS,
        "businessHash":cap_core::sha256_hex(&credential), "businessBinding":business.binding,
        "c":config.challenge_count, "s":config.salt_size, "d":config.difficulty});
    let token = cap_core::jwt_sign(&claims, SECRET);
    // OpenSSL-backed hashlib avoids debug Rust hex-formatting dominating the
    // real credential lifetime. All default 80/d4 proofs are still verified by
    // the unchanged Rust verifier; no reduced difficulty or extended token TTL.
    let challenges: Vec<_> = (1..=config.challenge_count)
        .map(|i| {
            (
                cap_core::prng(&format!("{token}{i}"), config.salt_size as usize),
                cap_core::prng(&format!("{token}{i}d"), config.difficulty as usize),
            )
        })
        .collect();
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import hashlib,json,sys,time
out=[]
end=time.monotonic()+25
for salt,target in json.loads(sys.argv[1]):
    n=0
    while not hashlib.sha256((salt+str(n)).encode()).hexdigest().startswith(target):
        n+=1
        if n%10000==0 and time.monotonic()>end: raise TimeoutError('fixture solving deadline')
    out.append(n)
print(json.dumps(out))
"#,
            &serde_json::to_string(&challenges).unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let solutions: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        now_ms() < business.exp,
        "fixture must be live before admission"
    );
    assert_eq!(verify_v1_pow(&token, &claims, &solutions), Ok(()));
    let mut headers = HeaderMap::new();
    headers.insert("host", "fixture.test".parse().unwrap());
    headers.insert("origin", "https://fixture.test".parse().unwrap());
    crate::integrity::remember_challenge_env(st, &token, &headers, &address(), None)
        .await
        .unwrap();
    let body = Bytes::from(
        json!({"token":token, "businessToken":credential, "solutions":solutions}).to_string(),
    );
    Fixture {
        body,
        headers,
        token,
        business,
        credential,
    }
}
fn scheduler(waiters: usize) -> Arc<CpuScheduler> {
    Arc::new(
        CpuScheduler::new(CpuConfig {
            total: 1,
            argon: 1,
            waiters,
            wait_timeout: Duration::from_millis(100),
        })
        .unwrap(),
    )
}
async fn event(rx: &mut mpsc::UnboundedReceiver<&'static str>, expected: &str) {
    loop {
        let value = tokio::time::timeout(BOUND, rx.recv())
            .await
            .unwrap()
            .unwrap();
        if value == expected {
            return;
        }
        assert_eq!(value, "pending", "unexpected checkpoint before {expected}");
    }
}
fn launch(
    st: &AppState,
    f: &Fixture,
    s: Arc<CpuScheduler>,
    stage: &'static str,
    worker: bool,
) -> (
    tokio::task::JoinHandle<Response>,
    mpsc::UnboundedReceiver<&'static str>,
    oneshot::Sender<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (release, released) = oneshot::channel();
    let (work, worked) = std::sync::mpsc::channel();
    let c = Arc::new(Control {
        scheduler: s,
        events: tx,
        stage,
        release: std::sync::Mutex::new(Some(released)),
        worker: std::sync::Mutex::new(worker.then_some(worked)),
    });
    let (st, headers, body) = (st.clone(), f.headers.clone(), f.body.clone());
    let task = tokio::spawn(CONTROL.scope(c, async move {
        redeem(
            State(st),
            ConnectInfo(address()),
            Path(SITE.into()),
            headers,
            body,
        )
        .await
    }));
    (task, rx, release, work)
}
fn authority_key(f: &Fixture) -> String {
    let mut bytes = b"cap-business-key-v1\0".to_vec();
    for part in [
        f.business.binding.site.as_bytes(),
        f.business.binding.nonce.as_bytes(),
    ] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    format!("business:v1:{}", cap_core::sha256_hex(bytes))
}
fn redis_command(args: &[&str]) -> String {
    // URL is only the random-password child created by setup, never env/default.
    let private = settings().redis_url.strip_prefix("redis://:").unwrap();
    let (password, endpoint) = private.split_once('@').unwrap();
    let port = endpoint.strip_prefix("127.0.0.1:").unwrap().strip_suffix("/15").unwrap();
    let output = std::process::Command::new("redis-cli")
        .env("REDISCLI_AUTH", password)
        .env_remove("REDIS_URL")
        .args(["--no-auth-warning", "--raw", "-h", "127.0.0.1", "-p", port, "-n", "15"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = String::from_utf8(output.stdout).unwrap();
    assert!(!value.starts_with("ERR"), "{value}");
    value.trim().to_owned()
}
async fn no_commit(st: &AppState, f: &Fixture) {
    assert_eq!(
        st.kv
            .hget(&authority_key(f), "state")
            .await
            .unwrap()
            .as_deref(),
        Some("issued")
    );
    assert!(
        st.kv
            .hget(&authority_key(f), "result")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        redis_command(&[
            "EVAL",
            "return #redis.call('KEYS','business-result:v1:*')",
            "0"
        ]),
        "0"
    );
    assert!(
        !st.kv
            .exists(&format!("blocklist:{}", jwt_sig_hex(&f.token).unwrap()))
            .await
            .unwrap()
    );
}
async fn expire(f: &Fixture) {
    // Actual Redis TIME is the oracle. The timer targets that exact absolute
    // deadline; it is not a guessed delay used to establish an interleaving.
    let ttl: i64 = redis_command(&["PTTL", &authority_key(f)]).parse().unwrap();
    assert!((86_300_000..=86_400_000).contains(&ttl));
    tokio::time::timeout(BOUND, async {
        loop {
            let time = redis_command(&["TIME"]);
            let mut parts = time.lines().map(|s| s.parse::<i64>().unwrap());
            let now = parts.next().unwrap() * 1000 + parts.next().unwrap() / 1000;
            if now >= f.business.exp {
                break;
            }
            tokio::time::sleep_until(
                tokio::time::Instant::now() + Duration::from_millis((f.business.exp - now) as u64),
            )
            .await;
        }
    })
    .await
    .unwrap();
}
async fn untouched(st: &AppState, f: &Fixture) {
    no_commit(st, f).await;
    st.store
        .check_business(&f.business, &f.credential)
        .await
        .unwrap();
    assert!(
        !st.kv
            .exists(&format!("blocklist:{}", jwt_sig_hex(&f.token).unwrap()))
            .await
            .unwrap()
    );
    assert!(
        st.kv
            .exists(&crate::integrity::chalenv_key(&f.token))
            .await
            .unwrap()
    );
}
async fn blocker(
    s: Arc<CpuScheduler>,
) -> (tokio::task::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
    let (tx, rx) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        s.run(CpuClass::General, move || {
            tx.send(()).unwrap();
            released.recv_timeout(BOUND).unwrap();
        })
        .await
        .unwrap();
    });
    tokio::time::timeout(BOUND, rx).await.unwrap().unwrap();
    (task, release)
}
#[tokio::test]
#[ignore = "requires three explicit matching owned Redis URLs, DB15; run separately"]
async fn isolated_redeem_interleavings() {
    let (_owned, st) = setup().await;
    let f = fixture(&st).await;
    // Full queue: one proven waiter, then immediate Busy, then waiter timeout.
    let s = scheduler(1);
    let (blocked, release) = blocker(s.clone()).await;
    let (waiting, mut events, _gate, _work) = launch(&st, &f, s.clone(), "", false);
    event(&mut events, "pending").await;
    let (busy, mut busy_events, _gate2, _work2) = launch(&st, &f, s.clone(), "", false);
    assert_eq!(
        busy.await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        busy_events.try_recv().is_err(),
        "full queue must return Busy without waiting"
    );
    assert_eq!(
        waiting.await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        events.try_recv().is_err(),
        "timed-out waiter ran work or committed"
    );
    untouched(&st, &f).await;
    let (cancelled, mut events, _gate, _work) = launch(&st, &f, s.clone(), "", false);
    event(&mut events, "pending").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    untouched(&st, &f).await;
    release.send(()).unwrap();
    blocked.await.unwrap();

    // Running cancellation must retain capacity until the blocking worker exits.
    let s = scheduler(1);
    let (running, mut events, _gate, work) = launch(&st, &f, s.clone(), "", true);
    event(&mut events, "running").await;
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    let mut completion = Box::pin(s.run(CpuClass::General, || ()));
    std::future::poll_fn(|cx| {
        assert!(
            completion.as_mut().poll(cx).is_pending(),
            "cancel released running permit early"
        );
        Poll::Ready(())
    })
    .await;
    assert_eq!(s.run(CpuClass::General, || ()).await, Err(CpuError::Busy));
    untouched(&st, &f).await;
    work.send(()).unwrap();
    // Successful admission is the completion barrier, not elapsed time.
    assert_eq!(
        tokio::time::timeout(BOUND, completion).await.unwrap(),
        Ok(())
    );
    untouched(&st, &f).await;
    while let Ok(stage) = events.try_recv() {
        assert_eq!(stage, "pending");
    }

    let f = fixture(&st).await;
    let (before, mut events, _gate, _work) = launch(&st, &f, scheduler(1), "before_commit", false);
    event(&mut events, "running").await;
    event(&mut events, "before_commit").await;
    before.abort();
    assert!(before.await.unwrap_err().is_cancelled());
    untouched(&st, &f).await;

    // Credential and Redis check succeeded, then the real admission wait spans
    // business exp. Only scheduler timeout changes; token TTL is SHORTER.
    let expiring = fixture_ttl(&st, Some(30_000)).await;
    let s = Arc::new(
        CpuScheduler::new(CpuConfig {
            total: 1,
            argon: 1,
            waiters: 1,
            wait_timeout: Duration::from_secs(40),
        })
        .unwrap(),
    );
    let (blocked, release) = blocker(s.clone()).await;
    let (waiting, mut events, _gate, _work) = launch(&st, &expiring, s, "", false);
    event(&mut events, "pending").await;
    assert!(now_ms() < expiring.business.exp);
    expire(&expiring).await;
    release.send(()).unwrap();
    blocked.await.unwrap();
    let response = waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let doc: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(doc["error"], "business_expired");
    event(&mut events, "running").await;
    assert!(events.try_recv().is_err(), "expired handler reached commit");
    no_commit(&st, &expiring).await;

    // Cross exp AFTER the handler's wall-clock recheck. Resuming executes the
    // actual complete_business Lua; Redis TIME, not the handler, must reject.
    let expiring = fixture_ttl(&st, Some(30_000)).await;
    let (waiting, mut events, gate, _work) =
        launch(&st, &expiring, scheduler(1), "before_commit", false);
    event(&mut events, "running").await;
    event(&mut events, "before_commit").await;
    assert!(now_ms() < expiring.business.exp);
    expire(&expiring).await;
    gate.send(()).unwrap();
    let response = waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let doc: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(doc["error"], "business_expired");
    assert!(
        events.try_recv().is_err(),
        "rejected Lua reached after_commit"
    );
    no_commit(&st, &expiring).await;

    let (after, mut events, _gate, _work) = launch(&st, &f, scheduler(1), "after_commit", false);
    event(&mut events, "running").await;
    event(&mut events, "before_commit").await;
    event(&mut events, "after_commit").await;
    after.abort();
    assert!(after.await.unwrap_err().is_cancelled());
    assert_eq!(
        st.kv
            .hget(&authority_key(&f), "state")
            .await
            .unwrap()
            .as_deref(),
        Some("solved")
    );
    let result = st
        .kv
        .hget(&authority_key(&f), "result")
        .await
        .unwrap()
        .unwrap();
    let committed = st
        .store
        .business_token_state(&f.business.binding, &result)
        .await
        .unwrap();
    assert_eq!(committed.expires_ms, f.business.exp);
    let ttl: i64 = redis_command(&["PTTL", &format!("business-result:v1:token:{result}")])
        .parse()
        .unwrap();
    assert!(ttl > 0 && ttl <= f.business.exp - now_ms() + 1000);
    assert!(matches!(
        st.store.check_business(&f.business, &f.credential).await,
        Err(cap_store::BusinessStoreError::Used)
    ));
    assert!(
        st.kv
            .exists(&format!("blocklist:{}", jwt_sig_hex(&f.token).unwrap()))
            .await
            .unwrap()
    );
}
