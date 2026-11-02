//! Process-wide bounded CPU admission. No I/O or algorithm dependencies.
use std::{
    cell::Cell,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuClass {
    General,
    Argon,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuError {
    Busy,
    Cancelled,
    Nested,
    WorkerFailed,
    NotInitialized,
}
impl std::fmt::Display for CpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CPU admission: {self:?}")
    }
}
impl std::error::Error for CpuError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuConfig {
    pub total: usize,
    pub argon: usize,
    pub waiters: usize,
    pub wait_timeout: Duration,
}
impl Default for CpuConfig {
    fn default() -> Self {
        Self {
            total: std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(4),
            argon: 1,
            waiters: 16,
            wait_timeout: Duration::from_millis(100),
        }
    }
}
impl CpuConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.total == 0
            || self.total > 256
            || self.argon == 0
            || self.argon > self.total
            || self.waiters > 65536
            || self.wait_timeout.is_zero()
            || self.wait_timeout > Duration::from_secs(60)
        {
            return Err("CPU config requires total=1..256, argon=1..total, waiters=0..65536, wait_ms=1..60000".into());
        }
        Ok(())
    }
    pub fn from_env() -> Result<Self, String> {
        let mut c = Self::default();
        fn value(name: &str, default: usize) -> Result<usize, String> {
            match std::env::var(name) {
                Ok(v) => v
                    .parse()
                    .map_err(|_| format!("invalid {name}: expected unsigned integer")),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(_) => Err(format!("invalid {name}: non-Unicode value")),
            }
        }
        c.total = value("CAP_CPU_TOTAL", c.total)?;
        c.argon = value("CAP_CPU_ARGON", c.argon)?;
        c.waiters = value("CAP_CPU_WAITERS", c.waiters)?;
        c.wait_timeout = Duration::from_millis(value("CAP_CPU_WAIT_MS", 100)? as u64);
        c.validate()?;
        Ok(c)
    }
}

static GLOBAL: OnceLock<CpuScheduler> = OnceLock::new();
/// Call during startup, before accepting requests. Invalid/repeated conflicting configuration fails.
pub fn init_from_env() -> Result<(), String> {
    init(CpuConfig::from_env()?)
}
pub fn init(config: CpuConfig) -> Result<(), String> {
    let scheduler = CpuScheduler::new(config.clone())?;
    match GLOBAL.set(scheduler) {
        Ok(()) => Ok(()),
        Err(_) if GLOBAL.get().unwrap().config == config => Ok(()),
        Err(_) => Err("CPU scheduler already initialized with different configuration".into()),
    }
}
pub async fn run_cpu<F, T>(class: CpuClass, work: F) -> Result<T, CpuError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    GLOBAL
        .get()
        .ok_or(CpuError::NotInitialized)?
        .run(class, work)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};
    fn scheduler(total: usize, waiters: usize) -> Arc<CpuScheduler> {
        Arc::new(
            CpuScheduler::new(CpuConfig {
                total,
                argon: 1,
                waiters,
                wait_timeout: Duration::from_millis(100),
            })
            .unwrap(),
        )
    }
    async fn pending<F: Future>(f: std::pin::Pin<&mut F>) {
        let mut f = f;
        std::future::poll_fn(|cx| {
            assert!(f.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    #[tokio::test(start_paused = true)]
    async fn queue_bound_timeout_and_cancel() {
        let s = scheduler(1, 1);
        let held = s.try_permits(CpuClass::General).unwrap();
        let mut queued = Box::pin(s.run(CpuClass::General, || 1));
        pending(queued.as_mut()).await;
        assert_eq!(s.waiting.available_permits(), 0);
        assert_eq!(s.run(CpuClass::General, || 2).await, Err(CpuError::Busy));
        drop(queued);
        assert_eq!(s.waiting.available_permits(), 1);
        let mut queued = Box::pin(s.run(CpuClass::General, || 3));
        pending(queued.as_mut()).await;
        tokio::time::advance(Duration::from_millis(101)).await;
        assert_eq!(queued.await, Err(CpuError::Busy));
        drop(held);
        assert_eq!(s.total.available_permits(), 1);
    }
    #[tokio::test]
    async fn argon_waiters_do_not_take_general_capacity() {
        let s = scheduler(2, 2);
        let held = s.try_permits(CpuClass::Argon).unwrap();
        let mut queued = Box::pin(s.run(CpuClass::Argon, || ()));
        pending(queued.as_mut()).await;
        assert_eq!(s.total.available_permits(), 1);
        assert_eq!(s.run(CpuClass::General, || 7).await, Ok(7));
        drop(queued);
        drop(held);
    }
    #[tokio::test(start_paused = true)]
    async fn argon_partial_admission_releases_on_cancel_and_timeout() {
        let s = scheduler(1, 1);
        let held = s.try_permits(CpuClass::General).unwrap();
        let mut queued = Box::pin(s.run(CpuClass::Argon, || ()));
        pending(queued.as_mut()).await;
        assert_eq!(s.argon.available_permits(), 0);
        drop(queued);
        assert_eq!(s.argon.available_permits(), 1);
        assert_eq!(s.waiting.available_permits(), 1);

        let mut queued = Box::pin(s.run(CpuClass::Argon, || ()));
        pending(queued.as_mut()).await;
        tokio::time::advance(Duration::from_millis(101)).await;
        assert_eq!(queued.await, Err(CpuError::Busy));
        assert_eq!(s.argon.available_permits(), 1);
        assert_eq!(s.waiting.available_permits(), 1);
        assert_eq!(s.total.available_permits(), 0);
        drop(held);
        assert_eq!(s.total.available_permits(), 1);
    }
    #[tokio::test]
    async fn running_cancel_keeps_permits_and_nested_is_rejected() {
        let s = scheduler(1, 0);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let handle = tokio::runtime::Handle::current();
        let nested_s = s.clone();
        let mut running = Box::pin(s.run(CpuClass::Argon, move || {
            assert_eq!(
                handle.block_on(nested_s.run(CpuClass::General, || ())),
                Err(CpuError::Nested)
            );
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        pending(running.as_mut()).await;
        started_rx.await.unwrap();
        drop(running);
        assert_eq!(s.total.available_permits(), 0);
        assert_eq!(s.argon.available_permits(), 0);
        assert_eq!(s.run(CpuClass::General, || ()).await, Err(CpuError::Busy));
        release_tx.send(()).unwrap();
        // Acquiring the semaphore is the completion barrier, not a timing sleep.
        let _done = s.total.acquire().await.unwrap();
        let _argon_done = s.argon.acquire().await.unwrap();
    }
    #[test]
    fn dispatched_but_not_started_is_cancelled() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            rx.await.unwrap();
            let s = scheduler(1, 0);
            let executed = Arc::new(AtomicBool::new(false));
            let flag = executed.clone();
            let mut queued = Box::pin(s.run(CpuClass::General, move || {
                flag.store(true, Ordering::Release);
            }));
            pending(queued.as_mut()).await;
            drop(queued);
            assert_eq!(s.total.available_permits(), 0);
            release_tx.send(()).unwrap();
            blocker.await.unwrap();
            let _done = s.total.acquire().await.unwrap();
            assert!(!executed.load(Ordering::Acquire));
        });
    }
    #[tokio::test]
    async fn running_capacity_is_strict_and_panic_releases_permits() {
        let s = scheduler(2, 0);
        let mut jobs = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..2 {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let scheduler = s.clone();
            jobs.push(tokio::spawn(async move {
                scheduler
                    .run(CpuClass::General, move || {
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                    })
                    .await
            }));
            started_rx.await.unwrap();
            releases.push(release_tx);
        }
        assert_eq!(s.total.available_permits(), 0);
        assert_eq!(s.run(CpuClass::General, || ()).await, Err(CpuError::Busy));
        for release in releases {
            release.send(()).unwrap();
        }
        for job in jobs {
            assert_eq!(job.await.unwrap(), Ok(()));
        }
        assert_eq!(s.total.available_permits(), 2);
        assert_eq!(
            s.run(CpuClass::Argon, || panic!("test worker failure"))
                .await,
            Err(CpuError::WorkerFailed)
        );
        assert_eq!(s.total.available_permits(), 2);
        assert_eq!(s.argon.available_permits(), 1);
    }
    #[test]
    fn invalid_config_is_rejected() {
        let mut c = CpuConfig::default();
        c.total = 0;
        assert!(CpuScheduler::new(c).is_err());
    }
}

thread_local! { static IN_CPU: Cell<bool> = const { Cell::new(false) }; }
struct Running;
impl Drop for Running {
    fn drop(&mut self) {
        IN_CPU.set(false);
    }
}
struct CancelOnDrop(Arc<AtomicBool>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
type Permits = (OwnedSemaphorePermit, Option<OwnedSemaphorePermit>);

pub struct CpuScheduler {
    config: CpuConfig,
    total: Arc<Semaphore>,
    argon: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
}
impl CpuScheduler {
    pub fn new(config: CpuConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            total: Arc::new(Semaphore::new(config.total)),
            argon: Arc::new(Semaphore::new(config.argon)),
            waiting: Arc::new(Semaphore::new(config.waiters)),
            config,
        })
    }
    fn try_permits(&self, class: CpuClass) -> Option<Permits> {
        let argon = if class == CpuClass::Argon {
            Some(self.argon.clone().try_acquire_owned().ok()?)
        } else {
            None
        };
        Some((self.total.clone().try_acquire_owned().ok()?, argon))
    }
    async fn permits(&self, class: CpuClass) -> Result<Permits, CpuError> {
        if let Some(p) = self.try_permits(class) {
            return Ok(p);
        }
        let _waiting = self
            .waiting
            .clone()
            .try_acquire_owned()
            .map_err(|_| CpuError::Busy)?;
        tokio::time::timeout(self.config.wait_timeout, async {
            // Never hold total CPU capacity while waiting for the Argon sub-budget.
            let argon = if class == CpuClass::Argon {
                Some(
                    self.argon
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| CpuError::WorkerFailed)?,
                )
            } else {
                None
            };
            let total = self
                .total
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| CpuError::WorkerFailed)?;
            Ok((total, argon))
        })
        .await
        .map_err(|_| CpuError::Busy)?
    }
    pub async fn run<F, T>(&self, class: CpuClass, work: F) -> Result<T, CpuError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        if IN_CPU.get() {
            return Err(CpuError::Nested);
        }
        let permits = self.permits(class).await?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel = CancelOnDrop(cancelled.clone());
        tokio::task::spawn_blocking(move || {
            // Keep permits even if the async caller is dropped after dispatch.
            let _permits = permits;
            if cancelled.load(Ordering::Acquire) {
                return Err(CpuError::Cancelled);
            }
            IN_CPU.set(true);
            let _running = Running;
            Ok(work())
        })
        .await
        .map_err(|_| CpuError::WorkerFailed)?
    }
}
