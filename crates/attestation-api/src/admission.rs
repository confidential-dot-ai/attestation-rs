//! Bounded verification on the blocking pool. Missing collateral is fetched
//! on the I/O runtime, so vendor time never holds a worker.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::config::VerifyConfig;
use crate::error::ApiError;

pub struct Admission {
    workers: Arc<Semaphore>,
    site_helpers: Semaphore,
    places: Arc<Semaphore>,
    queue_deadline: Duration,
    fetches: Arc<Semaphore>,
    fetch_deadline: Duration,
}

/// At most this many fetch tasks run at once, late ones included.
const FETCHES: usize = 1024;

impl Admission {
    pub fn new(config: &VerifyConfig) -> Self {
        let workers = config.workers();
        Self {
            workers: Arc::new(Semaphore::new(workers)),
            site_helpers: Semaphore::new(workers),
            places: Arc::new(Semaphore::new(workers * (1 + config.queue_per_worker))),
            queue_deadline: Duration::from_millis(config.queue_deadline_ms),
            fetches: Arc::new(Semaphore::new(FETCHES)),
            fetch_deadline: Duration::from_millis(config.fetch_deadline_ms),
        }
    }

    /// Bound concurrent site helper processes separately from CPU verification workers.
    pub(crate) async fn selected_tdx(
        &self,
        source: &crate::selected_tdx::SelectedTdx,
    ) -> Result<Vec<u8>, ApiError> {
        let _permit = self
            .site_helpers
            .try_acquire()
            .map_err(|_| ApiError::Overloaded)?;
        Ok(source.read(self.fetch_deadline).await?)
    }

    /// Run `job` on a worker, else 503 (queue full, or the queue deadline).
    pub async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let place = self.places.clone().try_acquire_owned();
        let _place = place.map_err(|_| ApiError::Overloaded)?;
        let worker = timeout(self.queue_deadline, self.workers.clone().acquire_owned()).await;
        let Ok(Ok(worker)) = worker else {
            return Err(ApiError::Overloaded);
        };
        let job = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            job()
        });
        job.await.map_err(|e| ApiError::Internal(e.to_string()))
    }

    /// `evidence` with all the collateral and NRAS answers it needs attached
    /// ([`attestation::Verifier::attach_all_collateral`]): 503 when [`FETCHES`]
    /// are running, 502 when collateral stays unavailable or after the fetch
    /// deadline. The fetch runs in its own task, so a late request leaves it
    /// to finish in the store.
    pub async fn fetch(
        &self,
        verifier: &Arc<attestation::Verifier>,
        evidence: &Arc<Vec<u8>>,
        nonce: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        let permit = self.fetches.clone().try_acquire_owned();
        let permit = permit.map_err(|_| ApiError::Overloaded)?;
        let (verifier, evidence) = (verifier.clone(), evidence.clone());
        let fetch = tokio::spawn(async move {
            let _permit = permit;
            verifier.attach_all_collateral(&evidence, &nonce).await
        });
        match timeout(self.fetch_deadline, fetch).await {
            Ok(Ok(attached)) => Ok(attached?),
            Ok(Err(e)) => Err(ApiError::Internal(e.to_string())),
            Err(_) => Err(ApiError::Verification(
                attestation::AttestationError::CollateralUnavailable {
                    collateral: "collateral".into(),
                    retry_after: Some(1),
                    detail: "not fetched within the fetch deadline".into(),
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use super::*;

    /// One worker, held until the sender is dropped.
    async fn busy(queue_per_worker: usize) -> (Arc<Admission>, std::sync::mpsc::Sender<()>) {
        let admission = Arc::new(Admission::new(&VerifyConfig {
            workers: 1,
            queue_per_worker,
            queue_deadline_ms: 100,
            ..Default::default()
        }));
        let (hold, wait) = std::sync::mpsc::channel::<()>();
        let held = admission.clone();
        tokio::spawn(async move { held.run(move || wait.recv()).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (admission, hold)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_busy_cpu_worker_does_not_block_the_bounded_site_helper() {
        let (admission, _hold) = busy(0).await;
        let source = crate::selected_tdx::SelectedTdx {
            helper: "/bin/false".into(),
            profile: "/profile".into(),
        };
        assert!(matches!(
            admission.selected_tdx(&source).await,
            Err(ApiError::Verification(_))
        ));
        let _helper = admission.site_helpers.try_acquire().unwrap();
        assert!(matches!(
            admission.selected_tdx(&source).await,
            Err(ApiError::Overloaded)
        ));
    }

    #[tokio::test]
    async fn a_request_that_cannot_start_is_refused_and_never_runs() {
        let ran = Arc::new(AtomicBool::new(false));
        let job = || {
            let ran = ran.clone();
            move || ran.store(true, Ordering::SeqCst)
        };
        let overloaded = |r: Result<(), ApiError>| matches!(r, Err(ApiError::Overloaded));
        // The queue is full: 503 at once. Queued past the deadline: 503.
        for (queue, waited) in [(0, 0..10), (1, 100..500)] {
            let (admission, _hold) = busy(queue).await;
            let start = Instant::now();
            assert!(overloaded(admission.run(job()).await));
            assert!(waited.contains(&start.elapsed().as_millis()));
        }
        // Queued, and the client went away.
        let (admission, hold) = busy(1).await;
        let _ = tokio::time::timeout(Duration::from_millis(10), admission.run(job())).await;
        drop(hold);
        tokio::time::sleep(Duration::from_millis(50)).await;
        admission.run(|| ()).await.unwrap();
        assert!(!ran.load(Ordering::SeqCst));
        let response = axum::response::IntoResponse::into_response(ApiError::Overloaded);
        assert_eq!(response.headers()["retry-after"], "1");
        // Every fetch task is running: 503 at once.
        let _all = admission
            .fetches
            .clone()
            .acquire_many_owned(FETCHES as u32)
            .await;
        let verifier = Arc::new(attestation::Verifier::new(attestation::Context::offline()));
        let fetch = admission
            .fetch(&verifier, &Arc::default(), Vec::new())
            .await;
        assert!(matches!(fetch, Err(ApiError::Overloaded)));
    }
}
