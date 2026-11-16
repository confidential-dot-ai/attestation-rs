//! Bounded verification on the blocking pool. Missing collateral is fetched
//! on the I/O runtime, so vendor time never holds a worker.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Instant};

use crate::config::VerifyConfig;
use crate::error::ApiError;

pub struct Admission {
    workers: Arc<Semaphore>,
    places: Arc<Semaphore>,
    queue_deadline: Duration,
    fetch_deadline: Duration,
}

impl Admission {
    pub fn new(config: &VerifyConfig) -> Self {
        let workers = config.workers();
        Self {
            workers: Arc::new(Semaphore::new(workers)),
            places: Arc::new(Semaphore::new(workers * (1 + config.queue_per_worker))),
            queue_deadline: Duration::from_millis(config.queue_deadline_ms),
            fetch_deadline: Duration::from_millis(config.fetch_deadline_ms),
        }
    }

    /// Run `job` on a worker, else 503 (queue full, or the queue deadline).
    pub async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let place = self.places.clone().try_acquire_owned();
        let _place = place.map_err(|_| ApiError::Overloaded)?;
        let deadline = Instant::now() + self.queue_deadline;
        let worker = timeout_at(deadline, self.workers.clone().acquire_owned()).await;
        let worker = worker
            .map_err(|_| ApiError::Overloaded)?
            .expect("never closed");
        blocking(move || {
            let _worker = worker;
            job()
        })
        .await
    }

    /// `evidence` with the collateral and NRAS answers it needs attached,
    /// gathered as [`attestation::Verifier::attach_collateral`] does: 502 after
    /// the fetch deadline. The fetches run in their own task, so a late
    /// request leaves them to finish in the store; per-host caps bound them.
    pub async fn fetch(
        &self,
        verifier: &Arc<attestation::Verifier>,
        evidence: &Arc<Vec<u8>>,
        nonce: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError> {
        let (verifier, evidence) = (verifier.clone(), evidence.clone());
        let fetch =
            tokio::spawn(async move { verifier.attach_collateral(&evidence, &nonce).await });
        match tokio::time::timeout(self.fetch_deadline, fetch).await {
            Ok(Ok(attached)) => Ok(attached?),
            _ => Err(ApiError::Verification(
                attestation::AttestationError::CollateralUnavailable {
                    collateral: "collateral".into(),
                    retry_after: Some(1),
                    detail: "not fetched within the fetch deadline".into(),
                },
            )),
        }
    }
}

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    let job = tokio::task::spawn_blocking(job);
    job.await.map_err(|e| ApiError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

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
    }
}
