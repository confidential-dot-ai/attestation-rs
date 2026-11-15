//! Bounded verification. A job runs on the blocking pool once one of
//! `workers` slots is free; at most `queue_per_worker` per worker wait, each
//! no longer than the queue deadline. Evidence whose collateral is not in
//! memory is verified again in a separate, small cold lane that may wait for
//! vendors, so vendor time never holds a worker slot.

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
    cold: Arc<Semaphore>,
    cold_places: Arc<Semaphore>,
    fetch_deadline: Duration,
}

impl Admission {
    pub fn new(config: &VerifyConfig) -> Self {
        let workers = config.workers();
        Self {
            workers: Arc::new(Semaphore::new(workers)),
            places: Arc::new(Semaphore::new(workers * (1 + config.queue_per_worker))),
            queue_deadline: Duration::from_millis(config.queue_deadline_ms),
            cold: Arc::new(Semaphore::new(config.cold_workers())),
            cold_places: Arc::new(Semaphore::new(
                config.cold_workers() * (1 + config.queue_per_worker),
            )),
            fetch_deadline: Duration::from_millis(config.fetch_deadline_ms),
        }
    }

    /// Run `job` on a worker: 503 at once when the queue is full, or when no
    /// worker is free within the queue deadline. Dropping the returned future
    /// before the job starts means it never runs.
    pub async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let place = self.places.clone().try_acquire_owned();
        let _place = place.map_err(|_| ApiError::Overloaded)?;
        let deadline = Instant::now() + self.queue_deadline;
        let worker = timeout_at(deadline, self.workers.clone().acquire_owned())
            .await
            .map_err(|_| ApiError::Overloaded)?
            .expect("never closed");
        blocking(move || {
            let _worker = worker;
            job()
        })
        .await
    }

    /// Run `job`, which may wait for vendors, in the cold lane: 503 at once
    /// when its queue is full, 502 when it has not finished within the fetch
    /// deadline. A job that has started runs to its end, so the fetches it
    /// started finish in the store.
    pub async fn cold<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, ApiError> {
        let place = self.cold_places.clone().try_acquire_owned();
        let _place = place.map_err(|_| ApiError::Overloaded)?;
        let deadline = Instant::now() + self.fetch_deadline;
        let late = || {
            ApiError::Verification(attestation::AttestationError::CollateralUnavailable {
                collateral: "collateral".into(),
                retry_after: Some(1),
                detail: "not fetched within the fetch deadline".into(),
            })
        };
        let lane = timeout_at(deadline, self.cold.clone().acquire_owned()).await;
        let lane = lane.map_err(|_| late())?.expect("never closed");
        let job = blocking(move || {
            let _lane = lane;
            job()
        });
        timeout_at(deadline, job).await.map_err(|_| late())?
    }
}

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// One worker and `queue_per_worker` places, with the worker held until
    /// the returned sender is dropped.
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
        let queued = tokio::spawn({
            let (admission, job) = (admission.clone(), job());
            async move { admission.run(job).await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        queued.abort();
        drop(hold);
        tokio::time::sleep(Duration::from_millis(50)).await;
        admission.run(|| ()).await.unwrap();
        assert!(!ran.load(Ordering::SeqCst));
        let response = axum::response::IntoResponse::into_response(ApiError::Overloaded);
        assert_eq!(response.headers()["retry-after"], "1");
    }
}
