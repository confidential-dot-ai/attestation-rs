//! A single hardware owner keeps blocking quote generation off async workers.
use std::sync::OnceLock;

use tokio::sync::{mpsc, oneshot};

use super::{generate_evidence_sync, TdxEvidence, TdxQuoteMethod};
use crate::error::{AttestationError, Result};

// One executing request and at most sixteen waiting, each with fixed-size
// REPORTDATA. There is no unbounded spawn_blocking queue or per-request thread.
const WAITING_QUOTES: usize = 16;
static WORKER: OnceLock<std::result::Result<Worker, String>> = OnceLock::new();

struct Job {
    report_data: [u8; 64],
    method: TdxQuoteMethod,
    reply: oneshot::Sender<Result<TdxEvidence>>,
}

struct Worker {
    jobs: mpsc::Sender<Job>,
}

impl Worker {
    fn start(
        capacity: usize,
        mut generate: impl FnMut([u8; 64], TdxQuoteMethod) -> Result<TdxEvidence> + Send + 'static,
    ) -> std::io::Result<Self> {
        let (jobs, mut receiver) = mpsc::channel::<Job>(capacity);
        std::thread::Builder::new()
            .name("tdx-quote".into())
            .spawn(move || {
                while let Some(job) = receiver.blocking_recv() {
                    // A cancelled queued request costs no hardware operation.
                    // An executing syscall may finish, but still owns the one
                    // execution slot until it does; cancellation cannot free it.
                    if !job.reply.is_closed() {
                        let _ = job.reply.send(generate(job.report_data, job.method));
                    }
                }
            })?;
        Ok(Self { jobs })
    }

    fn enqueue(
        &self,
        report_data: [u8; 64],
        method: TdxQuoteMethod,
    ) -> Result<oneshot::Receiver<Result<TdxEvidence>>> {
        let (reply, response) = oneshot::channel();
        self.jobs
            .try_send(Job {
                report_data,
                method,
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => AttestationError::QuoteQueueFull,
                mpsc::error::TrySendError::Closed(_) => stopped(),
            })?;
        Ok(response)
    }
}

fn stopped() -> AttestationError {
    AttestationError::HardwareAccessFailed("TDX quote worker stopped".into())
}

pub(super) async fn generate(report_data: [u8; 64], method: TdxQuoteMethod) -> Result<TdxEvidence> {
    let worker = WORKER
        .get_or_init(|| {
            Worker::start(WAITING_QUOTES, generate_evidence_sync).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|error| {
            AttestationError::HardwareAccessFailed(format!("start TDX quote worker: {error}"))
        })?;
    worker
        .enqueue(report_data, method)?
        .await
        .map_err(|_| stopped())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn evidence(report_data: [u8; 64]) -> TdxEvidence {
        TdxEvidence {
            quote: format!("{}", report_data[0]),
            cc_eventlog: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_hardware_leaves_async_work_runnable_and_rejects_overflow() {
        let (started, running) = oneshot::channel();
        let mut started = Some(started);
        let (release, wait) = std::sync::mpsc::channel();
        let worker = Worker::start(1, move |data, _| {
            if let Some(started) = started.take() {
                let _ = started.send(());
                wait.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            Ok(evidence(data))
        })
        .unwrap();
        let first = worker.enqueue([1; 64], TdxQuoteMethod::ConfigFs).unwrap();
        tokio::time::timeout(Duration::from_secs(1), running)
            .await
            .unwrap()
            .unwrap();
        let second = worker.enqueue([2; 64], TdxQuoteMethod::Vsock).unwrap();
        assert!(matches!(
            worker.enqueue([3; 64], TdxQuoteMethod::Auto),
            Err(AttestationError::QuoteQueueFull)
        ));
        // On a single-thread runtime, the old synchronous path prevents this
        // task from running until hardware finishes. No hardware is needed.
        tokio::time::timeout(Duration::from_millis(200), tokio::spawn(async { 42 }))
            .await
            .unwrap()
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap().unwrap().quote, "1");
        assert_eq!(second.await.unwrap().unwrap().quote, "2");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_does_not_overlap_hardware_and_skips_queued_work() {
        let (started, running) = oneshot::channel();
        let mut started = Some(started);
        let (release, wait) = std::sync::mpsc::channel();
        let (calls, mut observed) = mpsc::unbounded_channel();
        let worker = Worker::start(2, move |data, method| {
            calls.send((data[0], method)).unwrap();
            if let Some(started) = started.take() {
                let _ = started.send(());
                wait.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            if data[0] == 3 {
                return Err(AttestationError::HardwareAccessFailed("fixture".into()));
            }
            Ok(evidence(data))
        })
        .unwrap();
        let first = worker.enqueue([1; 64], TdxQuoteMethod::ConfigFs).unwrap();
        running.await.unwrap();
        let second = worker.enqueue([2; 64], TdxQuoteMethod::Vsock).unwrap();
        drop(first);
        drop(second);
        let third = worker.enqueue([3; 64], TdxQuoteMethod::Auto).unwrap();
        assert!(matches!(
            worker.enqueue([4; 64], TdxQuoteMethod::Auto),
            Err(AttestationError::QuoteQueueFull)
        ));
        assert_eq!(observed.try_recv().unwrap(), (1, TdxQuoteMethod::ConfigFs));
        assert!(observed.try_recv().is_err());
        release.send(()).unwrap();
        assert!(
            matches!(third.await.unwrap(), Err(AttestationError::HardwareAccessFailed(s)) if s == "fixture")
        );
        assert_eq!(observed.recv().await.unwrap(), (3, TdxQuoteMethod::Auto));
        drop(worker);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), observed.recv())
                .await
                .unwrap(),
            None
        );
    }
}
