//! The verification pool: one thread per CPU, each running one verification
//! at a time, fed from one queue.
//!
//! Verification is CPU-bound. The async workers only read requests and write
//! responses, so they never wait behind a verification. A request is queued
//! only while the threads can start it within `max_wait`; past that it is
//! refused at once, so that clients get a fast 503 rather than a timeout.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use tokio::sync::oneshot;

/// Why the pool did not run a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The queue holds more work than the threads start within `max_wait`.
    Full,
    /// The job waited past its deadline and was dropped unstarted.
    Expired,
    /// The job panicked.
    Panicked,
}

/// Counters since the start of the process.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Jobs run to the end.
    pub done: u64,
    /// Refused at admission.
    pub full: u64,
    /// Dropped unstarted past their deadline.
    pub expired: u64,
    /// Dropped because the caller went away.
    pub gone: u64,
    /// Total time jobs waited in the queue.
    pub wait: Duration,
    /// Total time jobs ran.
    pub run: Duration,
}

type Job = Box<dyn FnOnce() + Send>;

pub struct Pool {
    queue: Sender<Job>,
    shared: Arc<Shared>,
}

struct Shared {
    threads: usize,
    max_wait: Duration,
    deadline: Duration,
    /// Jobs queued and not yet started.
    queued: AtomicUsize,
    /// Moving average of the run time of a job, in nanoseconds.
    cost_ns: AtomicU64,
    done: AtomicU64,
    full: AtomicU64,
    expired: AtomicU64,
    gone: AtomicU64,
    wait_ns: AtomicU64,
    run_ns: AtomicU64,
}

/// The nice value of the verification threads.
#[cfg(target_os = "linux")]
const VERIFY_NICE: i32 = 10;

/// The run time assumed for a job until one has run.
const FIRST_COST: Duration = Duration::from_millis(5);

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Pool {
    /// `threads` threads; a job is admitted while the queue ahead of it
    /// takes them at most `max_wait`, and dropped unstarted once it waited
    /// `deadline`.
    pub fn new(threads: usize, max_wait: Duration, deadline: Duration) -> Self {
        let threads = threads.max(1);
        let (queue, jobs) = crossbeam_channel::bounded::<Job>(threads * 1024);
        for i in 0..threads {
            let jobs = jobs.clone();
            std::thread::Builder::new()
                .name(format!("verify-{i}"))
                .spawn(move || {
                    // Below the I/O threads, so that a busy pool does not
                    // slow accepting and reading requests; Linux sets the
                    // nice value per thread.
                    #[cfg(target_os = "linux")]
                    let _ = rustix::process::setpriority_process(None, VERIFY_NICE);
                    while let Ok(job) = jobs.recv() {
                        job();
                    }
                })
                .expect("spawn a verification thread");
        }
        Self {
            queue,
            shared: Arc::new(Shared {
                threads,
                max_wait,
                deadline,
                queued: AtomicUsize::new(0),
                cost_ns: AtomicU64::new(nanos(FIRST_COST)),
                done: AtomicU64::new(0),
                full: AtomicU64::new(0),
                expired: AtomicU64::new(0),
                gone: AtomicU64::new(0),
                wait_ns: AtomicU64::new(0),
                run_ns: AtomicU64::new(0),
            }),
        }
    }

    pub fn threads(&self) -> usize {
        self.shared.threads
    }

    /// Run `job` on a pool thread (with the caller's runtime for its I/O)
    /// and return its output. Dropping the returned future drops the job,
    /// queued or running.
    pub async fn run<T, F>(&self, job: F) -> Result<T, Refused>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let s = &self.shared;
        let ahead = s.queued.fetch_add(1, Relaxed);
        // With fewer jobs queued than threads, one is idle or nearly so.
        if ahead >= s.threads {
            let cost = Duration::from_nanos(s.cost_ns.load(Relaxed));
            let wait = cost.saturating_mul(u32::try_from(ahead + 1).unwrap_or(u32::MAX))
                / u32::try_from(s.threads).unwrap_or(u32::MAX);
            if wait > s.max_wait {
                s.queued.fetch_sub(1, Relaxed);
                s.full.fetch_add(1, Relaxed);
                return Err(Refused::Full);
            }
        }
        let (mut tx, rx) = oneshot::channel();
        let shared = s.clone();
        let runtime = tokio::runtime::Handle::current();
        let queued_at = Instant::now();
        let task: Job = Box::new(move || {
            let s = shared;
            s.queued.fetch_sub(1, Relaxed);
            let waited = queued_at.elapsed();
            s.wait_ns.fetch_add(nanos(waited), Relaxed);
            if tx.is_closed() {
                s.gone.fetch_add(1, Relaxed);
                return;
            }
            if waited > s.deadline {
                s.expired.fetch_add(1, Relaxed);
                let _ = tx.send(Err(Refused::Expired));
                return;
            }
            let started = Instant::now();
            let out = std::panic::catch_unwind(AssertUnwindSafe(|| {
                runtime.block_on(async {
                    tokio::select! {
                        out = job => Some(out),
                        () = tx.closed() => None,
                    }
                })
            }));
            let ran = nanos(started.elapsed());
            s.run_ns.fetch_add(ran, Relaxed);
            // cost += (ran - cost) / 8; a racing update loses one sample.
            let cost = s.cost_ns.load(Relaxed);
            s.cost_ns.store(cost - cost / 8 + ran / 8, Relaxed);
            match out {
                Ok(Some(out)) => {
                    s.done.fetch_add(1, Relaxed);
                    let _ = tx.send(Ok(out));
                }
                Ok(None) => {
                    s.gone.fetch_add(1, Relaxed);
                }
                Err(_) => {
                    let _ = tx.send(Err(Refused::Panicked));
                }
            }
        });
        if self.queue.try_send(task).is_err() {
            s.queued.fetch_sub(1, Relaxed);
            s.full.fetch_add(1, Relaxed);
            return Err(Refused::Full);
        }
        rx.await.unwrap_or(Err(Refused::Panicked))
    }

    pub fn stats(&self) -> Stats {
        let s = &self.shared;
        Stats {
            done: s.done.load(Relaxed),
            full: s.full.load(Relaxed),
            expired: s.expired.load(Relaxed),
            gone: s.gone.load(Relaxed),
            wait: Duration::from_nanos(s.wait_ns.load(Relaxed)),
            run: Duration::from_nanos(s.run_ns.load(Relaxed)),
        }
    }

    /// Log what the pool did every `every`, when it did anything.
    pub async fn report(self: Arc<Self>, every: Duration) {
        let mut last = self.stats();
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            let now = self.stats();
            let done = now.done - last.done;
            let started = done + (now.gone - last.gone);
            let dequeued = started + (now.expired - last.expired);
            let refused = now.full - last.full;
            if dequeued + refused > 0 {
                let mean = |d: Duration, n: u64| {
                    (d.as_secs_f64() * 1e3 / n.max(1) as f64 * 100.0).round() / 100.0
                };
                tracing::info!(
                    done,
                    refused,
                    expired = now.expired - last.expired,
                    gone = now.gone - last.gone,
                    queue_wait_ms = mean(now.wait - last.wait, dequeued),
                    verify_ms = mean(now.run - last.run, started),
                    "verification pool"
                );
            }
            last = now;
        }
    }
}
