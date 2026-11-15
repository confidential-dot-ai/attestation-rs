//! The verification pool: one thread per CPU, each running one verification
//! at a time, fed from one queue.
//!
//! Verification is CPU-bound. The async workers only read requests and write
//! responses, so they never wait behind a verification. A request is queued
//! only while the threads can start it within `max_wait`; past that it is
//! refused at once, so that clients get a fast 503 rather than a timeout.
//! Jobs must not wait on I/O: a thread that waits serves no one.

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
    /// No thread took the job within the deadline; it never starts.
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
    /// Not started within the deadline.
    pub expired: u64,
    /// Dropped because the caller went away.
    pub gone: u64,
    /// Total time jobs waited in the queue.
    pub wait: Duration,
    /// Total CPU time of jobs.
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
    /// Moving average of the CPU time of a job, in nanoseconds.
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

/// A job already admitted once is refused only past this many times
/// `max_wait` of work queued.
const RERUN_SLACK: u32 = 4;

/// The CPU time assumed for a job until one has run.
const FIRST_COST: Duration = Duration::from_millis(5);

/// The CPU time of the calling thread; elsewhere than Linux, wall time.
fn thread_time() -> Duration {
    #[cfg(target_os = "linux")]
    {
        let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
        Duration::new(
            u64::try_from(t.tv_sec).unwrap_or(0),
            u32::try_from(t.tv_nsec).unwrap_or(0),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
        START.elapsed()
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Pool {
    /// `threads` threads; a job is admitted while the queue ahead of it
    /// takes them at most `max_wait`, and its caller gets
    /// [`Refused::Expired`] when no thread took it within `deadline`.
    pub fn new(threads: usize, max_wait: Duration, deadline: Duration) -> Self {
        let threads = threads.max(1);
        // Admission keeps the queue near max_wait of work; this bounds it
        // when the cost estimate is low.
        let (queue, jobs) = crossbeam_channel::bounded::<Job>(threads * 64);
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

    /// Run `job` on a pool thread and return its output. `job` runs on the
    /// caller's runtime handle but must not wait on I/O. Dropping the
    /// returned future drops the job, queued or running.
    pub async fn run<T, F>(&self, job: F) -> Result<T, Refused>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.queue(job, true).await
    }

    /// As [`Self::run`], for the next step of work already admitted (a
    /// verification that had to ask a vendor first): it is refused only when
    /// the queue holds [`RERUN_SLACK`] times `max_wait` of work.
    pub async fn rerun<T, F>(&self, job: F) -> Result<T, Refused>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.queue(job, false).await
    }

    async fn queue<T, F>(&self, job: F, admit: bool) -> Result<T, Refused>
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
            let limit = if admit {
                s.max_wait
            } else {
                s.max_wait * RERUN_SLACK
            };
            if wait > limit {
                s.queued.fetch_sub(1, Relaxed);
                s.full.fetch_add(1, Relaxed);
                return Err(Refused::Full);
            }
        }
        let (mut tx, mut rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel::<()>();
        let shared = s.clone();
        let runtime = tokio::runtime::Handle::current();
        let queued_at = Instant::now();
        let task: Job = Box::new(move || {
            let s = shared;
            s.queued.fetch_sub(1, Relaxed);
            let waited = queued_at.elapsed();
            s.wait_ns.fetch_add(nanos(waited), Relaxed);
            if tx.is_closed() || started_tx.send(()).is_err() {
                // A caller past the deadline was counted as expired.
                if waited < s.deadline {
                    s.gone.fetch_add(1, Relaxed);
                }
                return;
            }
            let started = thread_time();
            let out = std::panic::catch_unwind(AssertUnwindSafe(|| {
                runtime.block_on(async {
                    tokio::select! {
                        out = job => Some(out),
                        () = tx.closed() => None,
                    }
                })
            }));
            let ran = nanos(thread_time().saturating_sub(started));
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
        // The deadline is for reaching a thread. Returning drops the
        // receivers: a job not started yet never starts.
        tokio::select! {
            biased;
            out = &mut rx => return out.unwrap_or(Err(Refused::Panicked)),
            started = tokio::time::timeout(s.deadline, started_rx) => {
                if !matches!(started, Ok(Ok(()))) {
                    s.expired.fetch_add(1, Relaxed);
                    return Err(Refused::Expired);
                }
            }
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
