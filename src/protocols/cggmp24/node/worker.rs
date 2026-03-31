//! Generic CGGMP24 protocol worker.
//!
//! A single worker implementation shared across key generation and signing.
//! Each protocol implements the `CggmpProtocol` trait to provide its state
//! machine, message types, and output handling.

use std::{
    fmt::Debug,
    mem::take,
    sync::{Arc, Condvar, LockResult, Mutex, MutexGuard, WaitTimeoutResult},
    thread::{spawn, yield_now},
    time::Duration,
};

use crossbeam_channel::{Receiver, Sender};
use once_cell::sync::Lazy;
use round_based::{
    Incoming,
    Outgoing,
    state_machine::{ProceedResult, StateMachine},
};
use tokio::sync::Notify;

/// Maximum number of concurrent CGGMP24 workers across all protocol types.
const MAXIMUM_WORKERS: usize = 64;

/// Timeout for incoming messages. If no message arrives within this window
/// the worker treats it as a disconnect and aborts.
const INCOMING_MESSAGE_TIMEOUT: Duration =
    Duration::from_secs(if cfg!(feature = "test-fast-crypto") {
        600
    } else {
        300
    });

/// Maximum time to wait for a worker slot when the concurrency limit is
/// reached. If no slot becomes available within this window the worker signals
/// failure instead of blocking indefinitely — prevents hangs when a previous
/// worker crashed without releasing its slot.
const WORKER_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Global limiter for concurrent workers. Enforces a maximum number of active
/// workers across all protocol types, blocking new spawns until a slot is
/// available.
struct WorkerLimiter {
    /// Number of currently active workers.
    active: Mutex<usize>,
    /// Condition variable to wake waiting threads when a slot is released.
    condvar: Condvar,
}

/// Global worker limiter instance.
static LIMITER: Lazy<WorkerLimiter> = Lazy::new(|| WorkerLimiter {
    active: Mutex::new(0),
    condvar: Condvar::new(),
});

/// Abstracts over CGGMP24 protocol variants (key generation, signing).
/// `run` is called directly inside the worker thread — no `Send` constraint
/// on the state machine, which may use `Rc` internally.
pub trait CggmpProtocol: Send + 'static {
    /// Inbound/outbound message type.
    type Message: Send + 'static;
    /// Successful output type.
    type Output: Send + 'static;

    /// Drive the protocol to completion.
    /// Called from inside the worker thread — free to construct and use
    /// non-`Send` types (e.g. state machines backed by `Rc`) internally.
    ///
    /// # Arguments
    /// * `incoming` (`Receiver<Incoming<Self::Msg>>`) - channel to receive
    ///   messages from the node.
    /// * `outgoing` (`Sender<Vec<Outgoing<Self::Msg>>`) - channel to send
    ///   outgoing messages from the node.
    /// * `notify` (`&Notify`) - fired after each outgoing batch is sent so
    ///   that the async poller in `collect_round` can wake up promptly rather
    ///   than spinning with `yield_now`.
    ///
    /// # Returns
    /// * `Option<Self::Output>` - `Some(output)` if the protocol completed
    ///   successfully, `None` if it failed or was aborted (e.g. due to a
    ///   disconnect or invalid message).
    fn run(
        self,
        incoming: &Receiver<Incoming<Self::Message>>,
        outgoing: &Sender<Vec<Outgoing<Self::Message>>>,
        notify: &Notify,
    ) -> Option<Self::Output>;
}

/// Drive a state machine to completion.
/// Flushes outgoing message batches atomically before blocking on incoming
/// messages. Returns `Some(output)` on success, `None` on any error or
/// timeout.
///
/// # Arguments
/// * `state_machine` (`impl StateMachine<Msg = M, Output = Result<O, E>>`) -
///   the state machine to drive to completion.
/// * `incoming` (`Receiver<Incoming<M>>`) - channel to receive messages from
///   the node.
/// * `outgoing` (`Sender<Vec<Outgoing<M>>`) - channel to send outgoing
///   messages to the node.
/// * `notify` (`&Notify`) - fired after each outgoing batch is sent so that
///   the async poller in `collect_round` can wake up immediately instead of
///   busy-spinning. Called from this OS thread — no Tokio runtime required.
///
/// # Returns
/// * `Option<O>` - `Some(output)` if the state machine completed successfully,
///   `None` if it produced an error or if the incoming channel was closed or
///   timed out.
pub fn drive<M, O, E: Debug>(
    mut state_machine: impl StateMachine<Msg = M, Output = Result<O, E>>,
    incoming: &Receiver<Incoming<M>>,
    outgoing: &Sender<Vec<Outgoing<M>>>,
    notify: &Notify,
) -> Option<O> {
    let mut pending: Vec<Outgoing<M>> = Vec::new();
    tracing::debug!("State machine starting.");

    loop {
        match state_machine.proceed() {
            // State machine produced an outgoing message to send.
            ProceedResult::SendMsg(message) => {
                tracing::debug!("State machine produced outgoing message.");
                pending.push(message);
            },

            // State machine needs to receive a message before proceeding.
            ProceedResult::NeedsOneMoreMessage => {
                tracing::debug!(
                    pending_count = pending.len(),
                    "State machine needs one more message, flushing pending \
                    outgoing batch."
                );

                // Flush all accumulated outgoing messages atomically before
                // blocking — ensures the node receives the full batch for
                // this round before we wait for the next incoming message.
                if !pending.is_empty() {
                    if outgoing.send(take(&mut pending)).is_err() {
                        tracing::debug!("Outgoing channel closed, aborting.");
                        return None;
                    }
                    // Wake the async poller so it can drain this batch and
                    // forward the messages to the controller without delay.
                    // `notify_one` is safe to call from any thread.
                    notify.notify_one();
                }

                tracing::debug!("Waiting for incoming message.");
                match incoming.recv_timeout(INCOMING_MESSAGE_TIMEOUT) {
                    Ok(_message) => {
                        tracing::debug!(
                            "Incoming message received, delivering to state \
                            machine."
                        );
                        if state_machine.received_msg(_message).is_err() {
                            tracing::debug!(
                                "State machine rejected incoming message, \
                                aborting."
                            );
                            return None;
                        }
                    },
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "Incoming channel error, aborting."
                        );
                        return None;
                    },
                }
            },

            // State machine yielded without producing output — back off before
            // resuming to avoid busy-waiting.
            ProceedResult::Yielded => {
                tracing::debug!("State machine yielded.");
                yield_now();
            },

            // State machine produced an output, drive is complete.
            ProceedResult::Output(result) => {
                tracing::debug!("State machine produced output.");

                // Flush any remaining outgoing messages before signaling
                // completion.
                if !pending.is_empty() {
                    tracing::debug!(
                        pending_count = pending.len(),
                        "Flushing remaining outgoing messages before \
                        completion."
                    );
                    let _ = outgoing.send(take(&mut pending));
                    notify.notify_one();
                }

                return match result {
                    Ok(output) => {
                        tracing::debug!(
                            "State machine completed successfully."
                        );
                        Some(output)
                    },
                    Err(error) => {
                        tracing::error!(
                            error = ?error,
                            "State machine output error, aborting."
                        );
                        None
                    },
                };
            },

            // State machine produced an error, drive is complete but protocol
            // failed.
            ProceedResult::Error(error) => {
                tracing::error!(
                    error = ?error,
                    "State machine error, aborting."
                );
                return None;
            },
        }
    }
}

/// Context for acquiring a worker slot before spawning.
#[derive(Debug)]
enum LockContext {
    /// Initial acquisition of a worker slot before spawning.
    Acquire,
    /// Waiting for a worker slot to become available.
    Wait,
    /// Releasing a worker slot after completion.
    Release,
}

/// Helper function to recover from a poisoned mutex lock by logging the error
/// and returning the inner value.
///
/// # Arguments
/// * `result` (`LockResult<MutexGuard<'_, T>>`) - the result of attempting to
///   lock a mutex.
/// * `context` (`LockContext`) - the context of the lock for logging purposes.
///
/// # Returns
/// * `MutexGuard<'_, T>` - the guard for the locked mutex, recovered if the
///   mutex was poisoned.
fn recover_lock<'l, T>(
    result: LockResult<MutexGuard<'l, T>>,
    context: LockContext,
) -> MutexGuard<'l, T> {
    match result {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::error!(?context, "Mutex poisoned, recovering.");
            poisoned.into_inner()
        },
    }
}

/// Helper to recover from a poisoned mutex lock returned by
/// `Condvar::wait_timeout`.
///
/// # Arguments
/// * `result` - the result of `Condvar::wait_timeout`.
/// * `context` - the context of the lock for logging purposes.
///
/// # Returns
/// * `(MutexGuard<'_, T>, WaitTimeoutResult)` - guard and timeout status,
///   recovered if the mutex was poisoned.
fn recover_lock_timeout<'l, T>(
    result: LockResult<(MutexGuard<'l, T>, WaitTimeoutResult)>,
    context: LockContext,
) -> (MutexGuard<'l, T>, WaitTimeoutResult) {
    match result {
        Ok(pair) => pair,
        Err(poisoned) => {
            tracing::error!(?context, "Mutex poisoned, recovering.");
            poisoned.into_inner()
        },
    }
}

/// Completion signal sent by the worker to the node protocol.
pub enum WorkerDone<O> {
    /// Protocol completed successfully.
    Ok(O),
    /// Protocol failed or was aborted.
    Failed,
}

/// Generic CGGMP24 worker. Carries the channels and the protocol descriptor.
pub struct Worker<P: CggmpProtocol> {
    /// Protocol descriptor — drives the state machine.
    pub protocol: P,
    /// Channel to receive incoming messages from the node.
    pub incoming_receiver: Receiver<Incoming<P::Message>>,
    /// Channel to send batches of outgoing messages to the node.
    pub outgoing_transmitter: Sender<Vec<Outgoing<P::Message>>>,
    /// Channel to notify the node when the worker completes.
    pub done_transmitter: Sender<WorkerDone<P::Output>>,
    /// Fired after each outgoing batch and after the done signal so that
    /// `collect_round` can wake immediately rather than busy-spinning.
    pub notify: Arc<Notify>,
}

/// Spawn a worker thread for the given protocol, subject to the global
/// concurrency limit.
///
/// Blocks until a slot is available, then spawns an OS thread.
///
/// # Arguments
/// * `worker` (`Worker<P>`) - The worker instance containing the protocol
///   descriptor, message channels, and completion signal transmitter.
pub fn spawn_worker<P: CggmpProtocol>(worker: Worker<P>) {
    let limiter: &'static WorkerLimiter = &LIMITER;
    tracing::debug!("Spawning CGGMP24 worker thread.");

    spawn(move || {
        // Acquire a slot — blocks if MAXIMUM_WORKERS are already active.
        // Uses a timeout to avoid hanging indefinitely if a previous worker
        // crashed without releasing its slot.
        {
            let mut active: MutexGuard<'_, usize> =
                recover_lock(limiter.active.lock(), LockContext::Acquire);

            while *active >= MAXIMUM_WORKERS {
                tracing::debug!(
                    active = *active,
                    max = MAXIMUM_WORKERS,
                    "Worker limit reached, waiting for a slot."
                );

                let (new_active, timed_out): (
                    MutexGuard<'_, usize>,
                    WaitTimeoutResult,
                ) = recover_lock_timeout(
                    limiter
                        .condvar
                        .wait_timeout(active, WORKER_ACQUIRE_TIMEOUT),
                    LockContext::Wait,
                );
                active = new_active;

                if timed_out.timed_out() && *active >= MAXIMUM_WORKERS {
                    tracing::error!(
                        max = MAXIMUM_WORKERS,
                        timeout_secs = WORKER_ACQUIRE_TIMEOUT.as_secs(),
                        "Timed out waiting for a worker slot — signaling \
                        failure to caller."
                    );
                    let _ = worker.done_transmitter.send(WorkerDone::Failed);
                    return;
                }
            }

            *active += 1;
            tracing::debug!(active = *active, "Worker slot acquired.");
        }

        // Run the worker protocol — this will block until completion. The
        // protocol is responsible for handling its own timeouts and abort
        // conditions (e.g. disconnects, invalid messages etc.) and returning
        // `None` if it fails or is aborted.
        run_worker(worker);

        // Release the slot and wake one waiting thread.
        let mut active: MutexGuard<'_, usize> =
            recover_lock(limiter.active.lock(), LockContext::Release);
        *active = active.saturating_sub(1);
        tracing::debug!(active = *active, "Worker slot released.");
        limiter.condvar.notify_one();
    });
}

/// Run the worker: delegate to the protocol's `run` method and forward the
/// result to `done_transmitter`.
///
/// # Arguments
/// * `worker` (`Worker<P>`) - the worker instance containing the protocol and
///   channels.
fn run_worker<P: CggmpProtocol>(worker: Worker<P>) {
    tracing::debug!("Worker thread started, running protocol.");

    let result: Option<<P as CggmpProtocol>::Output> = worker.protocol.run(
        &worker.incoming_receiver,
        &worker.outgoing_transmitter,
        &worker.notify,
    );

    let done: WorkerDone<<P as CggmpProtocol>::Output> = match result {
        Some(output) => {
            tracing::debug!("Protocol completed successfully.");
            WorkerDone::Ok(output)
        },
        None => {
            tracing::warn!("Protocol failed or was aborted.");
            WorkerDone::Failed
        },
    };

    if worker.done_transmitter.send(done).is_err() {
        tracing::debug!(
            "Failed to send completion signal, receiver already dropped."
        );
    }

    // Wake the async poller so it can observe the done signal via
    // `try_recv` on the done channel. Must fire after the send above.
    worker.notify.notify_one();
}
