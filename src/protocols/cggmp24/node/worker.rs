//! Generic CGGMP24 protocol worker.
//!
//! A single worker implementation shared across key generation and signing.
//! Each protocol implements the `CggmpProtocol` trait to provide its state
//! machine, message types, and output handling.

use std::{
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread::spawn,
    time::Duration,
};

use crossbeam_channel::{Receiver, Sender};
use once_cell::sync::Lazy;
use round_based::{
    Incoming,
    Outgoing,
    state_machine::{ProceedResult, StateMachine},
};

/// Maximum number of concurrent CGGMP24 workers across all protocol types.
const MAXIMUM_WORKERS: usize = 64;

/// Timeout for incoming messages. If no message arrives within this window
/// the worker treats it as a disconnect and aborts.
const INCOMING_MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

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
static LIMITER: Lazy<Arc<WorkerLimiter>> = Lazy::new(|| {
    Arc::new(WorkerLimiter { active: Mutex::new(0), condvar: Condvar::new() })
});

/// Abstracts over CGGMP24 protocol variants (key generation, signing).
/// `run` is called directly inside the worker thread — no `Send` constraint
/// on the state machine, which may use `Rc` internally.
pub trait CggmpProtocol: Send + 'static {
    /// Inbound/outbound message type.
    type Msg: Send + 'static;
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
    ///
    /// # Returns
    /// * `Option<Self::Output>` - `Some(output)` if the protocol completed
    ///   successfully, `None` if it failed or was aborted (e.g. due to a
    ///   disconnect or invalid message).
    fn run(
        self,
        incoming: &Receiver<Incoming<Self::Msg>>,
        outgoing: &Sender<Vec<Outgoing<Self::Msg>>>,
    ) -> Option<Self::Output>;
}

/// Drive a state machine to completion.
/// Flushes outgoing message batches atomically before blocking on incoming
/// messages. Returns `Some(output)` on success, `None` on any error or
/// timeout.
///
/// # Aruments
/// * `state_machine` (`impl StateMachine<Msg = M, Output = Result<O, E>>`) -
///   the state machine to drive to completion.
/// * `incoming` (`Receiver<Incoming<M>>`) - channel to receive messages from
///   the node.
/// * `outgoing` (`Sender<Vec<Outgoing<M>>`) - channel to send outgoing
///   messages to the node.
///
/// # Returns
/// * `Option<O>` - `Some(output)` if the state machine completed successfully,
///   `None` if it produced an error or if the incoming channel was closed or
///   timed out.
pub fn drive<M, O, E>(
    mut state_machine: impl StateMachine<Msg = M, Output = Result<O, E>>,
    incoming: &Receiver<Incoming<M>>,
    outgoing: &Sender<Vec<Outgoing<M>>>,
) -> Option<O> {
    let mut pending: Vec<Outgoing<M>> = Vec::new();
    let mut backoff: u64 = 1; // µs.
    tracing::debug!("State machine starting.");

    loop {
        match state_machine.proceed() {
            // State machine produced an outgoing message to send.
            ProceedResult::SendMsg(message) => {
                tracing::debug!("State machine produced outgoing message.");
                pending.push(message);
                backoff = 1;
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
                    if outgoing.send(std::mem::take(&mut pending)).is_err() {
                        tracing::debug!("Outgoing channel closed, aborting.");
                        return None;
                    }
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
                        tracing::debug!(
                            %error,
                            "Incoming channel error, aborting."
                        );
                        return None;
                    },
                }

                backoff = 1;
            },

            // State machine yielded without producing output — back off before
            // resuming to avoid busy-waiting.
            ProceedResult::Yielded => {
                tracing::debug!(
                    backoff_us = backoff,
                    "State machine yielded."
                );
                std::thread::sleep(Duration::from_micros(backoff));
                backoff = (backoff * 2).min(100);
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
                    let _ = outgoing.send(std::mem::take(&mut pending));
                }

                return match result {
                    Ok(output) => {
                        tracing::debug!(
                            "State machine completed successfully."
                        );
                        Some(output)
                    },
                    Err(_) => {
                        tracing::debug!(
                            "State machine output error, aborting."
                        );
                        None
                    },
                };
            },

            // State machine produced an error, drive is complete but protocol
            // failed.
            ProceedResult::Error(error) => {
                tracing::debug!(
                    error = ?error,
                    "State machine error, aborting."
                );
                return None;
            },
        }
    }
}

/// Completion signal sent by the worker to the node protocol.
pub enum WorkerDone<O> {
    /// Protocol completed successfully.
    Ok(O),
    /// Protocol failed or was aborted.
    Err,
}

/// Generic CGGMP24 worker. Carries the channels and the protocol descriptor.
pub struct Worker<P: CggmpProtocol> {
    /// Protocol descriptor — drives the state machine.
    pub protocol: P,
    /// Channel to receive incoming messages from the node.
    pub incoming_receiver: Receiver<Incoming<P::Msg>>,
    /// Channel to send batches of outgoing messages to the node.
    pub outgoing_transmitter: Sender<Vec<Outgoing<P::Msg>>>,
    /// Channel to notify the node when the worker completes.
    pub done_transmitter: Sender<WorkerDone<P::Output>>,
}

/// Spawn a worker thread for the given protocol, subject to the global
/// concurrency limit.
///
/// Blocks until a slot is available, then spawns an OS thread.
///
/// # Arguments
/// * `worker` (`Worker<P>`) - the worker instance containing the protocol and
pub fn spawn_worker<P: CggmpProtocol>(worker: Worker<P>) {
    let limiter: Arc<WorkerLimiter> = LIMITER.clone();
    tracing::debug!("Spawning CGGMP24 worker thread.");

    spawn(move || {
        // Acquire a slot — blocks if MAXIMUM_WORKERS are already active.
        {
            let mut active: MutexGuard<'_, usize> = match limiter.active.lock()
            {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!(
                        "Worker limiter mutex poisoned, recovering."
                    );
                    poisoned.into_inner()
                },
            };

            while *active >= MAXIMUM_WORKERS {
                tracing::debug!(
                    active = *active,
                    max = MAXIMUM_WORKERS,
                    "Worker limit reached, waiting for a slot."
                );

                active = match limiter.condvar.wait(active) {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        tracing::error!(
                            "Worker limiter condvar poisoned, recovering."
                        );
                        poisoned.into_inner()
                    },
                };
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
        match limiter.active.lock() {
            Ok(mut active) => {
                *active -= 1;
                tracing::debug!(active = *active, "Worker slot released.");
            },
            Err(poisoned) => {
                let mut active = poisoned.into_inner();
                *active = active.saturating_sub(1);

                tracing::error!(
                    active = *active,
                    "Worker limiter mutex poisoned on release, recovered."
                );
            },
        }

        limiter.condvar.notify_one();
    });
}

/// Run the worker: delegate to the protocol's `run` method and forward the
/// result to `done_transmitter`.
///
/// # Arguments
/// * `worker` (`Worker<P>`) - the worker instance containing the protocol and
///  channels.
fn run_worker<P: CggmpProtocol>(worker: Worker<P>) {
    tracing::debug!("Worker thread started, running protocol.");

    let result: Option<<P as CggmpProtocol>::Output> = worker
        .protocol
        .run(&worker.incoming_receiver, &worker.outgoing_transmitter);

    let done: WorkerDone<<P as CggmpProtocol>::Output> = match result {
        Some(output) => {
            tracing::debug!("Protocol completed successfully.");
            WorkerDone::Ok(output)
        },
        None => {
            tracing::debug!("Protocol failed or was aborted.");
            WorkerDone::Err
        },
    };

    if worker.done_transmitter.send(done).is_err() {
        tracing::debug!(
            "Failed to send completion signal, receiver already dropped."
        );
    }
}
