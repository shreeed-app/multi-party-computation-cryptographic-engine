//! CGGMP24 key generation worker implementation.

use std::{
    sync::Arc,
    thread::{sleep, spawn},
    time::Duration,
};

use cggmp24::{
    ExecutionId,
    generic_ec::curves::Secp256k1,
    key_share::IncompleteKeyShare,
    keygen::{KeygenError, ThresholdMsg},
    security_level::SecurityLevel128,
};
use crossbeam_channel::{Receiver, SendError, Sender};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use round_based::{
    Incoming,
    Outgoing,
    state_machine::{ProceedResult, StateMachine},
};
use sha2::Sha256;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Maximum number of concurrent CGGMP24 workers.
/// This bounds the number of OS threads spawned for CGGMP24
/// and prevents resource exhaustion under load.
const MAXIMUM_WORKERS: usize = 2;

/// Timeout duration for incoming messages.
/// CGGMP24 assumes reliable delivery, but we still need a
/// safety bound to avoid hanging forever if the orchestrator
/// misbehaves or a peer disappears.
const INCOMING_MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Global semaphore used to limit concurrent CGGMP24 workers.
/// A permit is acquired before spawning a worker thread and
/// released automatically when the worker exits.
static CGGMP_WORKER_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(MAXIMUM_WORKERS)));

/// Message type used by CGGMP24 threshold keygen state machine.
pub type CggmpKeyGenerationMessage =
    ThresholdMsg<Secp256k1, SecurityLevel128, Sha256>;

/// Worker completion notification.
/// This is sent exactly once by the worker thread.
pub enum WorkerDone {
    /// Key generation completed successfully with an incomplete key share.
    Ok(Box<IncompleteKeyShare<Secp256k1>>),
    /// Protocol ended with an error or was aborted.
    Err,
}

/// CGGMP24 key generation worker.
pub struct Worker {
    /// Identifier of the current participant.
    pub identifier: u16,
    /// Total number of participants (n).
    pub participants: u16,
    /// Threshold (t).
    pub threshold: u16,
    /// Execution identifier as bytes.
    pub execution_id_bytes: Vec<u8>,
    /// Channel to receive incoming messages.
    pub incoming_receiver: Receiver<Incoming<CggmpKeyGenerationMessage>>,
    /// Channel to send outgoing messages.
    pub outgoing_transmitter: Sender<Outgoing<CggmpKeyGenerationMessage>>,
    /// Channel to notify when the worker is done.
    pub done_transmitter: Sender<WorkerDone>,
}

/// Spawns a worker thread to execute CGGMP24 key generation.
/// Tokio is used only as a scheduler to provide back pressure.
/// The cryptographic protocol itself always runs on a blocking OS thread.
pub fn spawn_worker(worker: Worker) {
    let semaphore: Arc<Semaphore> = CGGMP_WORKER_SEMAPHORE.clone();

    tokio::spawn(async move {
        // Acquire a permit before spawning the OS thread.
        let _permit: SemaphorePermit<'_> = match semaphore.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                let _: Result<(), SendError<WorkerDone>> =
                    worker.done_transmitter.send(WorkerDone::Err);
                return;
            },
        };

        spawn(move || {
            run_worker(worker);
            // Permit released automatically when `_permit` is dropped.
        });
    });
}

/// Runs a single CGGMP24 keygen session.
fn run_worker(worker: Worker) {
    let mut random: OsRng = OsRng;

    let execution_id: ExecutionId<'_> =
        ExecutionId::new(&worker.execution_id_bytes);

    let mut state_machine: impl StateMachine<
        Output = Result<IncompleteKeyShare<Secp256k1>, KeygenError>,
        Msg = CggmpKeyGenerationMessage,
    > = cggmp24::keygen::<Secp256k1>(
        execution_id,
        worker.identifier,
        worker.participants,
    )
    .set_threshold(worker.threshold)
    .into_state_machine(&mut random);

    // Backoff delay for yielded executions.
    let mut backoff: u64 = 1;

    // Important: messages delivered via `incoming_receiver` must preserve
    // the order enforced by the orchestrator. Reordering would
    // violate CGGMP24 protocol assumptions.
    loop {
        match state_machine.proceed() {
            // Outgoing message to be sent to other participants.
            ProceedResult::SendMsg(output) => {
                backoff = 1; // Reset backoff on successful progress.

                let _: Result<
                    (),
                    SendError<Outgoing<CggmpKeyGenerationMessage>>,
                > = worker.outgoing_transmitter.send(output);
            },

            // Incoming message to be processed.
            ProceedResult::NeedsOneMoreMessage => {
                backoff = 1; // Reset backoff on successful progress.

                match worker
                    .incoming_receiver
                    .recv_timeout(INCOMING_MESSAGE_TIMEOUT)
                {
                    Ok(incoming) => {
                        if state_machine.received_msg(incoming).is_err() {
                            let _: Result<(), SendError<WorkerDone>> =
                                worker.done_transmitter.send(WorkerDone::Err);
                            break;
                        }
                    },
                    Err(_) => {
                        let _: Result<(), SendError<WorkerDone>> =
                            worker.done_transmitter.send(WorkerDone::Err);
                        break;
                    },
                }
            },

            // Yielded execution, continue.
            ProceedResult::Yielded => {
                // Simple exponential backoff to avoid busy-waiting.
                sleep(Duration::from_micros(backoff));
                backoff = (backoff * 2).min(100);
            },

            // Protocol completed.
            ProceedResult::Output(result) => {
                let _: Result<(), SendError<WorkerDone>> =
                    worker.done_transmitter.send(match result {
                        Ok(incomplete) => WorkerDone::Ok(Box::new(incomplete)),
                        Err(_) => WorkerDone::Err,
                    });
                break;
            },

            // Protocol ended with an error.
            ProceedResult::Error(_) => {
                let _: Result<(), SendError<WorkerDone>> =
                    worker.done_transmitter.send(WorkerDone::Err);
                break;
            },
        }
    }
}
