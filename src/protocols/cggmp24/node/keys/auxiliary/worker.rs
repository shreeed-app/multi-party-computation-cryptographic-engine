//! CGGMP24 auxiliary generation protocol descriptor.

use std::thread::JoinHandle;

use cggmp24::{
    ExecutionId,
    KeyRefreshError,
    key_refresh::{Msg, PregeneratedPrimes},
    key_share::{AuxInfo, DirtyAuxInfo, Valid},
};
use crossbeam_channel::{Receiver, Sender};
use rand_core::OsRng;
use round_based::{Incoming, Outgoing, state_machine::StateMachine};
use sha2::Sha256;
use tokio::sync::Notify;

use crate::protocols::cggmp24::{
    node::worker::{CggmpProtocol, WorkerDone, drive},
    security_level::Cggmp24SecurityLevel,
};

/// Message type for CGGMP24 auxiliary information generation.
pub type CggmpAuxiliaryGenerationMessage = Msg<Sha256, Cggmp24SecurityLevel>;

/// Output type for CGGMP24 auxiliary information generation.
pub type CggmpAuxiliaryGenerationOutput = AuxInfo<Cggmp24SecurityLevel>;

/// Completion signal alias for CGGMP24 auxiliary information generation.
pub type AuxiliaryGenerationWorkerDone =
    WorkerDone<CggmpAuxiliaryGenerationOutput>;

/// CGGMP24 auxiliary information generation protocol descriptor.
pub struct AuxiliaryGenerationProtocol {
    /// Unique identifier for the protocol instance.
    pub identifier: u16,
    /// Number of participants in the protocol.
    pub participants: u16,
    /// Unique identifier for the auxiliary information generation operation.
    pub execution_identifier_bytes: Vec<u8>,
    /// Handle to the prime generation thread spawned during protocol init.
    pub primes_handle: JoinHandle<PregeneratedPrimes<Cggmp24SecurityLevel>>,
}

impl CggmpProtocol for AuxiliaryGenerationProtocol {
    type Message = CggmpAuxiliaryGenerationMessage;
    type Output = CggmpAuxiliaryGenerationOutput;

    fn run(
        self,
        incoming: &Receiver<Incoming<Self::Message>>,
        outgoing: &Sender<Vec<Outgoing<Self::Message>>>,
        notify: &Notify,
    ) -> Option<Self::Output> {
        let execution_identifier: ExecutionId<'_> =
            ExecutionId::new(&self.execution_identifier_bytes);

        let mut random: OsRng = OsRng;

        // Wait for the prime generation thread spawned during protocol init.
        // All nodes start their prime generation threads simultaneously in
        // `start_session`, so by the time the first incoming message arrives
        // the slowest node's primes are ready — avoiding the `recv_timeout`
        // that would occur if prime generation ran here instead.
        tracing::info!("Waiting for Paillier primes.");
        let pregenerated_primes: PregeneratedPrimes<Cggmp24SecurityLevel> =
            match self.primes_handle.join() {
                Ok(primes) => primes,
                Err(_) => {
                    tracing::error!(
                        "Paillier prime generation thread panicked."
                    );
                    return None;
                },
            };
        tracing::info!("Paillier primes ready.");

        let state_machine: impl StateMachine<
            Msg = Self::Message,
            Output = Result<
                Valid<DirtyAuxInfo<Cggmp24SecurityLevel>>,
                KeyRefreshError,
            >,
        > = cggmp24::aux_info_gen::<Cggmp24SecurityLevel>(
            execution_identifier,
            self.identifier,
            self.participants,
            pregenerated_primes,
        )
        .into_state_machine(&mut random);

        drive(state_machine, incoming, outgoing, notify)
    }
}
