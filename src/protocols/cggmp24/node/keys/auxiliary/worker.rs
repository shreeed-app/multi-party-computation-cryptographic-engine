//! CGGMP24 auxiliary generation protocol descriptor.

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

use crate::protocols::cggmp24::{
    node::worker::{CggmpProtocol, WorkerDone, drive},
    pregenerated_primes::pregenerate_primes,
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
}

impl CggmpProtocol for AuxiliaryGenerationProtocol {
    type Message = CggmpAuxiliaryGenerationMessage;
    type Output = CggmpAuxiliaryGenerationOutput;

    fn run(
        self,
        incoming: &Receiver<Incoming<Self::Message>>,
        outgoing: &Sender<Vec<Outgoing<Self::Message>>>,
    ) -> Option<Self::Output> {
        let execution_identifier: ExecutionId<'_> =
            ExecutionId::new(&self.execution_identifier_bytes);

        let mut random: OsRng = OsRng;

        // Pre-generate Paillier primes to speed up the protocol execution, as
        // prime generation is the most time-consuming part of the protocol.
        // This allows us to have a more accurate measurement of the
        // protocol execution time without being dominated by prime generation
        // time, which is not the focus of our performance optimizations.
        tracing::info!("Pre-generating Paillier primes.");
        let pregenerated_primes: PregeneratedPrimes<Cggmp24SecurityLevel> =
            pregenerate_primes(self.identifier);
        tracing::info!("Paillier primes pregenerated.");

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

        drive(state_machine, incoming, outgoing)
    }
}
