//! CGGMP24 key generation protocol descriptor.

use std::fmt::Debug;

use cggmp24::{
    ExecutionId,
    generic_ec::curves::Secp256k1,
    key_share::IncompleteKeyShare,
    keygen::ThresholdMsg,
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

/// Message type for CGGMP24 key generation.
pub type CggmpKeyGenerationMessage =
    ThresholdMsg<Secp256k1, Cggmp24SecurityLevel, Sha256>;

/// Output type for CGGMP24 key generation.
pub type CggmpKeyGenerationOutput = Box<IncompleteKeyShare<Secp256k1>>;

/// Completion signal alias for CGGMP24 key generation.
pub type KeyGenerationWorkerDone = WorkerDone<CggmpKeyGenerationOutput>;

/// CGGMP24 key generation protocol descriptor.
pub struct KeyGenerationProtocol {
    /// Unique identifier for the protocol instance.
    pub identifier: u16,
    /// List of participant identifiers in the protocol.
    pub participants: u16,
    /// Threshold number of participants required to complete the protocol.
    pub threshold: u16,
    /// Unique identifier for the key being generated.
    pub execution_identifier_bytes: Vec<u8>,
}

impl CggmpProtocol for KeyGenerationProtocol {
    type Message = CggmpKeyGenerationMessage;
    type Output = CggmpKeyGenerationOutput;

    fn run(
        self,
        incoming: &Receiver<Incoming<Self::Message>>,
        outgoing: &Sender<Vec<Outgoing<Self::Message>>>,
        notify: &Notify,
    ) -> Option<Self::Output> {
        let execution_identifier: ExecutionId<'_> =
            ExecutionId::new(&self.execution_identifier_bytes);

        // Initialize a random number generator for the protocol execution.
        let mut random: OsRng = OsRng;

        // Initialize the CGGMP24 key generation state machine with the
        // provided parameters.
        let state_machine: impl StateMachine<
            Msg = Self::Message,
            Output = Result<IncompleteKeyShare<Secp256k1>, impl Debug>,
        > = cggmp24::keygen::<Secp256k1>(
            execution_identifier,
            self.identifier,
            self.participants,
        )
        .set_threshold(self.threshold)
        .set_security_level::<Cggmp24SecurityLevel>()
        .into_state_machine(&mut random);

        drive(state_machine, incoming, outgoing, notify).map(Box::new)
    }
}
