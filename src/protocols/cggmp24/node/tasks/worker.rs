//! CGGMP24 signing protocol descriptor.

use std::fmt::Debug;

use cggmp24::{
    ExecutionId,
    generic_ec::curves::Secp256k1,
    key_share::KeyShare,
    signing::{DataToSign, Signature, msg::Msg},
};
use crossbeam_channel::{Receiver, Sender};
use rand_core::OsRng;
use round_based::{Incoming, Outgoing, state_machine::StateMachine};
use sha2::Sha256;

use crate::protocols::cggmp24::node::worker::{
    CggmpProtocol,
    WorkerDone,
    drive,
};

/// Message type for CGGMP24 signing.
pub type CggmpSigningMessage = Msg<Secp256k1, Sha256>;

/// Completion signal alias for CGGMP24 signing.
pub type SigningWorkerDone = WorkerDone<CggmpSigningOutput>;

/// Output type for CGGMP24 signing.
pub type CggmpSigningOutput = Signature<Secp256k1>;

/// CGGMP24 signing protocol descriptor.
pub struct SigningProtocol {
    /// Unique identifier for the protocol instance.
    pub identifier: u16,
    /// List of participant identifiers in the protocol.
    pub parties: Vec<u16>,
    /// Key share used for signing.
    pub key_share: KeyShare<Secp256k1>,
    /// Data to be signed.
    pub data_to_sign: DataToSign<Secp256k1>,
    /// Unique identifier for the signing operation.
    pub execution_id_bytes: Vec<u8>,
}

impl CggmpProtocol for SigningProtocol {
    type Msg = CggmpSigningMessage;
    type Output = CggmpSigningOutput;

    fn run(
        self,
        incoming: &Receiver<Incoming<Self::Msg>>,
        outgoing: &Sender<Vec<Outgoing<Self::Msg>>>,
    ) -> Option<Self::Output> {
        let execution_id: ExecutionId<'_> =
            ExecutionId::new(&self.execution_id_bytes);

        // Initialize a random number generator for the protocol execution.
        let mut random: OsRng = OsRng;

        // Initialize the CGGMP24 signing state machine with the provided
        // parameters.
        let state_machine: impl StateMachine<
            Msg = Self::Msg,
            Output = Result<Signature<Secp256k1>, impl Debug>,
        > = cggmp24::signing(
            execution_id,
            self.identifier,
            &self.parties,
            &self.key_share,
        )
        .sign_sync(&mut random, &self.data_to_sign);

        drive(state_machine, incoming, outgoing)
    }
}
