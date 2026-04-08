//! CGGMP24 ECDSA Secp256k1 key generation protocol implementation.

use std::{num::TryFromIntError, sync::Arc};

use async_trait::async_trait;
use rkyv::{rancor::Error as RkyvError, to_bytes};
use serde_json::{Error, to_vec};
use tokio::sync::Notify;

use crate::{
    proto::engine::v1::{Algorithm, RoundMessage},
    protocols::{
        cggmp24::{
            node::{
                keys::worker::{
                    CggmpKeyGenerationMessage,
                    CggmpKeyGenerationOutput,
                    KeyGenerationProtocol,
                },
                protocol::{Cggmp24NodeProtocol, CggmpNodeProtocol},
            },
            stored_key::Cggmp24StoredKey,
        },
        protocol::Protocol,
        types::{
            KeyGenerationInit,
            NodeKeyGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    secrets::{secret::Secret, vault::key_path::scoped},
    transport::errors::Errors,
};

/// Protocol-specific data for CGGMP24 ECDSA Secp256k1 key generation.
pub struct KeyGenerationData {
    /// Threshold number of participants required to complete the protocol.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// Unique identifier for the key being generated — used to scope Vault
    /// paths and associate output with the correct key.
    key_identifier: String,
    /// This participant's identifier as u32 — used to scope the Vault path
    /// and populate the stored key identifier.
    identifier_u32: u32,
}

/// Protocol descriptor implementing `CggmpNodeProtocol` for key generation.
pub struct KeyGenerationProtocolDescriptor;

impl CggmpNodeProtocol for KeyGenerationProtocolDescriptor {
    type Message = CggmpKeyGenerationMessage;
    type Output = CggmpKeyGenerationOutput;
    type Data = KeyGenerationData;

    fn algorithm() -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    fn threshold(data: &Self::Data) -> u32 {
        data.threshold
    }

    fn participants(data: &Self::Data) -> u32 {
        data.participants
    }

    /// Finalize the protocol — serialize the incomplete key share and store
    /// it in Vault under the scoped key identifier.
    ///
    /// # Arguments
    /// * `data` (`&mut Self::Data`) - Protocol-specific data containing
    ///   identifiers and parameters.
    /// * `output` (`Self::Output`) - The output produced by the worker upon
    ///   protocol completion, containing the incomplete key share and public
    ///   key information.
    ///
    /// # Errors
    /// * `Errors::InvalidKeyShare` - If serialization of the stored key fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::KeyGeneration` - The key generation output
    ///   containing the key share and public key information.
    fn finalize(
        data: &mut Self::Data,
        output: Self::Output,
    ) -> Result<ProtocolOutput, Errors> {
        let incomplete_key_share: CggmpKeyGenerationOutput = output;

        // Serialize the incomplete key share to JSON for storage —
        // combined with AuxInfo during auxiliary generation to produce a full
        // KeyShare. Cloned before moving into Cggmp24StoredKey so the
        // same bytes can be reused as the public_key_package without
        // re-serializing.
        let json: Vec<u8> =
            to_vec(&incomplete_key_share).map_err(|error: Error| {
                Errors::InvalidKeyShare(error.to_string())
            })?;

        let public_key_package: Vec<u8> = json.clone();

        // Wrap the JSON blob in a Cggmp24StoredKey and serialize to rkyv
        // bytes for Vault storage.
        let stored: Cggmp24StoredKey = Cggmp24StoredKey {
            identifier: data.identifier_u32 as u16,
            key_share_json: json,
        };

        let blob: Vec<u8> = to_bytes::<RkyvError>(&stored)
            .map_err(|error: RkyvError| {
                Errors::InvalidKeyShare(error.to_string())
            })?
            .into_vec();

        // Extract the compressed SEC1-encoded public key bytes.
        let public_key: Vec<u8> = incomplete_key_share
            .shared_public_key
            .to_bytes(true)
            .as_ref()
            .to_vec();

        // Scope the key share under "<key_id>/<participant_id>" to avoid
        // Vault collisions across participants.
        Ok(ProtocolOutput::KeyGeneration {
            key_identifier: scoped(&data.key_identifier, data.identifier_u32),
            key_share: Some(Secret::new(blob)),
            public_key,
            // Reuse the JSON bytes serialized above — avoids a second
            // call to to_vec for the same data.
            public_key_package,
        })
    }
}

/// CGGMP24 ECDSA Secp256k1 node key generation protocol instance.
pub struct Cggmp24EcdsaSecp256k1NodeKeyGeneration(
    Cggmp24NodeProtocol<KeyGenerationProtocolDescriptor>,
);

impl Cggmp24EcdsaSecp256k1NodeKeyGeneration {
    /// Creates a new instance of the CGGMP24 ECDSA Secp256k1 node key
    /// generation protocol from the given protocol initialization parameters.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization
    ///   parameters, expected to be `ProtocolInit::KeyGeneration(Node(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    ///
    /// # Returns
    /// * `Self` - The initialized protocol instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        // Unpack the node key generation init — reject any other protocol
        // init.
        let init: NodeKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Node(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    node key generation."
                        .into(),
                ));
            },
        };

        // Convert identifiers to u16 — required by the CGGMP24 state machine.
        let identifier: u16 =
            init.identifier.try_into().map_err(|error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            })?;

        let participants_u16: u16 =
            init.common.participants.try_into().map_err(
                |error: TryFromIntError| {
                    Errors::InvalidProtocolInit(error.to_string())
                },
            )?;

        let threshold_u16: u16 = init.common.threshold.try_into().map_err(
            |error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            },
        )?;

        // Use the key identifier as the execution identifier — unique per key
        // generation session, scoped to avoid collision with auxiliary
        // generation and signing executions via their own prefixes.
        let execution_identifier_bytes: Vec<u8> =
            init.common.key_identifier.clone().into_bytes();

        let data: KeyGenerationData = KeyGenerationData {
            threshold: init.common.threshold,
            participants: init.common.participants,
            key_identifier: init.common.key_identifier,
            identifier_u32: init.identifier,
        };

        Ok(Self(Cggmp24NodeProtocol::new(
            data,
            init.identifier,
            // Spawn the worker thread — it will drive the CGGMP24 state
            // machine to completion and signal via done_transmitter when
            // finished.
            KeyGenerationProtocol {
                identifier,
                participants: participants_u16,
                threshold: threshold_u16,
                execution_identifier_bytes,
            },
        )))
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1NodeKeyGeneration {
    fn algorithm(&self) -> Algorithm {
        KeyGenerationProtocolDescriptor::algorithm()
    }

    fn threshold(&self) -> u32 {
        KeyGenerationProtocolDescriptor::threshold(&self.0.data)
    }

    fn participants(&self) -> u32 {
        KeyGenerationProtocolDescriptor::participants(&self.0.data)
    }

    fn current_round(&self) -> Round {
        self.0.message_identifier as Round
    }

    fn is_done(&self) -> bool {
        self.0.is_done()
    }

    /// Drain pending outgoing messages and return the next one if available.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidMessage` - If a message cannot be wrapped.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.0.aborted {
            return Err(Errors::Aborted("Protocol aborted.".into()));
        }

        // Drain any outgoing messages or completion signals produced by the
        // worker asynchronously since the last call.
        self.0.drain_pending()?;

        Ok(self.0.pending_messages.pop_front())
    }

    /// Handle an incoming key generation protocol message and deliver it to
    /// the worker.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If the message cannot be decoded or
    ///   delivered to the worker.
    async fn handle_message(
        &mut self,
        message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        // Deliver the message to the worker — P2P if a recipient is set,
        // broadcast otherwise. The worker will process it, advance the state
        // machine, and produce outgoing messages or a completion signal.
        self.0.deliver_message(message)?;

        Ok(None)
    }

    /// Consume and return the final key generation output.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidKeyShare` - If serialization of the stored key fails.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        if self.0.aborted {
            return Err(Errors::Aborted("Protocol aborted.".into()));
        }

        self.0.finalize_inner()
    }

    fn abort(&mut self) {
        self.0.aborted = true;
        self.0.abort_worker();
    }

    fn activity_notify(&self) -> Option<Arc<Notify>> {
        Some(self.0.activity_notify())
    }
}
