//! CGGMP24 ECDSA Secp256k1 auxiliary info generation node protocol.

use std::num::TryFromIntError;

use async_trait::async_trait;
use cggmp24::{
    KeyShare as CggmpKeyShare,
    generic_ec::curves::Secp256k1,
    key_share::{
        DirtyAuxInfo,
        DirtyIncompleteKeyShare,
        IncompleteKeyShare,
        InvalidKeyShare,
        Valid,
        ValidateError,
    },
};
use rkyv::{
    Archived,
    access,
    deserialize,
    rancor::Error as RkyvError,
    to_bytes,
};
use serde_json::{Error, from_slice, to_vec};

use crate::{
    proto::signer::v1::RoundMessage,
    protocols::{
        algorithm::Algorithm,
        cggmp24::{
            node::{
                keys::auxiliary::worker::{
                    AuxiliaryGenerationProtocol,
                    CggmpAuxiliaryGenerationMessage,
                    CggmpAuxiliaryGenerationOutput,
                },
                protocol::{Cggmp24NodeProtocol, CggmpNodeProtocol},
            },
            security_level::Cggmp24SecurityLevel,
            stored_key::{ArchivedCggmp24StoredKey, Cggmp24StoredKey},
        },
        protocol::Protocol,
        types::{
            AuxiliaryGenerationInit,
            NodeAuxiliaryGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    secrets::{secret::Secret, types::KeyShare, vault::key_path::scoped},
    transport::errors::Errors,
};

/// Protocol-specific data for CGGMP24 ECDSA Secp256k1 auxiliary generation.
pub struct AuxiliaryGenerationData {
    /// Total number of participants in the protocol.
    participants: u32,
    /// This participant's identifier as u32 — used to scope the Vault path.
    identifier_u32: u32,
    /// Unique key identifier — used to scope the Vault storage path.
    key_identifier: String,
    /// The incomplete key share produced by DKG — combined with AuxInfo
    /// in finalize() to produce the complete KeyShare.
    incomplete_key_share: KeyShare,
}

/// Protocol descriptor implementing `CggmpNodeProtocol` for auxiliary
/// info generation.
pub struct AuxiliaryGenerationProtocolDescriptor;

impl CggmpNodeProtocol for AuxiliaryGenerationProtocolDescriptor {
    type Message = CggmpAuxiliaryGenerationMessage;
    type Output = CggmpAuxiliaryGenerationOutput;
    type Data = AuxiliaryGenerationData;

    fn algorithm() -> Algorithm {
        Algorithm::Cggmp24EcdsaSecp256k1
    }

    fn threshold(data: &Self::Data) -> u32 {
        // Aux gen requires all participants — threshold equals participants.
        data.participants
    }

    fn participants(data: &Self::Data) -> u32 {
        data.participants
    }

    /// Finalize the auxiliary generation protocol — combine the
    /// `IncompleteKeyShare` with the generated `AuxInfo` to produce a
    /// complete `KeyShare` for Vault storage.
    ///
    /// # Errors
    /// * `Errors::InvalidKeyShare` - If any step of key assembly fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::AuxiliaryGeneration` - The complete key share blob
    ///   and scoped key identifier.
    fn finalize(
        data: &mut Self::Data,
        output: Self::Output,
    ) -> Result<ProtocolOutput, Errors> {
        let aux_info: CggmpAuxiliaryGenerationOutput = output;

        // Deserialize the IncompleteKeyShare from the Vault blob passed at
        // init — produced by the key generation protocol.
        let stored: Cggmp24StoredKey =
            data.incomplete_key_share.with_ref(|blob: &Vec<u8>| {
                let archived: &ArchivedCggmp24StoredKey =
                    access::<Archived<Cggmp24StoredKey>, RkyvError>(blob)
                        .map_err(|error: RkyvError| {
                            Errors::InvalidKeyShare(error.to_string())
                        })?;

                deserialize::<Cggmp24StoredKey, RkyvError>(archived).map_err(
                    |error: RkyvError| {
                        Errors::InvalidKeyShare(error.to_string())
                    },
                )
            })?;

        let incomplete: IncompleteKeyShare<Secp256k1> =
            from_slice(&stored.key_share_json).map_err(|error: Error| {
                Errors::InvalidKeyShare(error.to_string())
            })?;

        // Combine IncompleteKeyShare + AuxInfo → complete KeyShare.
        let key_share: CggmpKeyShare<Secp256k1, Cggmp24SecurityLevel> =
            CggmpKeyShare::from_parts((incomplete, aux_info)).map_err(
                |error: ValidateError<
                    (
                        Valid<DirtyIncompleteKeyShare<Secp256k1>>,
                        Valid<DirtyAuxInfo<Cggmp24SecurityLevel>>,
                    ),
                    InvalidKeyShare,
                >| Errors::InvalidKeyShare(error.to_string()),
            )?;

        // Serialize the complete KeyShare to JSON and wrap in a
        // Cggmp24StoredKey for rkyv Vault storage.
        let new_stored: Cggmp24StoredKey = Cggmp24StoredKey {
            identifier: data.identifier_u32 as u16,
            key_share_json: to_vec(&key_share).map_err(|error: Error| {
                Errors::InvalidKeyShare(error.to_string())
            })?,
        };

        let blob: Vec<u8> = to_bytes::<RkyvError>(&new_stored)
            .map_err(|error: RkyvError| {
                Errors::InvalidKeyShare(error.to_string())
            })?
            .into_vec();

        // Scope the key share under "<key_id>/<participant_id>" to avoid
        // Vault collisions across participants.
        Ok(ProtocolOutput::AuxiliaryGeneration {
            key_identifier: scoped(&data.key_identifier, data.identifier_u32),
            key_share: Some(Secret::new(blob)),
        })
    }
}

/// CGGMP24 ECDSA Secp256k1 auxiliary info generation node protocol instance.
///
/// Runs the auxiliary generation MPC protocol to produce Paillier moduli and
/// Pedersen parameters for each participant. On completion, combines the
/// `IncompleteKeyShare` from DKG with the generated `AuxInfo` to produce
/// a complete `KeyShare` stored in Vault.
pub struct Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration(
    Cggmp24NodeProtocol<AuxiliaryGenerationProtocolDescriptor>,
);

impl Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration {
    /// Creates a new CGGMP24 ECDSA Secp256k1 auxiliary generation protocol
    /// instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization
    ///   parameters, expected to be
    ///   `ProtocolInit::AuxiliaryGeneration(Node(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the init context is invalid.
    ///
    /// # Returns
    /// * `Self` - The initialized protocol instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        // Unpack the node auxiliary generation init — reject any other
        // protocol init.
        let init: NodeAuxiliaryGenerationInit = match protocol_init {
            ProtocolInit::AuxiliaryGeneration(
                AuxiliaryGenerationInit::Node(init),
            ) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    node auxiliary generation."
                        .into(),
                ));
            },
        };

        // Convert identifiers to u16 — required by the CGGMP24 state machine.
        let identifier: u16 =
            init.identifier.try_into().map_err(|error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            })?;

        let participants: u16 = init.common.participants.try_into().map_err(
            |error: TryFromIntError| {
                Errors::InvalidProtocolInit(error.to_string())
            },
        )?;

        // Prefix the execution identifier to avoid collisions with key
        // generation and signing executions sharing the same key
        // identifier.
        let execution_identifier_bytes: Vec<u8> =
            format!("auxiliary:{}", init.common.key_identifier).into_bytes();

        let data: AuxiliaryGenerationData = AuxiliaryGenerationData {
            participants: init.common.participants,
            identifier_u32: init.identifier,
            key_identifier: init.common.key_identifier,
            incomplete_key_share: init.incomplete_key_share,
        };

        Ok(Self(Cggmp24NodeProtocol::new(
            data,
            init.identifier,
            // Spawn the worker thread — it will drive the CGGMP24 auxiliary
            // generation state machine to completion and signal via
            // done_transmitter when finished.
            AuxiliaryGenerationProtocol {
                identifier,
                participants,
                execution_identifier_bytes,
            },
        )))
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration {
    fn algorithm(&self) -> Algorithm {
        AuxiliaryGenerationProtocolDescriptor::algorithm()
    }

    fn threshold(&self) -> u32 {
        AuxiliaryGenerationProtocolDescriptor::threshold(&self.0.data)
    }

    fn participants(&self) -> u32 {
        AuxiliaryGenerationProtocolDescriptor::participants(&self.0.data)
    }

    fn current_round(&self) -> Round {
        self.0.message_identifier as Round
    }

    fn is_done(&self) -> bool {
        self.0.is_done()
    }

    /// Handle an incoming auxiliary generation protocol message and deliver it
    /// to the worker.
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

    /// Finalize the auxiliary generation protocol — combine the
    /// `IncompleteKeyShare` with the generated `AuxInfo` to produce a
    /// complete `KeyShare` for Vault storage.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::InvalidKeyShare` - If any step of key assembly fails.
    ///
    /// # Returns
    /// * `ProtocolOutput::AuxiliaryGeneration` - The complete key share blob
    ///   and scoped key identifier.
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
}
