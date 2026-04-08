//! CGGMP24 ECDSA Secp256k1 controller-side auxiliary info generation protocol.
//!
//! Orchestrates the auxiliary generation session lifecycle across all
//! participant nodes: starts sessions in parallel (each node generates
//! Paillier primes concurrently), routes messages across rounds, and finalizes
//! all sessions to produce complete key shares in Vault.

use async_trait::async_trait;
use tonic::Status;

use crate::{
    proto::engine::v1::{
        Algorithm, FinalizeSessionResponse, RoundMessage, StartAuxiliaryGenerationSessionRequest, StartSessionResponse, finalize_session_response::FinalOutput
    },
    protocols::{
        cggmp24::controller::protocol::{
            Cggmp24ControllerProtocol,
            CggmpControllerProtocol,
        },
        protocol::Protocol,
        types::{
            AuxiliaryGenerationInit,
            ControllerAuxiliaryGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    transport::{errors::Errors, grpc::node_client::NodeIpcClient},
};

/// Protocol-specific data for CGGMP24 ECDSA Secp256k1 auxiliary generation.
pub struct AuxiliaryGenerationData {
    /// Algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique identifier for the key whose aux info is being generated.
    key_identifier: String,
    /// Total number of participants in the protocol.
    participants: u32,
}

/// Protocol descriptor implementing `CggmpControllerProtocol` for auxiliary
/// info generation.
pub struct AuxiliaryGenerationControllerDescriptor;

impl CggmpControllerProtocol for AuxiliaryGenerationControllerDescriptor {
    type Data = AuxiliaryGenerationData;

    fn participants(data: &Self::Data) -> u32 {
        data.participants
    }

    /// Start an auxiliary generation session on a single node.
    ///
    /// Sessions are started concurrently so that each node generates its
    /// Paillier primes simultaneously — reduces total wall time from
    /// O(n * prime_gen) to O(prime_gen).
    async fn start_session(
        data: &Self::Data,
        index: usize,
        node: &NodeIpcClient,
    ) -> Result<(String, Vec<RoundMessage>, Vec<u32>), Status> {
        let response: StartSessionResponse = node
            .start_auxiliary_generation(
                StartAuxiliaryGenerationSessionRequest {
                    key_identifier: data.key_identifier.clone(),
                    algorithm: data.algorithm.into(),
                    participants: data.participants,
                    identifier: index as u32,
                },
            )
            .await?;

        // Auxiliary generation has no signer set — return empty to skip
        // cross-node consistency verification.
        Ok((response.session_identifier, response.messages, Vec::new()))
    }

    /// Finalize all auxiliary generation sessions.
    ///
    /// Unlike key generation, auxiliary generation produces no public output —
    /// all key material is stored privately in Vault by each node. This
    /// method simply verifies that all sessions completed with the
    /// expected output variant.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any node returns an unexpected output
    ///   variant or no output is received.
    fn finalize_output(
        data: &Self::Data,
        responses: Vec<FinalizeSessionResponse>,
    ) -> Result<ProtocolOutput, Errors> {
        // Verify all nodes returned the expected AuxiliaryGeneration output —
        // key material is stored in Vault by each node, so no public output
        // needs to be extracted here.
        responses.into_iter().try_for_each(
            |response: FinalizeSessionResponse| match response.final_output {
                Some(FinalOutput::AuxiliaryGeneration(_)) => Ok(()),
                Some(other) => Err(Errors::InvalidMessage(format!(
                    "Unexpected finalize output variant: {:?}.",
                    other
                ))),
                None => Err(Errors::InvalidMessage(
                    "Node returned empty finalize output.".into(),
                )),
            },
        )?;

        Ok(ProtocolOutput::AuxiliaryGeneration {
            key_identifier: data.key_identifier.clone(),
            key_share: None,
        })
    }
}

/// CGGMP24 ECDSA Secp256k1 controller-side auxiliary info generation protocol.
///
/// Drives the full auxiliary generation session lifecycle: starts sessions on
/// all nodes in parallel (allowing concurrent Paillier prime generation),
/// routes messages between participants across rounds, and finalizes all
/// sessions once every worker signals completion.
pub struct Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration(
    Cggmp24ControllerProtocol<AuxiliaryGenerationControllerDescriptor>,
);

impl Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration {
    /// Construct a new instance from the provided protocol initialization
    /// context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Initialization context, must be
    ///   `AuxiliaryGeneration(Controller(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the variant does not match.
    ///
    /// # Returns
    /// * `Self` - Initialized instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerAuxiliaryGenerationInit = match protocol_init {
            ProtocolInit::AuxiliaryGeneration(
                AuxiliaryGenerationInit::Controller(init),
            ) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    auxiliary key generation."
                        .into(),
                ));
            },
        };

        Ok(Self(Cggmp24ControllerProtocol::new(
            AuxiliaryGenerationData {
                algorithm: init.common.algorithm,
                key_identifier: init.common.key_identifier,
                participants: init.common.participants,
            },
            init.nodes,
        )))
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration {
    fn algorithm(&self) -> Algorithm {
        self.0.data.algorithm
    }

    fn threshold(&self) -> u32 {
        // Aux gen requires all participants — threshold equals participants.
        self.0.data.participants
    }

    fn participants(&self) -> u32 {
        self.0.data.participants
    }

    fn current_round(&self) -> Round {
        self.0.round
    }

    /// Trigger protocol execution on the first call.
    ///
    /// The CGGMP24 controller drives the full session lifecycle internally —
    /// the engine calls `next_round` once to start execution, then `finalize`
    /// to retrieve the output. Subsequent calls return `Ok(None)`.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::Generic` - If any error occurs during protocol execution.
    async fn next_round(&mut self) -> Result<Option<RoundMessage>, Errors> {
        if self.0.aborted {
            return Err(Errors::Aborted("Protocol has been aborted.".into()));
        }

        if self.0.round != 0 {
            return Ok(None);
        }

        self.0.run().await?;

        Ok(None)
    }

    /// No-op — the CGGMP24 controller orchestrates all message routing
    /// internally via `run` and does not process individual inbound messages
    /// from the engine.
    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Consume and return the final protocol output.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If called before `next_round` has completed.
    ///
    /// # Returns
    /// * `ProtocolOutput::AuxiliaryGeneration` - Completion signal with the
    ///   scoped key identifier.
    async fn finalize(&mut self) -> Result<ProtocolOutput, Errors> {
        self.0.take_output().ok_or_else(|| {
            Errors::InvalidState(
                "Protocol output not available — next_round must complete \
                before finalize."
                    .into(),
            )
        })
    }

    fn abort(&mut self) {
        self.0.aborted = true;
    }
}
