//! CGGMP24 ECDSA Secp256k1 controller-side signing protocol implementation.

use async_trait::async_trait;
use tonic::Status;

use crate::{
    proto::engine::v1::{
        FinalizeSessionResponse,
        RoundMessage,
        StartSessionResponse,
        StartSigningSessionRequest,
        finalize_session_response::FinalOutput,
        signature_result::FinalSignature,
    },
    protocols::{
        algorithm::Algorithm,
        cggmp24::controller::protocol::{
            Cggmp24ControllerProtocol,
            CggmpControllerProtocol,
        },
        protocol::Protocol,
        types::{
            ControllerSigningInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
            SigningInit,
        },
    },
    secrets::vault::key_path::scoped,
    transport::{errors::Errors, grpc::node_client::NodeIpcClient},
};

/// Protocol-specific data for CGGMP24 ECDSA Secp256k1 signing.
pub struct SigningData {
    /// Algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique identifier for the key being signed with.
    key_identifier: String,
    /// Threshold number of participants required to complete the protocol.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
    /// Message to be signed.
    message: Vec<u8>,
}

/// Protocol descriptor implementing `CggmpControllerProtocol` for signing.
pub struct SigningControllerDescriptor;

impl CggmpControllerProtocol for SigningControllerDescriptor {
    type Data = SigningData;

    fn participants(data: &Self::Data) -> u32 {
        data.participants
    }

    /// Start a signing session on a single node.
    ///
    /// Each node receives a scoped key identifier
    /// (`<key_id>/<participant_index>`) to locate its key share in Vault.
    /// The node's reported signer set is returned so `start_sessions` can
    /// verify cross-node consistency.
    async fn start_session(
        data: &Self::Data,
        index: usize,
        node: &NodeIpcClient,
    ) -> Result<(String, Vec<RoundMessage>, Vec<u32>), Status> {
        let response: StartSessionResponse = node
            .start_signing(StartSigningSessionRequest {
                // Scope the key identifier per participant to locate the
                // correct key share in Vault.
                key_identifier: scoped(&data.key_identifier, index as u32),
                algorithm: data.algorithm.as_str().to_string(),
                threshold: data.threshold,
                participants: data.participants,
                message: data.message.clone(),
            })
            .await?;

        Ok((
            response.session_identifier,
            response.messages,
            response.signer_set,
        ))
    }

    /// Finalize all signing sessions.
    ///
    /// All nodes should produce the same signature — only the first is used
    /// since CGGMP24 guarantees deterministic output across participants.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any node returns an unexpected output.
    fn finalize_output(
        _data: &Self::Data,
        responses: Vec<FinalizeSessionResponse>,
    ) -> Result<ProtocolOutput, Errors> {
        // All nodes produce the same output — take the first valid signature.
        let final_output: FinalOutput = responses
            .into_iter()
            .find_map(|response: FinalizeSessionResponse| {
                response.final_output
            })
            .ok_or_else(|| {
                Errors::InvalidMessage("No finalize output received.".into())
            })?;

        match final_output {
            FinalOutput::Signature(result) => {
                let signature: FinalSignature =
                    result.final_signature.ok_or_else(|| {
                        Errors::InvalidMessage(
                            "Node returned signing output without final \
                            signature."
                                .into(),
                        )
                    })?;
                Ok(ProtocolOutput::Signature(signature))
            },
            other => Err(Errors::InvalidMessage(format!(
                "Unexpected finalize output variant: {:?}.",
                other
            ))),
        }
    }
}

/// CGGMP24 ECDSA Secp256k1 controller-side signing protocol.
///
/// Drives the full signing session lifecycle: starts sessions on all nodes in
/// parallel, routes messages between participants across rounds, and finalizes
/// all sessions once every worker signals completion.
pub struct Cggmp24EcdsaSecp256k1ControllerSigning(
    Cggmp24ControllerProtocol<SigningControllerDescriptor>,
);

impl Cggmp24EcdsaSecp256k1ControllerSigning {
    /// Construct a new instance from the provided protocol initialization
    /// context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Initialization context, must be
    ///   `Signing(Controller(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the variant does not match.
    ///
    /// # Returns
    /// * `Self` - Initialized instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerSigningInit = match protocol_init {
            ProtocolInit::Signing(SigningInit::Controller(init)) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    controller signing."
                        .into(),
                ));
            },
        };

        Ok(Self(Cggmp24ControllerProtocol::new(
            SigningData {
                algorithm: init.common.algorithm,
                key_identifier: init.common.key_identifier,
                threshold: init.common.threshold,
                participants: init.common.participants,
                message: init.common.message,
            },
            init.nodes,
        )))
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1ControllerSigning {
    fn algorithm(&self) -> Algorithm {
        self.0.data.algorithm
    }

    fn threshold(&self) -> u32 {
        self.0.data.threshold
    }

    fn participants(&self) -> u32 {
        self.0.data.participants
    }

    fn current_round(&self) -> Round {
        self.0.round
    }

    /// Drive the full signing protocol to completion.
    ///
    /// Called once at round 0 — orchestrates all node communication
    /// internally via `run`. Subsequent calls return `Ok(None)`.
    ///
    /// # Errors
    /// * `Errors::Aborted` - If the protocol has been aborted.
    /// * `Errors::Generic` - If any gRPC call fails during execution.
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

    /// No-op — the controller signing protocol is fully orchestrated within
    /// `next_round` and does not handle individual messages.
    async fn handle_message(
        &mut self,
        _message: RoundMessage,
    ) -> Result<Option<RoundMessage>, Errors> {
        Ok(None)
    }

    /// Return the final signing output produced by `next_round`.
    ///
    /// Consumes the output — calling `finalize` twice will return an error.
    ///
    /// # Errors
    /// * `Errors::InvalidState` - If `next_round` has not completed yet.
    ///
    /// # Returns
    /// * `ProtocolOutput` - The final aggregated signature.
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
