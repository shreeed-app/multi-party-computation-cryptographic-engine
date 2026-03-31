//! CGGMP24 controller-side key generation protocol implementation.

use async_trait::async_trait;
use tonic::Status;

use crate::{
    proto::signer::v1::{
        FinalizeSessionResponse,
        KeyGenerationResult,
        RoundMessage,
        StartKeyGenerationSessionRequest,
        StartSessionResponse,
        finalize_session_response::FinalOutput,
    },
    protocols::{
        algorithm::Algorithm,
        cggmp24::controller::protocol::{
            Cggmp24ControllerProtocol,
            CggmpControllerProtocol,
        },
        protocol::Protocol,
        types::{
            ControllerKeyGenerationInit,
            KeyGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            Round,
        },
    },
    transport::{errors::Errors, grpc::node_client::NodeIpcClient},
};

/// Protocol-specific data for CGGMP24 ECDSA Secp256k1 key generation.
pub struct KeyGenerationData {
    /// Algorithm identifier for this protocol instance.
    algorithm: Algorithm,
    /// Unique identifier for the key being generated — used to scope Vault
    /// paths and associate output with the correct key.
    key_identifier: String,
    /// Threshold number of participants required to complete the protocol.
    threshold: u32,
    /// Total number of participants in the protocol.
    participants: u32,
}

/// Protocol descriptor implementing `CggmpControllerProtocol` for key
/// generation.
pub struct KeyGenerationControllerDescriptor;

impl CggmpControllerProtocol for KeyGenerationControllerDescriptor {
    type Data = KeyGenerationData;

    fn participants(data: &Self::Data) -> u32 {
        data.participants
    }

    /// Start a key generation session on a single node.
    ///
    /// Each node receives its participant index as `identifier` so it can
    /// scope its key share in Vault under `<key_id>/<identifier>`.
    async fn start_session(
        data: &Self::Data,
        index: usize,
        node: &NodeIpcClient,
    ) -> Result<(String, Vec<RoundMessage>, Vec<u32>), Status> {
        let response: StartSessionResponse = node
            .start_key_generation(StartKeyGenerationSessionRequest {
                key_identifier: data.key_identifier.clone(),
                algorithm: data.algorithm.as_str().to_string(),
                threshold: data.threshold,
                participants: data.participants,
                identifier: index as u32,
            })
            .await?;

        // Key generation has no signer set — return empty to skip
        // cross-node consistency verification.
        Ok((response.session_identifier, response.messages, Vec::new()))
    }

    /// Finalize all key generation sessions.
    ///
    /// Collects results from all nodes and verifies that every node produced
    /// the same public key before accepting the output. A mismatch indicates a
    /// protocol execution fault and is surfaced as an error rather than
    /// silently accepting a potentially incorrect key.
    ///
    /// # Errors
    /// * `Errors::InvalidMessage` - If any node returns an unexpected output
    ///   variant or no output is received.
    /// * `Errors::InvalidKeyShare` - If nodes produced inconsistent public
    ///   keys.
    fn finalize_output(
        data: &Self::Data,
        responses: Vec<FinalizeSessionResponse>,
    ) -> Result<ProtocolOutput, Errors> {
        // Collect all KeyGeneration results — every responding node must
        // return this variant.
        let results: Vec<KeyGenerationResult> = responses
            .into_iter()
            .map(|response: FinalizeSessionResponse| {
                match response.final_output {
                    Some(FinalOutput::KeyGeneration(result)) => Ok(result),
                    Some(other) => Err(Errors::InvalidMessage(format!(
                        "Unexpected finalize output variant: {:?}",
                        other
                    ))),
                    None => Err(Errors::InvalidMessage(
                        "Node returned empty finalize output.".into(),
                    )),
                }
            })
            .collect::<Result<Vec<KeyGenerationResult>, Errors>>()?;

        let first: &KeyGenerationResult =
            results.first().ok_or_else(|| {
                Errors::InvalidMessage("No finalize output received.".into())
            })?;

        // Verify all nodes agree on the public key — divergence indicates a
        // bug in the protocol execution or a misconfigured node.
        if !results.iter().all(|result: &KeyGenerationResult| {
            result.public_key == first.public_key
        }) {
            return Err(Errors::InvalidKeyShare(
                "Nodes produced inconsistent public keys — protocol \
                execution may be corrupt."
                    .into(),
            ));
        }

        Ok(ProtocolOutput::KeyGeneration {
            key_identifier: data.key_identifier.clone(),
            key_share: None,
            public_key: first.public_key.clone(),
            public_key_package: first.public_key_package.clone(),
        })
    }
}

/// CGGMP24 ECDSA Secp256k1 controller-side key generation protocol.
///
/// Drives the full DKG session lifecycle: starts sessions on all nodes in
/// parallel, routes messages between participants across rounds, and finalizes
/// all sessions once every worker signals completion.
pub struct Cggmp24EcdsaSecp256k1ControllerKeyGeneration(
    Cggmp24ControllerProtocol<KeyGenerationControllerDescriptor>,
);

impl Cggmp24EcdsaSecp256k1ControllerKeyGeneration {
    /// Construct a new instance from the provided protocol initialization
    /// context.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Initialization context, must be
    ///   `KeyGeneration(Controller(...))`.
    ///
    /// # Errors
    /// * `Errors::InvalidProtocolInit` - If the variant does not match.
    ///
    /// # Returns
    /// * `Self` - Initialized instance ready to run.
    pub fn try_new(protocol_init: ProtocolInit) -> Result<Self, Errors> {
        let init: ControllerKeyGenerationInit = match protocol_init {
            ProtocolInit::KeyGeneration(KeyGenerationInit::Controller(
                init,
            )) => init,
            _ => {
                return Err(Errors::InvalidProtocolInit(
                    "Invalid protocol initialization context for CGGMP24 \
                    controller key generation."
                        .into(),
                ));
            },
        };

        Ok(Self(Cggmp24ControllerProtocol::new(
            KeyGenerationData {
                algorithm: init.common.algorithm,
                key_identifier: init.common.key_identifier,
                threshold: init.common.threshold,
                participants: init.common.participants,
            },
            init.nodes,
        )))
    }
}

#[async_trait]
impl Protocol for Cggmp24EcdsaSecp256k1ControllerKeyGeneration {
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
    /// * `ProtocolOutput` - Key generation output containing the public key
    ///   and public key package.
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
