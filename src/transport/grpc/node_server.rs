//! IPC server for the signing engine.

use std::str::FromStr;

use strum::ParseError;
use tonic::{Request, Response, Status};
use tracing::{field::Empty, instrument};

use crate::{
    auth::session::identifier::SessionIdentifier,
    proto::engine::v1::{
        AbortSessionRequest,
        AbortSessionResponse,
        AuxiliaryGenerationResult,
        CollectRoundRequest,
        CollectRoundResponse,
        FinalizeSessionRequest,
        FinalizeSessionResponse,
        KeyGenerationResult,
        RoundMessage,
        SignatureResult,
        StartAuxiliaryGenerationSessionRequest,
        StartKeyGenerationSessionRequest,
        StartSessionResponse,
        StartSigningSessionRequest,
        SubmitRoundRequest,
        SubmitRoundResponse,
        finalize_session_response::FinalOutput,
        node_server::Node,
    },
    protocols::{
        algorithm::Algorithm,
        cggmp24::node::tasks::ecdsa_secp256k1::compute_parties,
        types::{
            AuxiliaryGenerationInit,
            DefaultAuxiliaryGenerationInit,
            DefaultKeyGenerationInit,
            DefaultSigningInit,
            KeyGenerationInit,
            NodeAuxiliaryGenerationInit,
            NodeKeyGenerationInit,
            NodeSigningInit,
            ProtocolInit,
            ProtocolOutput,
            SigningInit,
        },
    },
    secrets::{
        types::KeyShare,
        vault::{
            api::VaultProvider,
            key_path::{base, scoped},
        },
    },
    service::api::EngineApi,
    transport::errors::Errors,
};

/// gRPC IPC server exposing the signing engine.
pub struct NodeIpcServer<E: EngineApi, V: VaultProvider> {
    /// Signing engine (business logic).
    pub engine: E,
    /// Vault provider for key shares.
    pub vault: V,
}

impl<E: EngineApi, V: VaultProvider> NodeIpcServer<E, V> {
    /// Create a new IPC server.
    ///
    /// # Arguments
    /// * `engine` (`E`) - Signing engine instance.
    /// * `vault` (`V`) - Vault provider for key shares.
    ///
    /// # Returns
    /// * `Self` - New IPC server instance.
    pub fn new(engine: E, vault: V) -> Self {
        Self { engine, vault }
    }
}

#[tonic::async_trait]
impl<
    E: EngineApi + Send + Sync + 'static,
    V: VaultProvider + Send + Sync + 'static,
> Node for NodeIpcServer<E, V>
{
    /// Start a new signing session.
    ///
    /// # Arguments
    /// * `request` (`Request<StartSigningSessionRequest>`) - Incoming gRPC
    ///   request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails or session creation fails.
    ///
    /// # Returns
    /// * `Result<Response<StartSessionResponse>, Status>` - gRPC response or
    ///   error.
    #[instrument(skip(self, request), fields(
        key_identifier = %request.get_ref().key_identifier,
        session = Empty
    ))]
    async fn start_signing_session(
        &self,
        request: Request<StartSigningSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        tracing::debug!(
            "Starting signing session for key {}.",
            request.get_ref().key_identifier
        );

        let request: &StartSigningSessionRequest = request.get_ref();

        let algorithm: Algorithm =
            match Algorithm::from_str(&request.algorithm) {
                Ok(algorithm) => algorithm,
                Err(error) => {
                    return Err(Errors::UnsupportedAlgorithm(format!(
                        "Failed to parse algorithm: {}",
                        error
                    ))
                    .into());
                },
            };

        // Extract the base key identifier by removing the per-participant
        // suffix appended by the controller (e.g. "my-key/0" → "my-key").
        // This base key is used for signer set derivation and as the
        // key_identifier in the protocol init.
        let base_key_identifier: &str = base(&request.key_identifier);

        let init: ProtocolInit =
            ProtocolInit::Signing(SigningInit::Node(NodeSigningInit {
                common: DefaultSigningInit {
                    key_identifier: base_key_identifier.into(),
                    algorithm,
                    threshold: request.threshold,
                    participants: request.participants,
                    message: request.message.clone(),
                },
                key_share: self
                    .vault
                    .get_key_share(&request.key_identifier.clone())
                    .await?,
            }));

        let (session_identifier, round_message): (
            SessionIdentifier,
            Vec<RoundMessage>,
        ) = self.engine.start_session(init).await?;

        // For CGGMP24 signing, compute the signer set so the controller can
        // verify all nodes independently derived the same participants.
        let signer_set: Vec<u32> = if algorithm
            == Algorithm::Cggmp24EcdsaSecp256k1
        {
            compute_parties(
                base_key_identifier,
                request.threshold,
                request.participants,
            )?
            .into_iter()
            .map(|participant_identifier: u16| participant_identifier as u32)
            .collect()
        } else {
            Vec::new()
        };

        Ok(Response::new(StartSessionResponse {
            session_identifier: session_identifier.to_string(),
            messages: round_message,
            signer_set,
        }))
    }

    /// Start a new key generation session.
    ///
    /// # Arguments
    /// * `request` (`Request<StartKeyGenerationSessionRequest>`) - Incoming
    ///   gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails or session creation fails.
    ///
    /// # Returns
    /// * `Result<Response<StartSessionResponse>, Status>` - gRPC response or
    ///   error.
    #[instrument(skip(self, request), fields(
        key_identifier = %request.get_ref().key_identifier,
        session = Empty
    ))]
    async fn start_key_generation_session(
        &self,
        request: Request<StartKeyGenerationSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        tracing::debug!(
            "Starting key generation session for key {}.",
            request.get_ref().key_identifier
        );

        let request: &StartKeyGenerationSessionRequest = request.get_ref();

        let algorithm: Algorithm = Algorithm::from_str(&request.algorithm)
            .map_err(|error: ParseError| {
                Errors::UnsupportedAlgorithm(format!(
                    "Failed to parse algorithm: {}",
                    error
                ))
            })?;

        let init: ProtocolInit = ProtocolInit::KeyGeneration(
            KeyGenerationInit::Node(NodeKeyGenerationInit {
                common: DefaultKeyGenerationInit {
                    key_identifier: request.key_identifier.clone(),
                    algorithm,
                    threshold: request.threshold,
                    participants: request.participants,
                },
                identifier: request.identifier,
            }),
        );

        let (session_identifier, round_message): (
            SessionIdentifier,
            Vec<RoundMessage>,
        ) = self.engine.start_session(init).await?;

        Ok(Response::new(StartSessionResponse {
            session_identifier: session_identifier.to_string(),
            messages: round_message,
            signer_set: Vec::new(),
        }))
    }

    /// Start a new auxiliary generation session.
    ///
    /// # Arguments
    /// * `request` (`Request<StartAuxiliaryGenerationSessionRequest>`) -
    ///   Incoming gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails or session creation fails.
    ///
    /// # Returns
    /// * `Result<Response<StartSessionResponse>, Status>` - gRPC response or
    ///   error.
    #[instrument(skip(self, request), fields(
        key_identifier = %request.get_ref().key_identifier,
        session = Empty
    ))]
    async fn start_auxiliary_generation_session(
        &self,
        request: Request<StartAuxiliaryGenerationSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        tracing::debug!(
            "Starting auxiliary generation session for key {}.",
            request.get_ref().key_identifier
        );

        let request: &StartAuxiliaryGenerationSessionRequest =
            request.get_ref();

        let algorithm: Algorithm = Algorithm::from_str(&request.algorithm)
            .map_err(|error: ParseError| {
                Errors::UnsupportedAlgorithm(error.to_string())
            })?;

        // Retrieve the incomplete key share from vault using the key
        // identifier and the auxiliary identifier.
        let vault_key: String =
            scoped(&request.key_identifier, request.identifier);
        let incomplete_key_share: KeyShare =
            self.vault.get_key_share(&vault_key).await?;

        let init: ProtocolInit = ProtocolInit::AuxiliaryGeneration(
            AuxiliaryGenerationInit::Node(NodeAuxiliaryGenerationInit {
                common: DefaultAuxiliaryGenerationInit {
                    key_identifier: request.key_identifier.clone(),
                    algorithm,
                    participants: request.participants,
                },
                identifier: request.identifier,
                incomplete_key_share,
            }),
        );

        let (session_identifier, messages): (
            SessionIdentifier,
            Vec<RoundMessage>,
        ) = self.engine.start_session(init).await?;

        Ok(Response::new(StartSessionResponse {
            session_identifier: session_identifier.to_string(),
            messages,
            signer_set: Vec::new(),
        }))
    }

    /// Submit a round message for an existing session.
    ///
    /// # Arguments
    /// * `request` (`Request<SubmitRoundRequest>`) - Incoming gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails, session does not exist, round is
    ///   invalid, or protocol fails.
    ///
    /// # Returns
    /// * `Result<Response<SubmitRoundResponse>, Status>` - gRPC response or
    ///   error.
    #[instrument(skip(self, request))]
    async fn submit_round(
        &self,
        request: Request<SubmitRoundRequest>,
    ) -> Result<Response<SubmitRoundResponse>, Status> {
        tracing::debug!("Submitting round message for session.");

        let request: &SubmitRoundRequest = request.get_ref();

        let session_identifier: SessionIdentifier =
            match SessionIdentifier::parse(&request.session_identifier) {
                Some(id) => id,
                None => {
                    return Err(Errors::SessionNotFound(
                        request.session_identifier.clone(),
                    )
                    .into());
                },
            };

        let message: RoundMessage = RoundMessage {
            round: request.round,
            from: request.from,
            to: request.to,
            payload: request.payload.clone(),
        };

        let round_messages: Vec<RoundMessage> =
            self.engine.submit_round(session_identifier, message).await?;

        Ok(Response::new(SubmitRoundResponse { messages: round_messages }))
    }

    /// Collect round messages for the current round of a session.
    ///
    /// # Arguments
    /// * `request` (`Request<CollectRoundRequest>`) - Incoming gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails, session does not exist, or
    ///   protocol fails.
    ///
    /// # Returns
    /// * `Result<Response<CollectRoundResponse>, Status>` - gRPC response or
    ///   error.
    #[instrument(skip(self, request))]
    async fn collect_round(
        &self,
        request: Request<CollectRoundRequest>,
    ) -> Result<Response<CollectRoundResponse>, Status> {
        tracing::debug!(
            "Collecting round messages for session {}.",
            request.get_ref().session_identifier
        );

        let request: &CollectRoundRequest = request.get_ref();

        let session_identifier: SessionIdentifier =
            match SessionIdentifier::parse(&request.session_identifier) {
                Some(identifier) => identifier,
                None => {
                    return Err(Errors::SessionNotFound(
                        request.session_identifier.clone(),
                    )
                    .into());
                },
            };

        let (messages, done): (Vec<RoundMessage>, bool) =
            self.engine.collect_round(session_identifier).await?;

        Ok(Response::new(CollectRoundResponse { messages, done }))
    }

    /// Finalize a signing session and return the final signature.
    ///
    /// # Arguments
    /// * `request` (`Request<FinalizeSessionRequest>`) - Incoming gRPC
    ///   request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails or session is not in a final
    ///   state.
    ///
    /// # Returns
    /// * `Result<Response<FinalizeSessionResponse>, Status>` - gRPC response
    ///   or error.
    #[instrument(skip(self, request))]
    async fn finalize_session(
        &self,
        request: Request<FinalizeSessionRequest>,
    ) -> Result<Response<FinalizeSessionResponse>, Status> {
        tracing::debug!(
            "Finalizing session {}.",
            request.get_ref().session_identifier
        );

        let request: &FinalizeSessionRequest = request.get_ref();

        let session_identifier: SessionIdentifier =
            match SessionIdentifier::parse(&request.session_identifier) {
                Some(id) => id,
                None => {
                    return Err(Errors::SessionNotFound(
                        request.session_identifier.clone(),
                    )
                    .into());
                },
            };

        let output: ProtocolOutput =
            self.engine.finalize(session_identifier).await?;

        match output {
            // Signing output: return final signature to caller.
            ProtocolOutput::Signature(signature) => {
                Ok(Response::new(FinalizeSessionResponse {
                    final_output: Some(FinalOutput::Signature(
                        SignatureResult { final_signature: Some(signature) },
                    )),
                }))
            },

            // Key generation output: store key share in vault, and return
            // the public key to the caller.
            ProtocolOutput::KeyGeneration {
                key_identifier,
                key_share,
                public_key,
                public_key_package,
            } => {
                // Ensure key share is present in the output.
                let key_share: KeyShare = key_share.ok_or_else(|| {
                    Errors::InvalidState("Missing key share in output.".into())
                })?;

                // Store key share in vault in a blocking task.
                self.vault.store_key_share(&key_identifier, key_share).await?;

                Ok(Response::new(FinalizeSessionResponse {
                    final_output: Some(FinalOutput::KeyGeneration(
                        KeyGenerationResult { public_key, public_key_package },
                    )),
                }))
            },

            // Auxiliary generation output: store key share in vault, and
            // return success to the caller.
            ProtocolOutput::AuxiliaryGeneration {
                key_identifier,
                key_share,
            } => {
                let key_share: KeyShare = key_share.ok_or_else(|| {
                    Errors::InvalidState(
                        "Missing key share in auxiliary generation output."
                            .into(),
                    )
                })?;

                // Erase the incomplete key share from vault, and store the
                // complete key share under the same identifier.
                self.vault.store_key_share(&key_identifier, key_share).await?;

                Ok(Response::new(FinalizeSessionResponse {
                    final_output: Some(FinalOutput::AuxiliaryGeneration(
                        AuxiliaryGenerationResult {},
                    )),
                }))
            },
        }
    }

    /// Abort a signing session.
    ///
    /// # Arguments
    /// * `request` (`Request<AbortSessionRequest>`) - Incoming gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails or session does not exist.
    ///
    /// # Returns
    /// * `Result<Response<AbortSessionResponse>, Status>` - gRPC response or
    ///   error.
    #[instrument(skip(self, request))]
    async fn abort_session(
        &self,
        request: Request<AbortSessionRequest>,
    ) -> Result<Response<AbortSessionResponse>, Status> {
        tracing::debug!(
            "Aborting session {}.",
            request.get_ref().session_identifier
        );

        let request: &AbortSessionRequest = request.get_ref();

        let session_identifier: SessionIdentifier =
            match SessionIdentifier::parse(&request.session_identifier) {
                Some(identifier) => identifier,
                None => {
                    return Err(Errors::SessionNotFound(
                        request.session_identifier.clone(),
                    )
                    .into());
                },
            };

        self.engine.abort(session_identifier).await?;

        Ok(Response::new(AbortSessionResponse {}))
    }
}
