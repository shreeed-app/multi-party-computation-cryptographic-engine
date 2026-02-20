//! IPC server for the signing engine.

use std::str::FromStr;

use tonic::{Request, Response, Status};
use tracing::{field::Empty, instrument};

use crate::{
    auth::session::identifier::SessionId,
    proto::signer::v1::{
        AbortSessionRequest,
        AbortSessionResponse,
        FinalizeSessionRequest,
        FinalizeSessionResponse,
        KeyGenerationResult,
        SignatureResult,
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
        types::{
            DefaultKeyGenerationInit,
            DefaultSigningInit,
            KeyGenerationInit,
            NodeKeyGenerationInit,
            NodeSigningInit,
            ProtocolInit,
            ProtocolOutput,
            RoundMessage,
            SigningInit,
        },
    },
    secrets::{types::KeyShare, vault::api::VaultProvider},
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
        key_id = %request.get_ref().key_id,
        session = Empty
    ))]
    async fn start_signing_session(
        &self,
        request: Request<StartSigningSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        let request: &StartSigningSessionRequest = request.get_ref();

        // Retrieve key share from vault in a blocking task.
        let key_id: String = request.key_id.clone();

        let key_share: KeyShare = self.vault.get_key_share(&key_id).await?;

        let algorithm: Algorithm =
            match Algorithm::from_str(&request.algorithm) {
                Ok(algorithm) => algorithm,
                Err(_) => {
                    return Err(Errors::UnsupportedAlgorithm(
                        request.algorithm.clone(),
                    )
                    .into());
                },
            };

        let init: ProtocolInit =
            ProtocolInit::Signing(SigningInit::Node(NodeSigningInit {
                common: DefaultSigningInit {
                    key_id: request.key_id.clone(),
                    algorithm,
                    threshold: request.threshold,
                    participants: request.participants,
                    message: request.message.clone(),
                },
                key_share,
            }));

        let (session_id, round_message): (SessionId, RoundMessage) =
            self.engine.start_session(init).await?;

        Ok(Response::new(StartSessionResponse {
            session_id: session_id.to_string(),
            round: round_message.round,
            payload: round_message.payload,
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
        key_id = %request.get_ref().key_id,
        session = Empty
    ))]
    async fn start_key_generation_session(
        &self,
        request: Request<StartKeyGenerationSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        let request: &StartKeyGenerationSessionRequest = request.get_ref();

        let algorithm: Algorithm = Algorithm::from_str(&request.algorithm)
            .map_err(|_| {
                Errors::UnsupportedAlgorithm(request.algorithm.clone())
            })?;

        let init: ProtocolInit = ProtocolInit::KeyGeneration(
            KeyGenerationInit::Node(NodeKeyGenerationInit {
                common: DefaultKeyGenerationInit {
                    key_id: request.key_id.clone(),
                    algorithm,
                    threshold: request.threshold,
                    participants: request.participants,
                },
                identifier: request.identifier,
            }),
        );

        let (session_id, round_message): (SessionId, RoundMessage) =
            self.engine.start_session(init).await?;

        Ok(Response::new(StartSessionResponse {
            session_id: session_id.to_string(),
            round: round_message.round,
            payload: round_message.payload,
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
        let request: &SubmitRoundRequest = request.get_ref();

        let session_id: SessionId = match SessionId::parse(&request.session_id)
        {
            Some(id) => id,
            None => {
                return Err(Errors::SessionNotFound(
                    request.session_id.clone(),
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
        let round_message: RoundMessage =
            self.engine.submit_round(session_id, message).await?;

        Ok(Response::new(SubmitRoundResponse {
            round: round_message.round,
            from: round_message.from,
            to: round_message.to,
            payload: round_message.payload,
        }))
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
        let request: &FinalizeSessionRequest = request.get_ref();

        let session_id: SessionId = match SessionId::parse(&request.session_id)
        {
            Some(id) => id,
            None => {
                return Err(Errors::SessionNotFound(
                    request.session_id.clone(),
                )
                .into());
            },
        };

        let output: ProtocolOutput = self.engine.finalize(session_id).await?;

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
                key_id,
                key_share,
                public_key,
                public_key_package,
            } => {
                // Store key share in vault in a blocking task.
                self.vault.store_key_share(&key_id, key_share).await?;

                Ok(Response::new(FinalizeSessionResponse {
                    final_output: Some(FinalOutput::KeyGeneration(
                        KeyGenerationResult { public_key, public_key_package },
                    )),
                }))
            },
        }
    }

    /// Abort an MPC signing session.
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
        let request: &AbortSessionRequest = request.get_ref();

        let session_id: SessionId = match SessionId::parse(&request.session_id)
        {
            Some(id) => id,
            None => {
                return Err(Errors::SessionNotFound(
                    request.session_id.clone(),
                )
                .into());
            },
        };

        self.engine.abort(session_id).await?;

        Ok(Response::new(AbortSessionResponse {}))
    }
}
