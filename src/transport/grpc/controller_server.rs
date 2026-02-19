//! gRPC IPC server for the controller engine.

use std::str::FromStr;

use tonic::{Request, Response, Status};
use tracing::instrument;

use crate::{
    auth::session::identifier::SessionId,
    proto::signer::v1::{
        AbortRequest,
        AbortResponse,
        GenerateKeyRequest,
        GenerateKeyResponse,
        KeyGenerationResult,
        SignRequest,
        SignResponse,
        SignatureResult,
        controller_server::Controller,
    },
    protocols::{
        algorithm::Algorithm,
        types::{
            ControllerKeyGenerationInit,
            ControllerSigningInit,
            DefaultKeyGenerationInit,
            DefaultSigningInit,
            KeyGenerationInit,
            ProtocolInit,
            ProtocolOutput,
            RoundMessage,
            SigningInit,
        },
    },
    service::api::EngineApi,
    transport::{errors::Errors, grpc::node_client::NodeIpcClient},
};

/// Controller IPC server.
///
/// This exposes the controller engine over gRPC.
pub struct ControllerIpcServer<E: EngineApi> {
    engine: E,
    nodes: Vec<NodeIpcClient>,
}

impl<E: EngineApi> ControllerIpcServer<E> {
    /// Create a new Controller IPC server.
    pub fn new(engine: E, nodes: Vec<NodeIpcClient>) -> Self {
        Self { engine, nodes }
    }
}

#[tonic::async_trait]
impl<E: EngineApi> Controller for ControllerIpcServer<E> {
    /// Generate distributed key.
    ///
    /// # Arguments
    /// * `request` (`GenerateKeyRequest`) - The request containing key
    ///   generation parameters.
    ///
    /// # Errors
    /// * `Status` - If the algorithm is unsupported, protocol initialization
    ///   fails, or if finalization fails.
    ///
    /// # Returns
    /// * `GenerateKeyResponse` - The response containing the generated public
    ///   key.
    #[instrument(skip(self, request))]
    async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let request: GenerateKeyRequest = request.into_inner();

        let algorithm: Algorithm =
            match Algorithm::from_str(&request.algorithm) {
                Ok(algorithm) => algorithm,
                Err(_) => {
                    return Err(Status::from(Errors::UnsupportedAlgorithm(
                        request.algorithm.clone(),
                    )));
                },
            };

        let init: ProtocolInit = ProtocolInit::KeyGeneration(
            KeyGenerationInit::Controller(ControllerKeyGenerationInit {
                common: DefaultKeyGenerationInit {
                    key_id: request.key_id.clone(),
                    algorithm,
                    threshold: request.threshold,
                    participants: request.participants,
                },
            }),
        );

        // Start controller session.
        let (session_id, _): (SessionId, RoundMessage) =
            self.engine.start_session(init).await.map_err(Status::from)?;

        // Immediately finalize (controller runs fully inside start_session).
        let output: ProtocolOutput =
            self.engine.finalize(session_id).await.map_err(Status::from)?;

        match output {
            ProtocolOutput::KeyGeneration {
                public_key,
                public_key_package,
                ..
            } => Ok(Response::new(GenerateKeyResponse {
                result: Some(KeyGenerationResult {
                    public_key,
                    public_key_package,
                }),
            })),

            _ => Err(Status::internal("Invalid protocol output.")),
        }
    }

    /// Sign message using distributed protocol.
    ///
    /// # Arguments
    /// * `request` (`SignRequest`) - The request containing signing
    ///   parameters.
    ///
    /// # Errors
    /// * `Status` - If the algorithm is unsupported, protocol initialization
    ///   fails, or if finalization fails.
    ///
    /// # Returns
    /// * `SignResponse` - The response containing the final signature.
    #[instrument(skip(self, request))]
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let request: SignRequest = request.into_inner();

        let init: ProtocolInit = ProtocolInit::Signing(
            SigningInit::Controller(ControllerSigningInit {
                common: DefaultSigningInit {
                    key_id: request.key_id.clone(),
                    algorithm: Algorithm::from_str(&request.algorithm)
                        .map_err(|_| {
                            Status::from(Errors::UnsupportedAlgorithm(
                                request.algorithm.clone(),
                            ))
                        })?,
                    threshold: request.threshold,
                    participants: request.participants,
                    message: request.message.clone(),
                },
                public_key_package: request.public_key_package.clone(),
                nodes: self.nodes.clone(),
            }),
        );

        let (session_id, _): (SessionId, RoundMessage) =
            self.engine.start_session(init).await.map_err(Status::from)?;

        let output: ProtocolOutput =
            self.engine.finalize(session_id).await.map_err(Status::from)?;

        match output {
            ProtocolOutput::Signature(signature) => {
                Ok(Response::new(SignResponse {
                    result: Some(SignatureResult {
                        final_signature: Some(signature),
                    }),
                }))
            },

            _ => Err(Status::internal("Invalid protocol output.")),
        }
    }

    /// Abort controller session.
    ///
    /// # Arguments
    /// * `request` (`AbortRequest`) - The request containing the session ID to
    ///   abort.
    ///
    /// # Errors
    /// * `Status` - If the session ID is invalid or if aborting the session
    ///   fails.
    #[instrument(skip(self, request))]
    async fn abort(
        &self,
        request: Request<AbortRequest>,
    ) -> Result<Response<AbortResponse>, Status> {
        let request: AbortRequest = request.into_inner();

        let session_id: SessionId = SessionId::parse(&request.session_id)
            .ok_or_else(|| {
                Status::from(Errors::SessionNotFound(request.session_id))
            })?;

        self.engine.abort(session_id).await.map_err(Status::from)?;

        Ok(Response::new(AbortResponse {}))
    }
}
