//! gRPC IPC server for the controller engine.

use std::str::FromStr;

use strum::ParseError;
use tonic::{Request, Response, Status};
use tracing::instrument;

use crate::{
    auth::session::identifier::SessionIdentifier,
    proto::signer::v1::{
        AbortRequest,
        AbortResponse,
        GenerateKeyRequest,
        GenerateKeyResponse,
        KeyGenerationResult,
        RoundMessage,
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
            SigningInit,
        },
    },
    service::api::EngineApi,
    transport::{errors::Errors, grpc::node_client::NodeIpcClient},
};

/// Controller IPC server.
pub struct ControllerIpcServer<E: EngineApi> {
    /// Engine API implementation for protocol execution.
    engine: E,
    /// gRPC clients for communicating with nodes.
    nodes: Vec<NodeIpcClient>,
}

impl<E: EngineApi> ControllerIpcServer<E> {
    /// Create a new Controller IPC server.
    ///
    /// # Arguments
    /// * `engine` (`E`) - Engine API implementation for protocol execution.
    /// * `nodes` (`Vec<NodeIpcClient>`) - gRPC clients for communicating with
    ///   nodes.
    ///
    /// # Returns
    /// * `Self` - A new instance of the Controller IPC server.
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
    #[instrument(skip(self, request), fields(
        key_identifier = %request.get_ref().key_identifier,
        algorithm = %request.get_ref().algorithm,
    ))]
    async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> Result<Response<GenerateKeyResponse>, Status> {
        let request: GenerateKeyRequest = request.into_inner();

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

        let init: ProtocolInit = ProtocolInit::KeyGeneration(
            KeyGenerationInit::Controller(ControllerKeyGenerationInit {
                common: DefaultKeyGenerationInit {
                    key_identifier: request.key_identifier.clone(),
                    algorithm,
                    threshold: request.threshold,
                    participants: request.participants,
                },
                nodes: self.nodes.clone(),
            }),
        );

        // Start controller session.
        let (session_id, _): (SessionIdentifier, Vec<RoundMessage>) =
            self.engine.start_session(init).await?;

        match self.engine.finalize(session_id).await? {
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

            _ => {
                Err(Errors::Internal("Invalid protocol output.".into()).into())
            },
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
    #[instrument(skip(self, request), fields(
        key_identifier = %request.get_ref().key_identifier,
        algorithm = %request.get_ref().algorithm,
    ))]
    async fn sign(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
        let request: SignRequest = request.into_inner();

        let init: ProtocolInit = ProtocolInit::Signing(
            SigningInit::Controller(ControllerSigningInit {
                common: DefaultSigningInit {
                    key_identifier: request.key_identifier.clone(),
                    algorithm: Algorithm::from_str(&request.algorithm)
                        .map_err(|error: ParseError| {
                            Errors::UnsupportedAlgorithm(format!(
                                "Failed to parse algorithm: {}",
                                error
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

        let (session_id, _): (SessionIdentifier, Vec<RoundMessage>) =
            self.engine.start_session(init).await?;

        match self.engine.finalize(session_id).await? {
            ProtocolOutput::Signature(signature) => {
                Ok(Response::new(SignResponse {
                    result: Some(SignatureResult {
                        final_signature: Some(signature),
                    }),
                }))
            },

            _ => {
                Err(Errors::Internal("Invalid protocol output.".into()).into())
            },
        }
    }

    /// Abort controller session.
    ///
    /// # Arguments
    /// * `request` (`AbortRequest`) - The request containing the session
    ///   identifier to abort.
    ///
    /// # Errors
    /// * `Status` - If the session identifier is invalid or if aborting the
    ///   session fails.
    #[instrument(skip(self, request))]
    async fn abort(
        &self,
        request: Request<AbortRequest>,
    ) -> Result<Response<AbortResponse>, Status> {
        let request: AbortRequest = request.into_inner();

        let session_identifier: SessionIdentifier =
            SessionIdentifier::parse(&request.session_identifier).ok_or_else(
                || Errors::SessionNotFound(request.session_identifier.clone()),
            )?;

        self.engine.abort(session_identifier).await?;

        Ok(Response::new(AbortResponse {}))
    }
}
