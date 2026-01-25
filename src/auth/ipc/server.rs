//! IPC server for the signing engine.

use std::{str::FromStr, sync::Arc};

use futures::executor::block_on;
use tokio::task::spawn_blocking;
use tonic::{Request, Response, Status};

use crate::{
    auth::{ipc::auth::AuthProvider, session::identifier::SessionId},
    engine::api::EngineApi,
    messages::error::Error,
    proto::signer::v1::{
        AbortSessionRequest,
        AbortSessionResponse,
        EcdsaSignature,
        FinalizeSessionRequest,
        FinalizeSessionResponse,
        StartSessionRequest,
        StartSessionResponse,
        SubmitRoundRequest,
        SubmitRoundResponse,
        finalize_session_response::FinalSignature,
        signer_server::Signer,
    },
    protocols::{
        algorithm::Algorithm,
        types::{ProtocolInit, RoundMessage, Signature},
    },
    secrets::{types::KeyShare, vault::api::VaultProvider},
};

/// gRPC IPC server exposing the signing engine.
pub struct IpcServer<A: AuthProvider, E: EngineApi, V: VaultProvider> {
    /// IPC authentication provider.
    pub auth: A,
    /// Signing engine (business logic).
    pub engine: E,
    /// Vault provider for key shares.
    pub vault: Arc<V>,
}

impl<A: AuthProvider, E: EngineApi, V: VaultProvider> IpcServer<A, E, V> {
    /// Create a new IPC server.
    ///
    /// # Arguments
    /// * `engine` (`E`) - Signing engine instance.
    /// * `auth` (`A`) - IPC authentication provider.
    /// * `vault` (`V`) - Vault provider for key shares.
    ///
    /// # Returns
    /// * `Self` - New IPC server instance.
    pub fn new(engine: E, auth: A, vault: V) -> Self {
        Self { engine, auth, vault: Arc::new(vault) }
    }

    /// Authenticate an incoming request.
    ///
    /// # Arguments
    /// * `request` (`&Request<T>`) - Incoming gRPC request.
    ///
    /// # Errors
    /// * `Error` - If authentication fails.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if authenticated, error otherwise.
    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Error> {
        self.auth.authenticate(request)
    }
}

#[tonic::async_trait]
impl<
    A: AuthProvider + Send + Sync + 'static,
    E: EngineApi + Send + Sync + 'static,
    V: VaultProvider + Send + Sync + 'static,
> Signer for IpcServer<A, E, V>
{
    /// Start a new signing session.
    ///
    /// # Arguments
    /// * `request` (`Request<StartSessionRequest>`) - Incoming gRPC request.
    ///
    /// # Errors
    /// * `Status` - If authentication fails or session creation fails.
    ///
    /// # Returns
    /// * `Result<Response<StartSessionResponse>, Status>` - gRPC response or
    ///   error.
    async fn start_session(
        &self,
        request: Request<StartSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        match self.authenticate(&request) {
            Ok(_) => (),
            Err(error) => return Err(Status::from(error)),
        }

        let request: &StartSessionRequest = request.get_ref();

        // Retrieve key share from vault in a blocking task.
        let key_id: String = request.key_id.clone();
        let vault: Arc<V> = Arc::clone(&self.vault);

        let key_share: KeyShare =
            match spawn_blocking(move || -> Result<KeyShare, Error> {
                block_on(vault.get_key_share(&key_id))
            })
            .await
            {
                Ok(Ok(share)) => share,
                Ok(Err(error)) => return Err(Status::from(error)),
                Err(error) => return Err(Status::internal(error.to_string())),
            };

        let algorithm: Algorithm =
            match Algorithm::from_str(&request.algorithm) {
                Ok(algorithm) => algorithm,
                Err(_) => {
                    return Err(Status::from(Error::UnsupportedAlgorithm(
                        request.algorithm.clone(),
                    )));
                },
            };

        let init: ProtocolInit = ProtocolInit {
            key_id: request.key_id.clone(),
            algorithm,
            threshold: request.threshold,
            participants: request.participants,
            message: request.message.clone(),
            key_share,
        };

        let (session_id, round_message): (SessionId, RoundMessage) =
            match self.engine.start_session(init) {
                Ok(result) => result,
                Err(error) => return Err(Status::from(error)),
            };

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
    async fn submit_round(
        &self,
        request: Request<SubmitRoundRequest>,
    ) -> Result<Response<SubmitRoundResponse>, Status> {
        match self.authenticate(&request) {
            Ok(_) => (),
            Err(error) => return Err(Status::from(error)),
        }

        let request: &SubmitRoundRequest = request.get_ref();

        let session_id: SessionId = match SessionId::parse(&request.session_id)
        {
            Some(id) => id,
            None => {
                return Err(Status::from(Error::SessionNotFound(
                    request.session_id.clone(),
                )));
            },
        };

        let message: RoundMessage = RoundMessage {
            round: request.round,
            from: request.from,
            to: request.to,
            payload: request.payload.clone(),
        };
        let round_message: RoundMessage =
            match self.engine.submit_round(session_id, message) {
                Ok(result) => result,
                Err(error) => return Err(Status::from(error)),
            };

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
    async fn finalize_session(
        &self,
        request: Request<FinalizeSessionRequest>,
    ) -> Result<Response<FinalizeSessionResponse>, Status> {
        match self.authenticate(&request) {
            Ok(_) => (),
            Err(error) => return Err(Status::from(error)),
        }

        let request: &FinalizeSessionRequest = request.get_ref();

        let session_id: SessionId = match SessionId::parse(&request.session_id)
        {
            Some(id) => id,
            None => {
                return Err(Status::from(Error::SessionNotFound(
                    request.session_id.clone(),
                )));
            },
        };

        let signature: Signature = match self.engine.finalize(session_id) {
            Ok(signature) => signature,
            Err(error) => return Err(Status::from(error)),
        };

        Ok(Response::new(FinalizeSessionResponse {
            final_signature: Some(match signature {
                Signature::Raw(bytes) => FinalSignature::Raw(bytes),
                Signature::EcdsaSecp256k1 { r, s, v } => {
                    FinalSignature::Ecdsa(EcdsaSignature {
                        r: r.to_vec(),
                        s: s.to_vec(),
                        v: v as u32,
                    })
                },
            }),
        }))
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
    async fn abort_session(
        &self,
        request: Request<AbortSessionRequest>,
    ) -> Result<Response<AbortSessionResponse>, Status> {
        match self.authenticate(&request) {
            Ok(_) => (),
            Err(error) => return Err(Status::from(error)),
        }

        let request: &AbortSessionRequest = request.get_ref();

        let session_id: SessionId = match SessionId::parse(&request.session_id)
        {
            Some(id) => id,
            None => {
                return Err(Status::from(Error::SessionNotFound(
                    request.session_id.clone(),
                )));
            },
        };

        match self.engine.abort(session_id) {
            Ok(()) => (),
            Err(error) => return Err(Status::from(error)),
        };

        Ok(Response::new(AbortSessionResponse {}))
    }
}
