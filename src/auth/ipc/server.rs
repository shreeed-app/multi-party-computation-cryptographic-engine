//! IPC server for the MPC signing engine.

use tonic::{Request, Response, Status};

use crate::auth::ipc::auth::AuthProvider;
use crate::engine::EngineApi;
use crate::messages::error::Error;

use crate::proto::signer::v1::{
    AbortSessionRequest, AbortSessionResponse, FinalizeSessionRequest,
    FinalizeSessionResponse, StartSessionRequest, StartSessionResponse,
    SubmitRoundRequest, SubmitRoundResponse, mpc_signer_server::MpcSigner,
};

/// gRPC IPC server exposing the MPC signing engine.
///
/// This server is a strict transport boundary:
/// - authenticates incoming requests
/// - forwards validated calls to the engine
/// - relies on canonical error conversions (`Error -> Status`)
///
/// It contains NO cryptographic logic and NO secret handling.
pub struct IpcServer<A: AuthProvider, E: EngineApi> {
    /// IPC authentication provider.
    auth: A,

    /// MPC signing engine (business logic).
    engine: E,
}

impl<A: AuthProvider, E: EngineApi> IpcServer<A, E> {
    /// Create a new IPC server.
    ///
    /// # Arguments
    /// * `engine` - Initialized MPC engine instance
    /// * `auth` - IPC authentication provider
    pub fn new(engine: E, auth: A) -> Self {
        Self { engine, auth }
    }

    /// Authenticate an incoming request.
    ///
    /// # Errors
    /// Returns a canonical `Error`, automatically converted to gRPC `Status`
    /// by the `From<Error> for Status` implementation.
    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Error> {
        self.auth.authenticate(request)
    }
}

#[tonic::async_trait]
impl<
    A: AuthProvider + Send + Sync + 'static,
    E: EngineApi + Send + Sync + 'static,
> MpcSigner for IpcServer<A, E>
{
    /// Start a new MPC signing session.
    async fn start_session(
        &self,
        request: Request<StartSessionRequest>,
    ) -> Result<Response<StartSessionResponse>, Status> {
        self.authenticate(&request)?;

        let req: &StartSessionRequest = request.get_ref();

        let session_id = self.engine.start_session(
            &req.key_id,
            &req.algorithm,
            req.threshold,
            req.participants,
            &req.message,
        )?;

        Ok(Response::new(StartSessionResponse {
            session_id: session_id.to_string(),
        }))
    }

    /// Submit a round message for an existing MPC session.
    async fn submit_round(
        &self,
        request: Request<SubmitRoundRequest>,
    ) -> Result<Response<SubmitRoundResponse>, Status> {
        self.authenticate(&request)?;

        let req: &SubmitRoundRequest = request.get_ref();

        let (payload, is_final) = self.engine.submit_round(
            &req.session_id,
            req.round,
            &req.payload,
        )?;

        Ok(Response::new(SubmitRoundResponse { payload, is_final }))
    }

    /// Finalize an MPC signing session and return the final signature.
    async fn finalize_session(
        &self,
        request: Request<FinalizeSessionRequest>,
    ) -> Result<Response<FinalizeSessionResponse>, Status> {
        self.authenticate(&request)?;

        let req = request.get_ref();

        let signature = self.engine.finalize_session(&req.session_id)?;

        Ok(Response::new(FinalizeSessionResponse { signature }))
    }

    /// Abort an MPC signing session.
    async fn abort_session(
        &self,
        request: Request<AbortSessionRequest>,
    ) -> Result<Response<AbortSessionResponse>, Status> {
        self.authenticate(&request)?;

        let req = request.get_ref();

        self.engine.abort_session(&req.session_id)?;

        Ok(Response::new(AbortSessionResponse {}))
    }
}
