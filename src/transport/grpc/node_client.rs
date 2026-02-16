//! gRPC client for communicating with peer nodes.

use std::time::Duration;

use tonic::{
    Request,
    Status,
    transport::{Channel, Endpoint, Error},
};

use crate::{
    auth::identity::Identity,
    proto::signer::v1::{
        AbortSessionRequest,
        AbortSessionResponse,
        FinalizeSessionRequest,
        FinalizeSessionResponse,
        StartKeyGenerationSessionRequest,
        StartSessionResponse,
        StartSigningSessionRequest,
        SubmitRoundRequest,
        SubmitRoundResponse,
        peer_client::PeerClient,
    },
    transport::grpc::middleware::inject_identity,
};

/// gRPC client used by the orchestrator to communicate with peers.
#[derive(Clone, Debug)]
pub struct NodeIpcClient {
    /// The gRPC endpoint of the peer.
    endpoint: String,
    /// The identity to use for authentication with the peer.
    identity: Identity,
    /// The participant ID of the peer.
    participant_id: u32,
    /// The inner gRPC client, lazily initialized on first use.
    inner: Option<PeerClient<Channel>>,
}

impl NodeIpcClient {
    /// Connect to a peer gRPC endpoint.
    ///
    /// # Arguments
    /// * `endpoint` (`String`) - The gRPC endpoint of the peer to connect to.
    /// * `identity` (`Identity`) - The identity to use for authentication with
    ///   the peer.
    /// * `participant_id` (`u32`) - The participant ID of the peer.
    ///
    /// # Returns
    /// * `PeerIpcClient` - A new instance of the peer gRPC client.
    pub fn new(
        endpoint: String,
        identity: Identity,
        participant_id: u32,
    ) -> Self {
        Self { endpoint, identity, participant_id, inner: None }
    }

    /// Get the participant ID of this peer client.
    ///
    /// # Returns
    /// * `Option<u32>` - The participant ID if this client represents a peer,
    ///   or `None` if it does not.
    pub fn participant_id(&self) -> Option<u32> {
        Some(self.participant_id)
    }

    /// Ensure the gRPC channel is connected. This performs a lazy connection
    /// if no active channel exists.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the connection is established or already
    ///   active, or an error if the connection attempt fails.
    async fn ensure_connected(&mut self) -> Result<(), Error> {
        if self.inner.is_some() {
            return Ok(());
        }

        let channel: Channel = Endpoint::from_shared(self.endpoint.clone())?
            .connect_timeout(Duration::from_secs(5))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .connect()
            .await?;

        self.inner = Some(PeerClient::new(channel));
        Ok(())
    }

    /// Connect to the provided [`Endpoint`] using the provided connector, and
    /// return a new [`Channel`].
    ///
    /// This is a lower level API, prefer to use [`Endpoint::connect`] if you
    /// are not using a custom connector. This method is used internally to
    /// lazily initialize the gRPC client connection.
    ///
    /// # Returns
    /// * `Result<&mut PeerClient<Channel>, Status>` - A mutable reference to
    ///   the initialized gRPC client, or an error status if the connection
    ///   fails.
    async fn get_client(
        &mut self,
    ) -> Result<&mut PeerClient<Channel>, Status> {
        self.ensure_connected()
            .await
            .map_err(|error: Error| Status::unavailable(error.to_string()))?;

        self.inner
            .as_mut()
            .ok_or_else(|| Status::internal("Client not initialized."))
    }

    /// Start a key generation session on a peer.
    ///
    /// # Arguments
    ///  * `request` (`StartKeyGenerationSessionRequest`) - The request
    ///    containing the parameters for starting the key generation session.
    ///
    /// # Returns
    ///  * `Result<StartSessionResponse, Status>` - A result containing the
    ///    response from the peer or an error status if the request failed.
    pub async fn start_key_generation(
        &mut self,
        request: StartKeyGenerationSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        let identity: Identity = self.identity.clone();
        let client: &mut PeerClient<Channel> = self.get_client().await?;

        let request: Request<StartKeyGenerationSessionRequest> =
            inject_identity(Request::new(request), identity);

        match client.start_key_generation_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Start a signing session on a peer.
    ///
    /// # Arguments
    ///  * `request` (`StartSigningSessionRequest`) - The request containing
    ///    the parameters for starting the signing session.
    ///
    /// # Returns
    /// * `Result<StartSessionResponse, Status>` - A result containing the
    ///   response from the peer or an error status if the request failed.
    pub async fn start_signing(
        &mut self,
        request: StartSigningSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        let identity: Identity = self.identity.clone();
        let client: &mut PeerClient<Channel> = self.get_client().await?;

        let request: Request<StartSigningSessionRequest> =
            inject_identity(Request::new(request), identity);

        match client.start_signing_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Submit a round message to a peer.
    ///
    /// # Arguments
    /// * `request` (`SubmitRoundRequest`) - The request containing the round
    ///   message and parameters.
    ///
    /// # Returns
    /// * `Result<SubmitRoundResponse, Status>` - A result containing the
    ///   response from the peer or an error status if the request failed.
    pub async fn submit_round(
        &mut self,
        request: SubmitRoundRequest,
    ) -> Result<SubmitRoundResponse, Status> {
        let identity: Identity = self.identity.clone();
        let client: &mut PeerClient<Channel> = self.get_client().await?;

        let request: Request<SubmitRoundRequest> =
            inject_identity(Request::new(request), identity);

        match client.submit_round(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Finalize a session on a peer.
    ///
    /// # Arguments
    /// * `session_id` (`String`) - The ID of the session to finalize.
    ///
    /// # Returns
    /// * `Result<FinalizeSessionResponse, Status>` - A result containing the
    ///   response from the peer or an error status if the request failed.
    pub async fn finalize(
        &mut self,
        session_id: String,
    ) -> Result<FinalizeSessionResponse, Status> {
        let identity: Identity = self.identity.clone();
        let client: &mut PeerClient<Channel> = self.get_client().await?;

        let request: Request<FinalizeSessionRequest> = inject_identity(
            Request::new(FinalizeSessionRequest { session_id }),
            identity,
        );

        match client.finalize_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Abort a session on a peer.
    ///
    /// # Arguments
    /// * `session_id` (`String`) - The ID of the session to abort.
    ///
    /// # Returns
    /// * `Result<AbortSessionResponse, Status>` - A result containing the
    ///   response from the peer or an error status if the request failed.
    pub async fn abort_session(
        &mut self,
        session_id: String,
    ) -> Result<AbortSessionResponse, Status> {
        let identity: Identity = self.identity.clone();
        let client: &mut PeerClient<Channel> = self.get_client().await?;

        let request: Request<AbortSessionRequest> = inject_identity(
            Request::new(AbortSessionRequest { session_id }),
            identity,
        );

        match client.abort_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }
}
