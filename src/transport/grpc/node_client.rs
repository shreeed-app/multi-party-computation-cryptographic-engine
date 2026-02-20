//! gRPC client for communicating with nodes.

use std::time::Duration;

use tonic::{
    Request,
    Status,
    service::interceptor::InterceptedService,
    transport::{Channel, Endpoint, Error},
};
use tracing::instrument;

use crate::{
    auth::bearer_client::ClientAuthInterceptor,
    config::controller::NodeConfig,
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
        node_client::NodeClient,
    },
    transport::errors::Errors,
};

/// gRPC client used by the controller to communicate with nodes.
#[derive(Clone, Debug)]
pub struct NodeIpcClient {
    /// The gRPC endpoint of the node.
    config: NodeConfig,
    /// The inner gRPC client, lazily initialized on first use.
    inner:
        Option<NodeClient<InterceptedService<Channel, ClientAuthInterceptor>>>,
}

impl NodeIpcClient {
    /// Connect to a node gRPC endpoint.
    ///
    /// # Arguments
    /// * `config` (`NodeConfig`) - The configuration for the node connection,
    ///  including the endpoint, participant ID, and authentication token.
    ///
    /// # Returns
    /// * `NodeIpcClient` - A new instance of the node gRPC client.
    pub fn new(config: NodeConfig) -> Self {
        Self { config, inner: None }
    }

    /// Get the participant ID of this node client.
    ///
    /// # Returns
    /// * `Option<u32>` - The participant ID if this client represents a node,
    ///   or `None` if it does not.
    pub fn participant_id(&self) -> Option<u32> {
        Some(self.config.participant_id)
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

        let channel: Channel =
            Endpoint::from_shared(self.config.endpoint.clone())?
                .connect_timeout(Duration::from_secs(5))
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .connect()
                .await?;

        // Create an interceptor that adds the Bearer token to each request.
        let interceptor: ClientAuthInterceptor =
            ClientAuthInterceptor { config: self.config.auth.clone() };

        let client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = NodeClient::with_interceptor(channel, interceptor);

        self.inner = Some(client);
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
    /// * `Result<&mut NodeClient<InterceptedService<Channel,
    ///   ClientAuthInterceptor>>, Status>` - A mutable reference to the
    ///   initialized gRPC client, or an error status if the connection fails.
    #[instrument(skip(self))]
    async fn get_client(
        &mut self,
    ) -> Result<
        &mut NodeClient<InterceptedService<Channel, ClientAuthInterceptor>>,
        Status,
    > {
        self.ensure_connected().await.map_err(Errors::from)?;

        let client: &mut NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self
            .inner
            .as_mut()
            .ok_or(Errors::Internal("Client not initialized.".to_string()))?;

        Ok(client)
    }

    /// Start a key generation session on a node.
    ///
    /// # Arguments
    ///  * `request` (`StartKeyGenerationSessionRequest`) - The request
    ///    containing the parameters for starting the key generation session.
    ///
    /// # Returns
    ///  * `Result<StartSessionResponse, Status>` - A result containing the
    ///    response from the node or an error status if the request failed.
    #[instrument(skip(self, request))]
    pub async fn start_key_generation(
        &mut self,
        request: StartKeyGenerationSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        let client: &mut NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.get_client().await?;

        match client.start_key_generation_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Start a signing session on a node.
    ///
    /// # Arguments
    ///  * `request` (`StartSigningSessionRequest`) - The request containing
    ///    the parameters for starting the signing session.
    ///
    /// # Returns
    /// * `Result<StartSessionResponse, Status>` - A result containing the
    ///   response from the node or an error status if the request failed.
    #[instrument(skip(self, request))]
    pub async fn start_signing(
        &mut self,
        request: StartSigningSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        let client: &mut NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.get_client().await?;

        match client.start_signing_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Submit a round message to a node.
    ///
    /// # Arguments
    /// * `request` (`SubmitRoundRequest`) - The request containing the round
    ///   message and parameters.
    ///
    /// # Returns
    /// * `Result<SubmitRoundResponse, Status>` - A result containing the
    ///   response from the node or an error status if the request failed.
    #[instrument(skip(self, request), fields(session_id = %request.session_id))]
    pub async fn submit_round(
        &mut self,
        request: SubmitRoundRequest,
    ) -> Result<SubmitRoundResponse, Status> {
        let client: &mut NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.get_client().await?;

        match client.submit_round(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Finalize a session on a node.
    ///
    /// # Arguments
    /// * `session_id` (`String`) - The ID of the session to finalize.
    ///
    /// # Returns
    /// * `Result<FinalizeSessionResponse, Status>` - A result containing the
    ///   response from the node or an error status if the request failed.
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn finalize(
        &mut self,
        session_id: String,
    ) -> Result<FinalizeSessionResponse, Status> {
        let client: &mut NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.get_client().await?;

        let request: Request<FinalizeSessionRequest> =
            Request::new(FinalizeSessionRequest { session_id });

        match client.finalize_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }

    /// Abort a session on a node.
    ///
    /// # Arguments
    /// * `session_id` (`String`) - The ID of the session to abort.
    ///
    /// # Returns
    /// * `Result<AbortSessionResponse, Status>` - A result containing the
    ///   response from the node or an error status if the request failed.
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn abort_session(
        &mut self,
        session_id: String,
    ) -> Result<AbortSessionResponse, Status> {
        let client: &mut NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.get_client().await?;

        let request: Request<AbortSessionRequest> =
            Request::new(AbortSessionRequest { session_id });

        match client.abort_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                self.inner = None;
                Err(status)
            },
        }
    }
}
