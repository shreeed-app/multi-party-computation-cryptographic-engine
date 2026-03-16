//! gRPC client for communicating with nodes.

use std::time::Duration;

use tonic::{
    Request,
    Response,
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
        CollectRoundRequest,
        CollectRoundResponse,
        FinalizeSessionRequest,
        FinalizeSessionResponse,
        StartAuxiliaryGenerationSessionRequest,
        StartKeyGenerationSessionRequest,
        StartSessionResponse,
        StartSigningSessionRequest,
        SubmitRoundRequest,
        SubmitRoundResponse,
        node_client::NodeClient,
    },
    transport::errors::Errors,
};

/// gRPC client for communicating with nodes.
#[derive(Clone, Debug)]
pub struct NodeIpcClient {
    /// Configuration for the node client.
    config: NodeConfig,
    /// gRPC endpoint for the node.
    endpoint: Endpoint,
}

impl NodeIpcClient {
    /// Create a new Node IPC client with the given configuration.
    ///
    /// # Arguments
    /// * `config` (`NodeConfig`) - Configuration for the node client.
    ///
    /// # Errors
    /// * `Error` - If any error occurs during client creation (e.g., invalid
    ///   endpoint).
    ///
    /// # Returns
    /// * `Self` - A new instance of the Node IPC client.
    pub fn new(config: NodeConfig) -> Result<Self, Error> {
        let endpoint: Endpoint =
            Endpoint::from_shared(config.endpoint.clone())?
                .connect_timeout(Duration::from_secs(20))
                .tcp_keepalive(Some(Duration::from_secs(60)))
                .http2_keep_alive_interval(Duration::from_secs(60))
                .keep_alive_timeout(Duration::from_secs(30))
                .timeout(Duration::from_secs(300));

        Ok(Self { config, endpoint })
    }

    /// Get the participant identifier from the client configuration.
    ///
    /// # Returns
    /// * `Option<u32>` - The participant identifier if available, otherwise
    ///   `None`.
    pub fn participant_id(&self) -> Option<u32> {
        Some(self.config.participant_id)
    }

    /// Create a gRPC client for communicating with the node, including
    /// authentication.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during client creation (e.g.,
    ///   connection failure).
    ///
    /// # Returns
    /// * `NodeClient<InterceptedService<Channel, ClientAuthInterceptor>>` - A
    ///   gRPC client for communicating with the node, wrapped with an
    ///   authentication interceptor.
    async fn make_client(
        &self,
    ) -> Result<
        NodeClient<InterceptedService<Channel, ClientAuthInterceptor>>,
        Status,
    > {
        let channel: Channel =
            self.endpoint.connect().await.map_err(Errors::from)?;

        let interceptor: ClientAuthInterceptor =
            ClientAuthInterceptor { config: self.config.auth.clone() };

        Ok(NodeClient::with_interceptor(channel, interceptor))
    }

    /// Start a key generation session with the node.
    ///
    /// # Arguments
    /// * `request` (`StartKeyGenerationSessionRequest`) - The request
    ///   containing key generation session parameters.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// # Returns
    /// * `StartSessionResponse` - The response containing session details and
    ///   initial messages.
    #[instrument(skip(self, request))]
    pub async fn start_key_generation(
        &self,
        request: StartKeyGenerationSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        tracing::debug!(
            "Starting key generation session for key {}.",
            request.key_identifier
        );

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        match client.start_key_generation_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => Err(status),
        }
    }

    /// Start an auxiliary generation session with the node.
    ///
    /// # Arguments
    /// * `request` (`StartAuxiliaryGenerationSessionRequest`) - The request
    ///   containing auxiliary generation session parameters.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// # Returns
    /// * `StartSessionResponse` - The response containing session details and
    ///   initial messages.
    #[instrument(skip(self, request))]
    pub async fn start_auxiliary_generation(
        &self,
        request: StartAuxiliaryGenerationSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        tracing::debug!(
            "Starting auxiliary generation session for key {}.",
            request.key_identifier
        );

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        match client.start_auxiliary_generation_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => Err(status),
        }
    }

    /// Submit a round message to the node.
    ///
    /// # Arguments
    /// * `request` (`SubmitRoundRequest`) - The request containing the round
    ///   message to submit.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// # Returns
    /// * `SubmitRoundResponse` - The response indicating the result of the
    ///   submission.
    #[instrument(skip(self, request))]
    pub async fn start_signing(
        &self,
        request: StartSigningSessionRequest,
    ) -> Result<StartSessionResponse, Status> {
        tracing::debug!(
            "Starting signing session for key {}.",
            request.key_identifier
        );

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        match client.start_signing_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => Err(status),
        }
    }

    /// Submit a round message to the node.
    ///
    /// # Arguments
    /// * `request` (`SubmitRoundRequest`) - The request containing the round
    ///   message to submit.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// # Returns
    /// * `SubmitRoundResponse` - The response indicating the result of the
    ///   submission.
    #[instrument(skip(self, request), fields(session_identifier = %request.session_identifier))]
    pub async fn submit_round(
        &self,
        request: SubmitRoundRequest,
    ) -> Result<SubmitRoundResponse, Status> {
        tracing::debug!(
            "Submitting round message for session {}.",
            request.session_identifier
        );

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        let response: tonic::Response<SubmitRoundResponse> =
            client.submit_round(request).await?;

        Ok(response.into_inner())
    }

    /// Collect round messages from the node for the given session.
    ///
    /// # Arguments
    /// * `session_id` (`String`) - The identifier of the session for which to
    ///   collect round messages.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// # Returns
    /// * `CollectRoundResponse` - The response containing collected round
    ///   messages and completion status.
    #[instrument(skip(self), fields(session_identifier = %session_identifier))]
    pub async fn collect_round(
        &self,
        session_identifier: String,
    ) -> Result<CollectRoundResponse, Status> {
        tracing::debug!(
            "Collecting round messages for session {}.",
            session_identifier
        );

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        let request: Request<CollectRoundRequest> =
            Request::new(CollectRoundRequest { session_identifier });

        let response: Response<CollectRoundResponse> =
            client.collect_round(request).await?;

        Ok(response.into_inner())
    }

    /// Finalize the session on the node and retrieve the final output.
    ///
    /// # Arguments
    /// * `session_identifier` (`String`) - The identifier of the session to
    ///   finalize.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// # Returns
    /// * `FinalizeSessionResponse` - The response containing the final output
    ///   of the session.
    #[instrument(skip(self), fields(session_identifier = %session_identifier))]
    pub async fn finalize(
        &self,
        session_identifier: String,
    ) -> Result<FinalizeSessionResponse, Status> {
        tracing::debug!("Finalizing session {}.", session_identifier);

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        let request: Request<FinalizeSessionRequest> =
            Request::new(FinalizeSessionRequest { session_identifier });

        match client.finalize_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => Err(status),
        }
    }

    /// Abort the session on the node.
    ///
    /// # Arguments
    /// * `session_identifier` (`String`) - The identifier of the session to
    ///   abort.
    ///
    /// # Errors
    /// * `Status` - If any error occurs during the RPC call.
    ///
    /// * `AbortSessionResponse` - On successful abortion.
    #[instrument(skip(self), fields(session_identifier = %session_identifier))]
    pub async fn abort_session(
        &self,
        session_identifier: String,
    ) -> Result<AbortSessionResponse, Status> {
        tracing::debug!("Aborting session {}.", session_identifier);

        let mut client: NodeClient<
            InterceptedService<Channel, ClientAuthInterceptor>,
        > = self.make_client().await?;

        let request: Request<AbortSessionRequest> =
            Request::new(AbortSessionRequest { session_identifier });

        match client.abort_session(request).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => Err(status),
        }
    }
}
