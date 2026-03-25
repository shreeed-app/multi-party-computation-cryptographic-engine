//! Node runtime module.

use std::{
    net::{AddrParseError, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::oneshot::Sender;
use tonic::transport::{Error, Server};
use tonic_middleware::RequestInterceptorLayer;
use tonic_reflection::server::{
    Builder as ReflectionBuilder,
    Error as ReflectionError,
    v1::{ServerReflection, ServerReflectionServer},
};
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};

use crate::{
    auth::bearer_server::BearerAuthInterceptor,
    config::node::NodeRuntimeConfig,
    logging::engine::LoggingEngine,
    proto::{FILE_DESCRIPTOR_SET, signer::v1::node_server::NodeServer},
    runtime::api::RuntimeApi,
    secrets::vault::hashicorp::HashicorpVaultProvider,
    service::{builder::EngineBuilder, node_engine::NodeEngine},
    transport::{errors::Errors, grpc::node_server::NodeIpcServer},
};

/// Node runtime implementation.
pub struct NodeRuntime;

#[async_trait]
impl RuntimeApi for NodeRuntime {
    /// Associated type for the node runtime configuration.
    type Config = NodeRuntimeConfig;

    /// Run the node runtime with the given configuration.
    ///
    /// # Arguments
    /// * `config` (`NodeRuntimeConfig`) - Configuration for the node runtime.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during runtime execution.
    ///
    /// # Returns
    /// * `()` - On successful execution.
    async fn run(
        config: NodeRuntimeConfig,
        ready: Sender<()>,
    ) -> Result<(), Errors> {
        LoggingEngine::init(
            format!("Node {}", config.ipc.node_identifier).as_str(),
        );

        tracing::info!(
            address = %config.ipc.address,
            "Starting node runtime."
        );

        // Initialize Hashicorp Vault provider based on configuration.
        let vault: HashicorpVaultProvider =
            HashicorpVaultProvider::try_from_config(config.vault)?;
        tracing::debug!("Initialized Hashicorp Vault provider.");

        // Build the node engine with session TTL from configuration.
        let engine: NodeEngine = EngineBuilder::default()
            .session_ttl(Duration::from_secs(config.ipc.ttl_seconds))
            .build();
        tracing::debug!(
            "Initialized node engine with session TTL of {} seconds.",
            config.ipc.ttl_seconds
        );

        // Create the gRPC server for the node, injecting the engine,
        // auth, and vault provider.
        let server: NodeIpcServer<NodeEngine, HashicorpVaultProvider> =
            NodeIpcServer::new(engine, vault);
        tracing::debug!("Initialized node IPC server.");

        // Parse the server address from configuration and handle any parsing
        // errors.
        let address: SocketAddr =
            config.ipc.address.parse().map_err(|error: AddrParseError| {
                Errors::ConfigError(error.to_string())
            })?;
        tracing::debug!(%address, "Parsed node IPC server address.");

        let auth_layer: RequestInterceptorLayer<BearerAuthInterceptor> =
            RequestInterceptorLayer::new(BearerAuthInterceptor::new(
                config.ipc.auth.token.clone(),
            ));

        let reflection_service: ServerReflectionServer<impl ServerReflection> =
            ReflectionBuilder::configure()
                .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
                .build_v1()
                .map_err(|error: ReflectionError| {
                    Errors::ConfigError(error.to_string())
                })?;
        tracing::debug!("Configured gRPC reflection service.");

        // Start the gRPC server and handle any errors that occur during
        // startup.
        let server: impl Future<Output = Result<(), Error>> =
            Server::builder()
                .layer(ConcurrencyLimitLayer::new(100))
                .layer(TimeoutLayer::new(Duration::from_secs(600)))
                .layer(auth_layer)
                .add_service(reflection_service)
                .add_service(NodeServer::new(server))
                .serve(address);

        ready.send(()).ok();

        server.await?;

        Ok(())
    }
}
