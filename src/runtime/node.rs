//! Node runtime module.

use std::{
    net::{AddrParseError, SocketAddr},
    time::Duration,
};

use async_trait::async_trait;
use tonic::transport::{Error as TransportError, Server};
use tonic_reflection::server::{
    Builder as ReflectionBuilder,
    Error as ReflectionError,
    v1::{ServerReflection, ServerReflectionServer},
};

use crate::{
    auth::{identity::Identity, ipc::auth::TokenAuth},
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
    /// * `Error` - If any error occurs during runtime execution.
    ///
    /// # Returns
    /// * `()` - On successful execution.
    async fn run(config: NodeRuntimeConfig) -> Result<(), Errors> {
        LoggingEngine::init("Node");

        tracing::info!(
            address = %config.ipc.address,
            "Starting node runtime."
        );

        // Create identity for the node based on configuration.
        let identity: Identity = Identity::Node {
            node_id: config.ipc.node_id,
            participant_id: config.ipc.participant_id,
        };

        // Initialize Hashicorp Vault provider based on configuration.
        let vault: HashicorpVaultProvider =
            HashicorpVaultProvider::try_from_config(config.vault)?;

        // Initialize authentication for the node using token-based
        // authentication from configuration.
        let auth: TokenAuth =
            TokenAuth::new(config.ipc.auth.token.clone(), identity.clone());

        // Build the node engine with session TTL from configuration.
        let engine: NodeEngine = EngineBuilder::new()
            .session_ttl(Duration::from_secs(config.ipc.ttl_seconds))
            .build();

        // Create the gRPC server for the node, injecting the engine,
        // auth, and vault provider.
        let server: NodeIpcServer<
            TokenAuth,
            NodeEngine,
            HashicorpVaultProvider,
        > = NodeIpcServer::new(engine, auth, vault);

        // Parse the server address from configuration and handle any parsing
        // errors.
        let address: SocketAddr =
            config.ipc.address.parse().map_err(|error: AddrParseError| {
                Errors::ConfigError(error.to_string())
            })?;

        let reflection_service: ServerReflectionServer<impl ServerReflection> =
            ReflectionBuilder::configure()
                .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
                .build_v1()
                .map_err(|error: ReflectionError| {
                    Errors::ConfigError(error.to_string())
                })?;

        // Start the gRPC server and handle any errors that occur during
        // startup.
        Server::builder()
            .add_service(reflection_service)
            .add_service(NodeServer::new(server))
            .serve(address)
            .await
            .map_err(|error: TransportError| {
                Errors::ConfigError(error.to_string())
            })
    }
}
