//! Controller runtime module.

use std::net::{AddrParseError, SocketAddr};

use async_trait::async_trait;
use tonic::transport::{Error as TransportError, Server};
use tonic_reflection::server::{
    Builder as ReflectionBuilder,
    Error as ReflectionError,
    v1::{ServerReflection, ServerReflectionServer},
};

use crate::{
    auth::identity::Identity,
    config::controller::{ControllerRuntimeConfig, NodeConfig},
    logging::engine::LoggingEngine,
    proto::{
        FILE_DESCRIPTOR_SET,
        signer::v1::controller_server::ControllerServer,
    },
    runtime::api::RuntimeApi,
    service::controller_engine::ControllerEngine,
    transport::{
        errors::Errors,
        grpc::{
            controller_server::ControllerIpcServer,
            node_client::NodeIpcClient,
        },
    },
};

/// Controller runtime implementation.
pub struct ControllerRuntime;

#[async_trait]
impl RuntimeApi for ControllerRuntime {
    type Config = ControllerRuntimeConfig;

    /// Run the controller runtime with the given configuration.
    ///
    /// # Arguments
    /// * `config` (`ControllerRuntimeConfig`) - Configuration for the
    ///   controller runtime.
    ///
    /// # Errors
    /// * `Error` - If any error occurs during runtime execution.
    ///
    /// # Returns
    /// * `()` - On successful execution.
    async fn run(config: ControllerRuntimeConfig) -> Result<(), Errors> {
        LoggingEngine::init("Controller");

        tracing::info!(
            address = %config.ipc.address,
            nodes = config.nodes.len(),
            "Starting controller runtime."
        );

        // Create nodes clients for each configured node.
        let nodes: Vec<NodeIpcClient> = config
            .nodes
            .into_iter()
            .map(|node_config: NodeConfig| {
                NodeIpcClient::new(
                    node_config.endpoint,
                    Identity::Controller {
                        service_id: config.ipc.service_id.clone(),
                    },
                    node_config.participant_id,
                )
            })
            .collect();

        // Create the gRPC server for the controller, injecting the controller
        // engine and node clients.
        let server: ControllerIpcServer<ControllerEngine> =
            ControllerIpcServer::new(ControllerEngine::default(), nodes);

        // Parse the controller's IPC server address from configuration.
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

        // Start the gRPC server and serve requests.
        Server::builder()
            .add_service(reflection_service)
            .add_service(ControllerServer::new(server))
            .serve(address)
            .await
            .map_err(|error: TransportError| {
                Errors::ConfigError(error.to_string())
            })
    }
}
