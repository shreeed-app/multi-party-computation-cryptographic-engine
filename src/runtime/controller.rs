//! Controller runtime module.

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
    config::controller::ControllerRuntimeConfig,
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
    /// * `ready` (`Sender<()>`) - Channel sender to signal when the runtime is
    ///   ready.
    ///
    /// # Errors
    /// * `Errors` - If any error occurs during runtime execution.
    ///
    /// # Returns
    /// * `()` - On successful execution.
    async fn run(
        config: ControllerRuntimeConfig,
        ready: Sender<()>,
    ) -> Result<(), Errors> {
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
            .map(NodeIpcClient::new)
            .map(|result: Result<NodeIpcClient, Error>| {
                result.map_err(|error: Error| {
                    Errors::ConfigError(error.to_string())
                })
            })
            .collect::<Result<Vec<NodeIpcClient>, Errors>>()?;
        tracing::debug!("Created node clients for configured nodes.");

        // Create the gRPC server for the controller, injecting the controller
        // engine and node clients.
        let server: ControllerIpcServer<ControllerEngine> =
            ControllerIpcServer::new(ControllerEngine::default(), nodes);
        tracing::debug!("Initialized controller IPC server.");

        // Parse the controller's IPC server address from configuration.
        let address: SocketAddr =
            config.ipc.address.parse().map_err(|error: AddrParseError| {
                Errors::ConfigError(error.to_string())
            })?;
        tracing::debug!(%address, "Parsed controller IPC server address.");

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

        // Start the gRPC server and serve requests.
        let server: impl Future<Output = Result<(), Error>> =
            Server::builder()
                .layer(ConcurrencyLimitLayer::new(100))
                .layer(TimeoutLayer::new(Duration::from_secs(600)))
                .layer(auth_layer)
                .add_service(reflection_service)
                .add_service(ControllerServer::new(server))
                .serve(address);

        ready.send(()).ok();

        server.await?;

        Ok(())
    }
}
