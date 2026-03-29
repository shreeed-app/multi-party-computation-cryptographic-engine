use std::{
    future::pending,
    io::Error as IoError,
    net::SocketAddr,
    thread::spawn,
    time::Duration,
};

use app::{
    auth::bearer_server::BearerAuthInterceptor,
    config::{
        controller::{ControllerRuntimeConfig, NodeConfig},
        ipc::{AuthConfig, ControllerIpcConfig, NodeIpcConfig},
    },
    proto::{FILE_DESCRIPTOR_SET, signer::v1::node_server::NodeServer},
    runtime::{
        api::RuntimeApi,
        controller::ControllerRuntime,
        types::IncomingStream,
    },
    service::{builder::EngineBuilder, node_engine::NodeEngine},
    transport::{errors::Errors, grpc::node_server::NodeIpcServer},
};
use futures::{
    future::{BoxFuture, join_all},
    stream::unfold,
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder, EnterGuard, Runtime},
    spawn as tokio_spawn,
    sync::{
        OnceCell,
        oneshot::{Receiver, Sender, channel},
    },
};
use tonic::transport::Server;
use tonic_middleware::RequestInterceptorLayer;
use tonic_reflection::server::{
    Builder as ReflectionBuilder,
    Error,
    v1::ServerReflectionServer,
};
use tower::{limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};
use tracing_subscriber::{EnvFilter, fmt};

use crate::helpers::{config::ClusterConfig, vault::MockVaultProvider};

/// Spawn a node with an in-memory mock vault and return a receiver that
/// signals when the node is ready.
pub async fn spawn_node(index: usize) -> Receiver<()> {
    let (ready_transmitter, ready_receiver): (Sender<()>, Receiver<()>) =
        channel();
    let cluster_config: &ClusterConfig = ClusterConfig::get();

    let ipc: NodeIpcConfig = NodeIpcConfig {
        node_identifier: cluster_config.node_participant_id(index).to_string(),
        participant_identifier: cluster_config.node_participant_id(index),
        address: format!("127.0.0.1:{}", cluster_config.node_port(index)),
        ttl_seconds: 600,
        auth: AuthConfig { token: cluster_config.node_token(index) },
    };

    tokio_spawn(async move {
        run_node(ipc, ready_transmitter).await.unwrap();
    });

    ready_receiver
}

/// Start a node gRPC server backed by a [`MockVaultProvider`].
///
/// This mirrors the logic in `NodeRuntime::run` but injects the mock vault
/// instead of a real HashiCorp Vault client, making it safe to use in CI.
async fn run_node(
    ipc: NodeIpcConfig,
    ready: Sender<()>,
) -> Result<(), Errors> {
    let vault: MockVaultProvider = MockVaultProvider::new();

    let engine: NodeEngine = EngineBuilder::default()
        .session_ttl(Duration::from_secs(ipc.ttl_seconds))
        .build();

    let server: NodeIpcServer<NodeEngine, MockVaultProvider> =
        NodeIpcServer::new(engine, vault);

    let address: SocketAddr =
        ipc.address.parse().map_err(|error: std::net::AddrParseError| {
            Errors::ConfigError(error.to_string())
        })?;

    let auth_layer: RequestInterceptorLayer<BearerAuthInterceptor> =
        RequestInterceptorLayer::new(BearerAuthInterceptor::new(
            ipc.auth.token.clone(),
        ));

    let reflection_service: ServerReflectionServer<_> =
        ReflectionBuilder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .map_err(|error: Error| Errors::ConfigError(error.to_string()))?;

    // Bind before signalling readiness so tests can connect immediately.
    let listener: TcpListener = TcpListener::bind(address)
        .await
        .map_err(|error: IoError| Errors::ConfigError(error.to_string()))?;

    ready.send(()).ok();

    let incoming: IncomingStream =
        unfold(listener, |listener: TcpListener| -> BoxFuture<'static, _> {
            Box::pin(async move {
                let result: Result<TcpStream, IoError> =
                    listener.accept().await.map(
                        |(tcp_stream, _): (TcpStream, SocketAddr)| tcp_stream,
                    );
                Some((result, listener))
            })
        });

    Server::builder()
        .layer(ConcurrencyLimitLayer::new(100))
        .layer(TimeoutLayer::new(Duration::from_secs(600)))
        .layer(auth_layer)
        .add_service(reflection_service)
        .add_service(NodeServer::new(server))
        .serve_with_incoming(incoming)
        .await?;

    Ok(())
}

/// Spawn the controller runtime and return a receiver that signals when the
/// controller is ready.
pub async fn spawn_controller() -> Receiver<()> {
    let (ready_transmitter, ready_receiver): (Sender<()>, Receiver<()>) =
        channel();
    let cluster_config: &ClusterConfig = ClusterConfig::get();

    let nodes: Vec<NodeConfig> = (0..cluster_config.node_count)
        .map(|index: usize| NodeConfig {
            endpoint: cluster_config.node_endpoint(index),
            participant_identifier: cluster_config.node_participant_id(index),
            auth: AuthConfig { token: cluster_config.node_token(index) },
        })
        .collect();

    let config: ControllerRuntimeConfig = ControllerRuntimeConfig {
        ipc: ControllerIpcConfig {
            address: cluster_config.controller_address(),
            auth: AuthConfig {
                token: cluster_config.controller_token.clone(),
            },
        },
        nodes,
    };

    tokio_spawn(async move {
        ControllerRuntime::run(config, ready_transmitter).await.unwrap();
    });

    ready_receiver
}

/// Start the cluster by spawning the controller and all nodes. This function
/// ensures that the cluster is only started once, even if called multiple
/// times across different tests.
pub async fn start_cluster_once() {
    static READY: OnceCell<()> = OnceCell::const_new();

    READY
        .get_or_init(|| async {
            let _ = fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();

            let cluster_config: &ClusterConfig = ClusterConfig::get();

            let (ready_transmitter, ready_receiver): (
                Sender<()>,
                Receiver<()>,
            ) = channel::<()>();

            spawn(move || {
                let runtime: Runtime =
                    Builder::new_multi_thread().enable_all().build().unwrap();

                let _guard: EnterGuard<'_> = runtime.enter();

                runtime.block_on(async move {
                    let node_receivers: Vec<Receiver<()>> = join_all(
                        (0..cluster_config.node_count).map(spawn_node),
                    )
                    .await;

                    join_all(node_receivers.into_iter().map(
                        |ready_receiver: Receiver<()>| async move {
                            ready_receiver.await.unwrap();
                        },
                    ))
                    .await;

                    let controller_receiver: Receiver<()> =
                        spawn_controller().await;

                    controller_receiver.await.unwrap();

                    let _ = ready_transmitter.send(());

                    // Block forever to keep nodes and controller alive.
                    pending::<()>().await;
                });
            });

            ready_receiver.await.unwrap();
        })
        .await;
}
