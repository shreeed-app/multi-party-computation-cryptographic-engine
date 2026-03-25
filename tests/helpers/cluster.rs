use std::{future::pending, thread::spawn};

use app::{
    config::{
        controller::{ControllerRuntimeConfig, NodeConfig},
        ipc::{AuthConfig, ControllerIpcConfig, NodeIpcConfig},
        node::NodeRuntimeConfig,
    },
    runtime::{
        api::RuntimeApi,
        controller::ControllerRuntime,
        node::NodeRuntime,
    },
};
use futures::future::join_all;
use tokio::{
    runtime::Builder,
    spawn as tokio_spawn,
    sync::{
        OnceCell,
        oneshot::{Receiver, Sender, channel},
    },
};
use tracing_subscriber::{EnvFilter, fmt};

use crate::helpers::{config::ClusterConfig, vault::vault_config};

/// Spawn a node runtime with the given index and return a receiver that
/// signals when the node is ready.
///
/// # Arguments
/// * `index` (`usize`) - The 0-based index of the node to spawn. This index is
///   used to calculate the node's participant ID, port, and token based on the
///   cluster configuration.
///
/// # Returns
/// * `Receiver<()>` - A oneshot receiver that will receive a signal when the
///   node is ready. The sender for this receiver is passed to the node
///   runtime, which will send the signal once it has completed its
///   initialization and is ready to accept requests.
pub async fn spawn_node(index: usize) -> Receiver<()> {
    let (ready_transmitter, ready_receiver): (Sender<()>, Receiver<()>) =
        channel();
    let cluster_config: &ClusterConfig = ClusterConfig::get();

    let config: NodeRuntimeConfig = NodeRuntimeConfig {
        ipc: NodeIpcConfig {
            node_identifier: cluster_config
                .node_participant_id(index)
                .to_string(),
            participant_identifier: cluster_config.node_participant_id(index),
            address: format!("127.0.0.1:{}", cluster_config.node_port(index)),
            ttl_seconds: 600,
            auth: AuthConfig { token: cluster_config.node_token(index) },
        },
        vault: vault_config(),
    };

    tokio_spawn(async move {
        NodeRuntime::run(config, ready_transmitter).await.unwrap();
    });

    ready_receiver
}

/// Spawn the controller runtime and return a receiver that signals when the
/// controller is ready.
///
/// # Returns
/// * `Receiver<()>` - A oneshot receiver that will receive a signal when the
///   controller is ready. The sender for this receiver is passed to the
///   controller runtime, which will send the signal once it has completed its
///   initialization and is ready to accept requests.
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
/// times across different tests. It uses a `OnceCell` to guarantee that the
/// cluster initialization logic is executed only once, and all subsequent
/// calls will await the same initialization process if it's still in progress.
pub async fn start_cluster_once() {
    static READY: OnceCell<()> = OnceCell::const_new();

    READY
        .get_or_init(|| async {
            let _ = fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();

            let cluster_config: &ClusterConfig = ClusterConfig::get();

            // Spawn the cluster in a dedicated OS thread with its own
            // long-lived Tokio runtime — decoupled from any test runtime
            // so it survives across all tests in the binary.
            let (ready_transmitter, ready_receiver): (
                Sender<()>,
                Receiver<()>,
            ) = channel::<()>();

            spawn(move || {
                Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
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

            // Wait until the cluster signals it is ready before returning.
            ready_receiver.await.unwrap();
        })
        .await;
}
