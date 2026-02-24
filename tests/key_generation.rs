use mpc_signer_engine::{
    auth::bearer_client::ClientAuthInterceptor,
    config::{
        controller::{ControllerRuntimeConfig, NodeConfig},
        ipc::{AuthConfig, ControllerIpcConfig, NodeIpcConfig},
        node::NodeRuntimeConfig,
    },
    proto::signer::v1::{
        GenerateKeyRequest,
        GenerateKeyResponse,
        controller_client::ControllerClient,
    },
    protocols::algorithm::Algorithm,
    runtime::{
        api::RuntimeApi,
        controller::ControllerRuntime,
        node::NodeRuntime,
    },
    secrets::vault::config::VaultConfig,
};

mod helpers;

use tokio::{
    spawn,
    time::{Duration, sleep},
};
use tonic::{service::interceptor::InterceptedService, transport::Channel};

async fn spawn_node(port: u16, participant_id: u32, token: &str) {
    let config: NodeRuntimeConfig = NodeRuntimeConfig {
        ipc: NodeIpcConfig {
            node_id: participant_id.to_string(),
            participant_id,
            address: format!("127.0.0.1:{port}"),
            ttl_seconds: 60,
            auth: AuthConfig { token: token.to_string() },
        },
        vault: VaultConfig {
            address: "http://127.0.0.1:8201".to_string(),
            mount: "secret".to_string(),
            prefix: "mpc/shares".to_string(),
            field: "share".to_string(),
            token: Some("token".to_string()),
            namespace: None,
        },
    };

    spawn(async move {
        NodeRuntime::run(config).await.unwrap();
    });
}

async fn spawn_controller() {
    let config: ControllerRuntimeConfig = ControllerRuntimeConfig {
        ipc: ControllerIpcConfig {
            address: "127.0.0.1:6000".to_string(),
            service_id: "controller".to_string(),
            auth: AuthConfig { token: "0".to_string() },
        },
        nodes: vec![
            NodeConfig {
                endpoint: "http://127.0.0.1:50051".to_string(),
                participant_id: 1,
                auth: AuthConfig { token: "1".to_string() },
            },
            NodeConfig {
                endpoint: "http://127.0.0.1:50052".to_string(),
                participant_id: 2,
                auth: AuthConfig { token: "2".to_string() },
            },
            NodeConfig {
                endpoint: "http://127.0.0.1:50053".to_string(),
                participant_id: 3,
                auth: AuthConfig { token: "3".to_string() },
            },
        ],
    };

    spawn(async move {
        ControllerRuntime::run(config).await.unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frost_ed25519_keygen_3of3_runtime_real_auth() {
    spawn_node(50051, 1, "1").await;
    spawn_node(50052, 2, "2").await;
    spawn_node(50053, 3, "3").await;

    spawn_controller().await;

    sleep(Duration::from_millis(800)).await;

    let channel: Channel =
        Channel::from_static("http://127.0.0.1:6000").connect().await.unwrap();

    let interceptor: ClientAuthInterceptor = ClientAuthInterceptor {
        config: AuthConfig {
        token: "0".to_string(), // Controller IPC token
    },
    };

    let mut client: ControllerClient<
        InterceptedService<Channel, ClientAuthInterceptor>,
    > = ControllerClient::with_interceptor(channel, interceptor);

    let request: GenerateKeyRequest = GenerateKeyRequest {
        key_id: "frost-runtime-3of3".to_string(),
        threshold: 3,
        participants: 3,
        algorithm: Algorithm::FrostEd25519.as_str().into(),
    };

    let response: GenerateKeyResponse = client
        .generate_key(request)
        .await
        .expect("keygen failed")
        .into_inner();

    println!("Public key: {:?}", response.result);
}
