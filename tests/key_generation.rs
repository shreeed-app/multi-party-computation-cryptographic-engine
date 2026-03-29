//! Integration tests for key generation flows.

mod helpers;

use app::{
    auth::bearer_client::ClientAuthInterceptor,
    config::ipc::AuthConfig,
    proto::signer::v1::{
        GenerateKeyRequest,
        GenerateKeyResponse,
        KeyGenerationResult,
        controller_client::ControllerClient,
    },
    protocols::algorithm::Algorithm,
};
use helpers::cluster::start_cluster_once;
use rand::random;
use serial_test::serial;
use tonic::{service::interceptor::InterceptedService, transport::Channel};

use crate::helpers::config::ClusterConfig;

/// Run a key generation test for the given algorithm, connecting to the
/// controller and asserting a successful response.
///
/// # Arguments
/// * `algorithm` (`Algorithm`) - The key generation algorithm to test (e.g.,
///   FROST with Ed25519, FROST with Schnorr over secp256k1, CGGMP24 with ECDSA
///   over secp256k1).
async fn run_key_generation_test(algorithm: Algorithm) {
    start_cluster_once().await;

    let cluster_config: &ClusterConfig = ClusterConfig::get();

    // Connect to the controller using a gRPC client with bearer token
    // authentication.
    let channel: Channel =
        Channel::from_shared(cluster_config.controller_endpoint())
            .unwrap()
            .connect()
            .await
            .unwrap();

    // Create an authentication interceptor using the controller token from the
    // cluster configuration. This interceptor will add the necessary
    // authentication headers to each gRPC request made by the client.
    let interceptor: ClientAuthInterceptor = ClientAuthInterceptor {
        config: AuthConfig { token: cluster_config.controller_token.clone() },
    };

    // Create a gRPC client for the controller, wrapped with the authentication
    // interceptor. This client will be used to send the key generation request
    // to the controller.
    let mut client: ControllerClient<
        InterceptedService<Channel, ClientAuthInterceptor>,
    > = ControllerClient::with_interceptor(channel, interceptor);

    // Send the key generation request to the controller and await the
    // response. If the request fails (e.g., due to a connection error or
    // server error), the test will panic with the message "Key generation
    // failed."
    let response: GenerateKeyResponse = client
        .generate_key(GenerateKeyRequest {
            key_identifier: format!(
                "{}-{}",
                algorithm.as_str(),
                random::<u64>()
            ),
            threshold: cluster_config.threshold(),
            participants: cluster_config.participants(),
            algorithm: algorithm.as_str().into(),
        })
        .await
        .expect("Key generation failed.")
        .into_inner();

    let key: KeyGenerationResult =
        response.result.expect("Key generation result missing.");

    assert!(!key.public_key.is_empty(), "Public key is empty.");
    assert!(
        !key.public_key_package.is_empty(),
        "Public key package is empty."
    );

    println!(
        "Public key: {:?} \nPublic key package: {:?}",
        key.public_key, key.public_key_package,
    );
}

/// Macro to generate a test function for a given algorithm.
/// Each test runs the key generation flow 3 times to catch race conditions
/// and non-deterministic failures.
macro_rules! generate_algo_test {
    ($test_name:ident, $algorithm:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn $test_name() {
            run_key_generation_test($algorithm).await;
        }
    };
}

generate_algo_test!(test_frost_ed25519, Algorithm::FrostEd25519);
generate_algo_test!(
    test_frost_schnorr_secp256k1,
    Algorithm::FrostSchnorrSecp256k1
);
generate_algo_test!(
    test_cggmp24_ecdsa_secp256k1,
    Algorithm::Cggmp24EcdsaSecp256k1
);
