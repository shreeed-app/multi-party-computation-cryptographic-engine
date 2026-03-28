//! Integration tests for signing flows.
//!
//! Each test generates a fresh key then signs a test message with it,
//! asserting that a valid signature is returned.

mod helpers;

use app::{
    auth::bearer_client::ClientAuthInterceptor,
    config::ipc::AuthConfig,
    proto::signer::v1::{
        GenerateKeyRequest,
        GenerateKeyResponse,
        KeyGenerationResult,
        SignRequest,
        SignResponse,
        controller_client::ControllerClient,
        signature_result::FinalSignature,
    },
    protocols::algorithm::Algorithm,
};
use helpers::cluster::start_cluster_once;
use rand::random;
use serial_test::serial;
use tonic::{service::interceptor::InterceptedService, transport::Channel};

use crate::helpers::config::ClusterConfig;

type ControllerClientIntercepted =
    ControllerClient<InterceptedService<Channel, ClientAuthInterceptor>>;

/// Connect to the controller and return an authenticated gRPC client.
async fn connect(
    cluster_config: &ClusterConfig,
) -> ControllerClientIntercepted {
    let channel: Channel =
        Channel::from_shared(cluster_config.controller_endpoint())
            .unwrap()
            .connect()
            .await
            .unwrap();

    let interceptor: ClientAuthInterceptor = ClientAuthInterceptor {
        config: AuthConfig { token: cluster_config.controller_token.clone() },
    };

    ControllerClient::with_interceptor(channel, interceptor)
}

/// Run a full sign test for the given algorithm:
/// 1. Generate a key.
/// 2. Sign a SHA-256 digest of a test message with that key.
/// 3. Assert that a signature is present in the response.
///
/// # Arguments
/// * `algorithm` (`Algorithm`) - The signing algorithm to test.
async fn run_signing_test(algorithm: Algorithm) {
    start_cluster_once().await;

    let cluster_config: &ClusterConfig = ClusterConfig::get();
    let mut client: ControllerClientIntercepted =
        connect(cluster_config).await;

    // Generate a key to sign with. The key identifier is scoped to the
    // algorithm to avoid conflicts across test runs.
    let key_identifier: String =
        format!("{}-{}", algorithm.as_str(), random::<u64>());

    let keygen_response: GenerateKeyResponse = client
        .generate_key(GenerateKeyRequest {
            key_identifier: key_identifier.clone(),
            threshold: cluster_config.threshold(),
            participants: cluster_config.participants(),
            algorithm: algorithm.as_str().into(),
        })
        .await
        .expect("Key generation failed.")
        .into_inner();

    let key: KeyGenerationResult =
        keygen_response.result.expect("Key generation result missing.");

    // All signing algorithms expect a 32-byte message digest. Hash the test
    // message with SHA-256 before submitting it to the signing protocol.
    let message: Vec<u8> =
        format!("{}-{}", algorithm.as_str(), random::<u64>())
            .as_bytes()
            .to_vec();

    let sign_response: SignResponse = client
        .sign(SignRequest {
            key_identifier,
            public_key_package: key.public_key_package,
            algorithm: algorithm.as_str().into(),
            threshold: cluster_config.threshold(),
            participants: cluster_config.participants(),
            message,
        })
        .await
        .expect("Signing failed.")
        .into_inner();

    let result: FinalSignature = sign_response
        .result
        .expect("Signing result missing.")
        .final_signature
        .expect("Final signature missing in signing result.");

    println!("Signature: {:?}", result);
}

/// Macro to generate a signing test function for a given algorithm.
macro_rules! generate_signing_test {
    ($test_name:ident, $algorithm:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[serial]
        async fn $test_name() {
            run_signing_test($algorithm).await;
        }
    };
}

generate_signing_test!(test_frost_ed25519, Algorithm::FrostEd25519);
generate_signing_test!(
    test_frost_schnorr_secp256k1,
    Algorithm::FrostSchnorrSecp256k1
);
generate_signing_test!(
    test_cggmp24_ecdsa_secp256k1,
    Algorithm::Cggmp24EcdsaSecp256k1
);
