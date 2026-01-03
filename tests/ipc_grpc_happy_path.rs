//! Tests for IPC gRPC happy path scenarios.
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

use mpc_signer_engine::auth::ipc::server::IpcServer;
use mpc_signer_engine::proto::signer::v1::{
    StartSessionRequest, StartSessionResponse,
    mpc_signer_client::MpcSignerClient, mpc_signer_server::MpcSignerServer,
};

use crate::helpers::mock_auth::AllowAllAuth;
use crate::helpers::mock_engine::MockEngine;

pub mod helpers;

#[tokio::test]
pub async fn start_session_happy_path() {
    let listener: TcpListener =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();

    let server: IpcServer<AllowAllAuth, MockEngine> =
        IpcServer::new(MockEngine, AllowAllAuth);

    tokio::spawn(async move {
        Server::builder()
            .add_service(MpcSignerServer::new(server))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let mut client: MpcSignerClient<Channel> =
        MpcSignerClient::connect(format!("http://{}", address)).await.unwrap();

    let start_session_request: StartSessionRequest = StartSessionRequest {
        key_id: "0".into(),
        algorithm: "frost-ed25519".into(),
        threshold: 2,
        participants: 3,
        message: vec![1, 2, 3],
    };

    let response: tonic::Response<StartSessionResponse> =
        client.start_session(start_session_request).await.unwrap();

    assert!(!response.into_inner().session_id.is_empty());
}
