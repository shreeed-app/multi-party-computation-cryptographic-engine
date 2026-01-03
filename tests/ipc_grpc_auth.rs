//! Tests for IPC gRPC authentication mechanisms.
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Code, Status};

use mpc_signer_engine::auth::ipc::server::IpcServer;
use mpc_signer_engine::proto::signer::v1::{
    StartSessionRequest, mpc_signer_client::MpcSignerClient,
    mpc_signer_server::MpcSignerServer,
};

use crate::helpers::mock_auth::DenyAllAuth;
use crate::helpers::mock_engine::MockEngine;

pub mod helpers;

#[tokio::test]
pub async fn rejects_unauthenticated_requests() {
    let listener: TcpListener =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();

    let server: IpcServer<DenyAllAuth, MockEngine> =
        IpcServer::new(MockEngine, DenyAllAuth);

    tokio::spawn(async move {
        Server::builder()
            .add_service(MpcSignerServer::new(server))
            .serve_with_incoming::<TcpListenerStream, _, _, _>(
                TcpListenerStream::new(listener),
            )
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
        message: vec![],
    };

    let error: Status =
        client.start_session(start_session_request).await.unwrap_err();

    assert_eq!(error.code(), Code::Unauthenticated);
}
