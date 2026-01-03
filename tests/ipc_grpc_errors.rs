//! Tests for IPC gRPC error propagation.
use std::net::SocketAddr;

use mpc_signer_engine::auth::session::identifier::SessionId;
use mpc_signer_engine::engine::EngineApi;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Code, Status};

use mpc_signer_engine::auth::ipc::server::IpcServer;
use mpc_signer_engine::messages::error::Error;
use mpc_signer_engine::proto::signer::v1::{
    StartSessionRequest, mpc_signer_client::MpcSignerClient,
    mpc_signer_server::MpcSignerServer,
};

use crate::helpers::mock_auth::AllowAllAuth;

pub mod helpers;

/// Engine that always errors
struct FailingEngine;

impl EngineApi for FailingEngine {
    fn start_session(
        &self,
        _key_id: &str,
        _algorithm: &str,
        _threshold: u32,
        _participants: u32,
        _message: &[u8],
    ) -> Result<SessionId, Error> {
        Err(Error::UnsupportedAlgorithm)
    }

    fn submit_round(
        &self,
        _: &str,
        _: u32,
        _: &[u8],
    ) -> Result<(Vec<u8>, bool), Error> {
        Err(Error::UnsupportedAlgorithm)
    }

    fn finalize_session(&self, _: &str) -> Result<Vec<u8>, Error> {
        Err(Error::UnsupportedAlgorithm)
    }

    fn abort_session(&self, _: &str) -> Result<(), Error> {
        Err(Error::UnsupportedAlgorithm)
    }
}

#[tokio::test]
pub async fn propagates_engine_error() {
    let listener: TcpListener =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();

    let server: IpcServer<AllowAllAuth, FailingEngine> =
        IpcServer::new(FailingEngine, AllowAllAuth);

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
        algorithm: "_".into(),
        threshold: 2,
        participants: 3,
        message: vec![],
    };

    let error: Status =
        client.start_session(start_session_request).await.unwrap_err();

    assert_eq!(error.code(), Code::InvalidArgument);
}
