//! Mock engine for testing purposes.
use mpc_signer_engine::auth::session::identifier::SessionId;
use mpc_signer_engine::engine::api::EngineApi;
use mpc_signer_engine::messages::error::Error;
use mpc_signer_engine::protocols::types::{
    ProtocolInit, RoundMessage, Signature,
};

/// Minimal engine mock for IPC tests.
#[derive(Clone)]
pub struct MockEngine;

impl EngineApi for MockEngine {
    fn start_session(
        &self,
        _init: ProtocolInit,
    ) -> Result<(SessionId, RoundMessage), Error> {
        Ok((SessionId::new(), RoundMessage { round: 0, payload: vec![] }))
    }

    fn submit_round(
        &self,
        _session_id: SessionId,
        _message: RoundMessage,
    ) -> Result<RoundMessage, Error> {
        Ok(RoundMessage { round: 0, payload: vec![] })
    }

    fn finalize(&self, _session_id: SessionId) -> Result<Signature, Error> {
        Ok(Signature { bytes: vec![] })
    }

    fn abort(&self, _session_id: SessionId) -> Result<(), Error> {
        Ok(())
    }
}
