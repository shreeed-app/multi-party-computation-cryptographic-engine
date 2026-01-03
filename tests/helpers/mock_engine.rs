//! Mock engine for testing purposes.
use mpc_signer_engine::auth::session::identifier::SessionId;
use mpc_signer_engine::engine::EngineApi;
use mpc_signer_engine::messages::error::Error;

/// Minimal engine mock for IPC tests.
#[derive(Clone)]
pub struct MockEngine;

impl EngineApi for MockEngine {
    fn start_session(
        &self,
        _key_id: &str,
        _algorithm: &str,
        _threshold: u32,
        _participants: u32,
        _message: &[u8],
    ) -> Result<SessionId, Error> {
        Ok(SessionId::new())
    }

    fn submit_round(
        &self,
        _session_id: &str,
        _round: u32,
        _payload: &[u8],
    ) -> Result<(Vec<u8>, bool), Error> {
        Ok((vec![], false))
    }

    fn finalize_session(&self, _session_id: &str) -> Result<Vec<u8>, Error> {
        Ok(vec![0xde, 0xad, 0xbe, 0xef])
    }

    fn abort_session(&self, _session_id: &str) -> Result<(), Error> {
        Ok(())
    }
}
