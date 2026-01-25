//! Live session entry definition.

use std::sync::Mutex;

use crate::{
    auth::session::state::SessionState,
    protocols::signing::SigningProtocol,
};

/// A live session entry held in memory.
/// The protocol is protected by a mutex to guarantee
/// single-threaded execution per session.
pub struct SessionEntry {
    /// Current session state.
    pub state: SessionState,
    /// Underlying signing protocol instance.
    pub protocol: Mutex<Box<dyn SigningProtocol>>,
}
