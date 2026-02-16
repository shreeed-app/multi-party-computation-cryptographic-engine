//! Live session entry definition.

use crate::{
    auth::session::state::SessionState,
    protocols::protocol::Protocol,
};

/// A live session entry held in memory.
/// The protocol is protected by a mutex to guarantee
/// single-threaded execution per session.
pub struct SessionEntry {
    /// Current session state.
    pub state: SessionState,
    /// Underlying signing protocol instance.
    pub protocol: Option<Box<dyn Protocol>>,
}
