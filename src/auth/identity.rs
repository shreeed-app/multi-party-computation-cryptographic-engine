//! Defines the various identities that can interact with the engine.

/// An identity can be a peer node, an orchestrator service, or an admin user.
#[derive(Debug, Clone)]
pub enum Identity {
    /// A peer node participating in the MPC protocol.
    Node {
        /// Unique node identifier.
        node_id: String,
        /// Participant identifier within the session.
        participant_id: u32,
    },

    /// An orchestrator service managing sessions.
    Controller {
        /// Service identifier.
        service_id: String,
    },
}
