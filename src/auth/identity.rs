//! Defines the various identities that can interact with the engine.

/// An identity can be a node, an controller service, or an admin user.
#[derive(Debug, Clone)]
pub enum Identity {
    /// A node participating in the MPC protocol.
    Node {
        /// Unique node identifier.
        node_id: String,
        /// Participant identifier within the session.
        participant_id: u32,
    },

    /// An controller service managing sessions.
    Controller {
        /// Service identifier.
        service_id: String,
    },
}
