//! Session policy for authorizing actions based on identity.

use crate::{auth::identity::Identity, transport::error::Error};

/// Session policy for authorizing actions based on identity.
pub struct SessionPolicy;

impl SessionPolicy {
    /// Check if the identity is a peer.
    ///
    /// # Arguments
    /// * `id` (`&Identity`) - Identity to check.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the identity is a peer, Unauthorized
    ///   error otherwise.
    fn is_member(identity: &Identity) -> Result<(), Error> {
        match identity {
            Identity::Node { .. } | Identity::Controller { .. } => Ok(()),
            // This line can be uncommented for future identity types that are
            // not authorized.
            // _ => Err(Error::Unauthorized),
        }
    }

    /// Check if the identity can start a signing session.
    ///
    /// # Arguments
    /// * `id` (`&Identity`) - Identity to check.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the identity can start a signing session,
    ///   Unauthorized error otherwise.
    pub fn can_start_signing_session(
        identity: &Identity,
    ) -> Result<(), Error> {
        Self::is_member(identity)
    }

    /// Check if the identity can start a key generation session.
    ///
    /// # Arguments
    /// * `id` (`&Identity`) - Identity to check.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the identity can start a key generation
    ///   session, Unauthorized error otherwise.
    pub fn can_start_key_generation_session(
        identity: &Identity,
    ) -> Result<(), Error> {
        Self::is_member(identity)
    }

    /// Check if the identity can submit a round.
    ///
    /// # Arguments
    /// * `id` (`&Identity`) - Identity to check.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the identity can submit a round,
    ///   Unauthorized error otherwise.
    pub fn can_submit_round(identity: &Identity) -> Result<(), Error> {
        Self::is_member(identity)
    }

    /// Check if the identity can abort a session.
    ///
    /// # Arguments
    /// * `id` (`&Identity`) - Identity to check.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the identity can abort a session,
    ///   Unauthorized error otherwise.
    pub fn can_abort_session(identity: &Identity) -> Result<(), Error> {
        Self::is_member(identity)
    }

    /// Check if the identity can finalize a session.
    ///
    /// # Arguments
    /// * `id` (`&Identity`) - Identity to check.
    ///
    /// # Returns
    /// * `Result<(), Error>` - Ok if the identity can finalize a session,
    ///   Unauthorized error otherwise.
    pub fn can_finalize_session(identity: &Identity) -> Result<(), Error> {
        Self::is_member(identity)
    }
}
