//! Provides context for authenticated identities within IPC requests.

use tonic::Extensions;

use super::identity::Identity;

/// Wrapper for storing Identity in request extensions.
#[derive(Clone)]
pub struct IdentityContext(pub Identity);

/// Extension trait for accessing Identity from request extensions.
pub trait IdentityExtension {
    /// Retrieves the Identity from the extensions if present.
    ///
    /// # Returns
    /// * `Option<&Identity>` - Some reference to Identity if present, None
    ///   otherwise.
    fn identity(&self) -> Option<&Identity>;
}

impl IdentityExtension for Extensions {
    /// Retrieves the Identity from the extensions if present.
    ///
    /// # Returns
    /// * `Option<&Identity>` - Some reference to Identity if present, None
    ///   otherwise.
    fn identity(&self) -> Option<&Identity> {
        self.get::<IdentityContext>()
            .map(|context: &IdentityContext| &context.0)
    }
}
