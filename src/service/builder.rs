//! Engine builder.

use std::time::Duration;

use crate::service::node_engine::NodeEngine;

/// Builder for [`Engine`] responsible for wiring runtime configuration
/// and producing a fully initialized engine instance.
pub struct EngineBuilder {
    session_ttl: Duration,
}

impl EngineBuilder {
    /// Create a new builder with default settings.
    ///
    /// # Returns
    /// * `Self` - New engine builder instance.
    pub fn new(session_ttl: Duration) -> Self {
        Self { session_ttl }
    }

    /// Override the session TTL.
    ///
    /// # Arguments
    /// * `ttl` (`Duration`) - Session time-to-live.
    pub fn session_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = ttl;
        self
    }

    /// Build the engine.
    ///
    /// # Returns
    /// * `Engine` - Fully initialized engine instance.
    pub fn build(self) -> NodeEngine {
        NodeEngine::new(self.session_ttl)
    }
}

impl Default for EngineBuilder {
    /// Create a new builder with default settings.
    ///
    /// # Returns
    /// * `Self` - New engine builder instance.
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minutes.
    }
}
