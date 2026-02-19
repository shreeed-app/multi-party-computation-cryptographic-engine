//! Runtime API definitions.

use async_trait::async_trait;

use crate::{config::api::RuntimeConfig, transport::errors::Errors};

/// Runtime API trait defining the interface for running different types of
/// runtimes (e.g., node, controller).
#[async_trait]
pub trait RuntimeApi {
    /// Associated type for the runtime configuration.
    type Config: RuntimeConfig;

    /// Run the runtime with the given configuration.
    ///
    /// # Arguments
    /// * `config` (`NodeRuntimeConfig`) - Configuration for the runtime.
    ///
    /// # Errors
    /// * `Error` - If any error occurs during runtime execution.
    ///
    /// # Returns
    /// * `()` - On successful execution.
    async fn run(config: Self::Config) -> Result<(), Errors>
    where
        Self: Sized;
}
