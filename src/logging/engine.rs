//! Logging initialization utilities.

use tracing::Level;
use tracing_subscriber::{
    EnvFilter,
    Registry,
    fmt::{
        self,
        Layer,
        format::{Format, Json, JsonFields},
    },
    layer::{Layered, SubscriberExt},
    util::SubscriberInitExt,
};

/// Logging engine for initializing global logging configuration.
pub struct LoggingEngine;

impl LoggingEngine {
    /// Initialize global logging with the specified service name.
    ///
    /// # Arguments
    /// * `service_name` (`&str`) - Logical service name (e.g. "node" or
    ///   "controller").
    pub fn init(service_name: &str) {
        let env_filter: EnvFilter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(Level::INFO.to_string()));

        let formatting_layer: Layer<
            Layered<EnvFilter, Registry>,
            JsonFields,
            Format<Json>,
        > = fmt::layer()
            .json()
            .with_target(false)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_current_span(true)
            .with_span_list(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(formatting_layer)
            .init();

        tracing::info!(service = service_name, "Logging initialized.");
    }
}
