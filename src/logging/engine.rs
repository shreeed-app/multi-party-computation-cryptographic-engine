//! Logging initialization utilities.

use tracing::Level;
use tracing_appender::{
    non_blocking::{NonBlocking, WorkerGuard},
    rolling::{self, RollingFileAppender},
};
use tracing_subscriber::{
    EnvFilter,
    Registry,
    filter::FromEnvError,
    fmt::{
        self,
        Layer,
        format::{Format, Json, JsonFields},
    },
    layer::{Layered, SubscriberExt},
    util::SubscriberInitExt,
};

type FileLayer = Layer<
    Layered<Layer<Layered<EnvFilter, Registry>>, Layered<EnvFilter, Registry>>,
    JsonFields,
    Format<Json>,
    NonBlocking,
>;

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
            .unwrap_or_else(|error: FromEnvError| {
                tracing::warn!(
                    "Failed to initialize environment filter: {}",
                    error
                );
                EnvFilter::new(Level::INFO.to_string())
            });

        let file_appender: RollingFileAppender =
            rolling::daily("logs", "history.log");

        let (non_blocking, guard): (NonBlocking, WorkerGuard) =
            tracing_appender::non_blocking(file_appender);

        Box::leak(Box::new(guard));

        let file_layer: FileLayer = fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_current_span(true)
            .with_span_list(true);

        let console_layer: Layer<Layered<EnvFilter, Registry>> = fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(true)
            .with_thread_names(true);

        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(console_layer)
            .with(file_layer)
            .try_init();

        tracing::info!(service = service_name, "Logging initialized.");
    }
}
