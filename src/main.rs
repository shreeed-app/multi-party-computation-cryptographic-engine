//! Main entrypoint for application.

use app::{
    config::{
        api::RuntimeConfig,
        controller::ControllerRuntimeConfig,
        node::NodeRuntimeConfig,
    },
    runtime::{
        api::RuntimeApi,
        controller::ControllerRuntime,
        node::NodeRuntime,
    },
    transport::errors::Errors,
};
use clap::{Parser, Subcommand};
use tokio::sync::oneshot::{Sender, channel};

/// CLI entrypoint.
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    /// Subcommand to run either as node or controller.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    // Run as node.
    Node {
        /// Path to node configuration file.
        #[arg(short, long)]
        config: String,
    },

    /// Run as controller.
    Controller {
        /// Path to controller configuration file.
        #[arg(short, long)]
        config: String,
    },
}

/// Main entrypoint for the application.
///
/// # Errors
/// * - If any error occurs during execution.
///
/// # Returns
/// * `()` - On successful execution.
#[tokio::main]
async fn main() -> Result<(), Errors> {
    // Allow panic usage in CLI parsing as it is a common pattern and does
    // not pose a security risk in this context.
    let cli: Cli = Cli::parse();

    let (ready_transmitter, _): (Sender<()>, _) = channel();

    match cli.command {
        // Run as node.
        Command::Node { config } => {
            let runtime_config: NodeRuntimeConfig =
                NodeRuntimeConfig::load_from_file(&config)?;
            NodeRuntime::run(runtime_config, ready_transmitter).await
        },
        // Run as controller.
        Command::Controller { config } => {
            let runtime_config: ControllerRuntimeConfig =
                ControllerRuntimeConfig::load_from_file(&config)?;
            ControllerRuntime::run(runtime_config, ready_transmitter).await
        },
    }
}
