use std::{net::SocketAddr, time::Duration};

use mpc_signer_engine::{
    auth::ipc::{auth::TokenAuth, config::IpcConfig, server::IpcServer},
    config::EnvConfig,
    engine::{builder::EngineBuilder, core::Engine},
    messages::error::Error,
    proto::signer::v1::signer_server::SignerServer,
    secrets::vault::{config::VaultConfig, hashicorp::HashicorpVaultProvider},
};
use tonic::transport::Server;

/// Main entry point.
/// Loads configuration, initializes components, and starts the IPC server.
///
/// # Errors
/// * `Error` - If initialization or server fails.
///
/// # Returns
/// * `()` - Nothing.
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Load environment configuration from environment variables.
    dotenvy::dotenv().ok();
    let environment_configuration: &EnvConfig = match EnvConfig::load() {
        Ok(configuration) => configuration,
        Err(error) => return Err(Error::ConfigError(error.to_string())),
    };

    // Load IPC and Vault configuration from TOML files.
    let ipc_configuration: IpcConfig =
        match IpcConfig::load(&environment_configuration.ipc_config_path) {
            Ok(configuration) => configuration,
            Err(error) => return Err(Error::ConfigError(error.to_string())),
        };
    let vault_configuration: VaultConfig = match VaultConfig::load(
        &environment_configuration.vault_config_path,
    ) {
        Ok(configuration) => configuration,
        Err(error) => return Err(Error::ConfigError(error.to_string())),
    };

    // Initialize Vault.
    let vault: HashicorpVaultProvider =
        HashicorpVaultProvider::try_from_config(vault_configuration)?;

    // Initialize authentication.
    let authentication: TokenAuth =
        TokenAuth::new(ipc_configuration.auth.token);

    // Build engine with a session TTL from IPC configuration.
    let engine: Engine = EngineBuilder::new()
        .session_ttl(Duration::from_secs(ipc_configuration.ttl_seconds))
        .build();

    // Build IPC server.
    let ipc_server: IpcServer<TokenAuth, Engine, HashicorpVaultProvider> =
        IpcServer::new(engine, authentication, vault);

    // Start gRPC server.
    let address: SocketAddr = match ipc_configuration.address.parse() {
        Ok(address) => address,
        Err(error) => return Err(Error::ConfigError(error.to_string())),
    };

    match Server::builder()
        .add_service(SignerServer::new(ipc_server))
        .serve(address)
        .await
    {
        Ok(_) => (),
        Err(error) => return Err(Error::ConfigError(error.to_string())),
    }

    Ok(())
}
