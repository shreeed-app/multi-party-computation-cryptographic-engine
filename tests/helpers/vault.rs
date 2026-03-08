// tests/helpers/vault.rs

use mpc_signer_engine::secrets::vault::config::VaultConfig;

use crate::helpers::config::ClusterConfig;

/// Construct a `VaultConfig` for the tests based on the cluster configuration.
/// This function reads the necessary Vault configuration values from the
/// global cluster configuration and constructs a `VaultConfig` instance that
/// can be used by the node runtimes to connect to the Vault server and perform
/// secret storage and retrieval operations during the tests.
///
/// # Returns
/// * `VaultConfig` - A configuration struct containing the Vault connection
///   details, including the address, mount path, key prefix, field name,
///   authentication token, and optional namespace
pub fn vault_config() -> VaultConfig {
    let cluster_config: &ClusterConfig = ClusterConfig::get();

    VaultConfig {
        address: cluster_config.vault_address.clone(),
        mount: cluster_config.vault_mount.clone(),
        prefix: cluster_config.vault_prefix.clone(),
        field: cluster_config.vault_field.clone(),
        token: Some(cluster_config.vault_token.clone()),
        namespace: cluster_config.vault_namespace.clone(),
    }
}
