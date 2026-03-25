use std::{fmt::Debug, str::FromStr, sync::OnceLock};

use dotenvy::{dotenv, var};
use strum_macros::AsRefStr;

/// Environment variable keys used to configure the test cluster.
#[derive(AsRefStr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
enum EnvKey {
    NodeCount,
    ControllerHost,
    ControllerPort,
    ControllerToken,
    NodeBasePort,
    NodeBaseToken,
}

impl EnvKey {
    /// Read the environment variable, returning `None` if absent or empty.
    ///
    /// # Returns
    /// * `Option<String>` - The value of the environment variable, or `None`
    ///   if it is not set or is empty.
    pub fn read(&self) -> Option<String> {
        var(self.as_ref()).ok().filter(|value: &String| !value.is_empty())
    }

    /// Read and parse into `T`, returning `default` if the variable is absent.
    /// Panics if the variable is present but cannot be parsed.
    ///
    /// # Type Parameters
    /// * `T` - The type to parse the environment variable into. Must implement
    ///   `FromStr` and have a `Debug` error type.
    ///
    /// # Returns
    /// * `T` - The parsed value, or `default` when the variable is unset.
    ///
    /// # Panics
    /// * If the environment variable is present but cannot be parsed into `T`.
    pub fn with_default<T>(&self, default: T) -> T
    where
        T: FromStr,
        T::Err: Debug,
    {
        match self.read() {
            Some(value) => {
                value.parse().unwrap_or_else(|error: <T as FromStr>::Err| {
                    panic!("Invalid value for {}: {:?}", self.as_ref(), error)
                })
            },
            None => default,
        }
    }
}

/// Fully resolved cluster configuration, loaded once from environment
/// variables (with `.env` fallback via dotenvy).
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Number of nodes in the cluster.
    pub node_count: usize,
    /// Controller bind/connect host.
    pub controller_host: String,
    /// Controller bind/connect port.
    pub controller_port: u16,
    /// Controller bearer token.
    pub controller_token: String,
    /// Port for node 1; node N uses `node_base_port + (N - 1)`.
    pub node_base_port: u16,
    /// Token prefix; node N gets `<prefix><N>`.
    pub node_token_prefix: String,
}

impl ClusterConfig {
    /// Load configuration from environment variables, with `.env` as fallback.
    /// All variables are optional and fall back to sensible defaults so that
    /// tests work out-of-the-box without a `.env` file.
    fn load() -> Self {
        // Best-effort — silently ignored if .env is absent.
        let _ = dotenv();

        Self {
            node_count: EnvKey::NodeCount.with_default(3usize),
            controller_host: EnvKey::ControllerHost
                .with_default("127.0.0.1".to_string()),
            controller_port: EnvKey::ControllerPort.with_default(50051u16),
            controller_token: EnvKey::ControllerToken
                .with_default("controller-".to_string()),
            node_base_port: EnvKey::NodeBasePort.with_default(50052u16),
            node_token_prefix: EnvKey::NodeBaseToken
                .with_default("node-".to_string()),
        }
    }

    /// Global singleton — loaded once, shared across all tests.
    ///
    /// # Returns
    /// * `&'static Self` - A reference to the global cluster configuration
    ///   instance.
    pub fn get() -> &'static Self {
        static INSTANCE: OnceLock<ClusterConfig> = OnceLock::new();
        INSTANCE.get_or_init(Self::load)
    }

    /// Signing threshold — equal to `node_count` (all-n signing).
    ///
    /// # Returns
    /// * `u32` - The signing threshold for the cluster, which is equal to the
    ///   total number of nodes (i.e., all nodes must participate in signing).
    pub fn threshold(&self) -> u32 {
        self.node_count as u32
    }

    /// Total participant count — equal to `node_count`.
    ///
    /// # Returns
    /// * `u32` - The total number of participants in the cluster, which is
    ///   equal to the number of nodes.
    pub fn participants(&self) -> u32 {
        self.node_count as u32
    }

    /// Controller bind address (`host:port`).
    ///
    /// # Returns
    /// * `String` - The bind address for the controller, formatted as
    ///   `host:port`.
    pub fn controller_address(&self) -> String {
        format!("{}:{}", self.controller_host, self.controller_port)
    }

    /// Controller gRPC endpoint (`http://host:port`).
    ///
    /// # Returns
    /// * `String` - The gRPC endpoint for the controller, formatted as `http://host:port`.
    pub fn controller_endpoint(&self) -> String {
        format!("http://{}:{}", self.controller_host, self.controller_port)
    }

    /// Port for node at `index` (0-based).
    ///
    /// # Arguments
    /// * `index` (`usize`) - The 0-based index of the node for which to
    ///   calculate the port.
    pub fn node_port(&self, index: usize) -> u16 {
        self.node_base_port + index as u16
    }

    /// 1-based participant ID for node at `index` (0-based).
    ///
    /// # Arguments
    /// * `index` (`usize`) - The 0-based index of the node for which to
    ///   calculate the participant ID.
    ///
    /// # Returns
    /// * `u32` - The participant ID for the node, calculated as `index + 1` to
    ///   ensure it starts from 1.
    pub fn node_participant_id(&self, index: usize) -> u32 {
        (index + 1) as u32
    }

    /// Bearer token for node at `index` (0-based).
    ///
    /// # Arguments
    /// * `index` (`usize`) - The 0-based index of the node for which to
    ///   calculate the token.
    ///
    /// # Returns
    /// * `String` - The bearer token for the node, constructed by
    ///   concatenating the `node_token_prefix` with the participant ID (e.g.,
    ///   if the prefix is "node-token-" and the participant ID is 1, the token
    ///   would be "node-token-1").
    pub fn node_token(&self, index: usize) -> String {
        format!(
            "{}{}",
            self.node_token_prefix,
            self.node_participant_id(index)
        )
    }

    /// gRPC endpoint for node at `index` (0-based).
    ///
    /// # Arguments
    /// * `index` (`usize`) - The 0-based index of the node for which to
    ///   calculate the endpoint.
    ///
    /// # Returns
    /// * `String` - The gRPC endpoint for the node, formatted as `http://host:port`,
    ///   where `host` is `127.0.0.1`.
    pub fn node_endpoint(&self, index: usize) -> String {
        format!("http://127.0.0.1:{}", self.node_port(index))
    }
}
