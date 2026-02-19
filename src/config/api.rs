//! Runtime configuration API.

use crate::transport::errors::Errors;

/// Runtime configuration API trait defining the interface for loading runtime
/// configurations from files.
pub trait RuntimeConfig {
    /// Load configuration from a file path.
    ///
    /// # Arguments
    /// * `path` (`&str`) - Path to the configuration file.
    ///
    /// # Errors
    /// * `Error` - If file reading or parsing fails.
    ///
    /// # Returns
    /// * `Self` - Loaded configuration instance.
    fn load_from_file(path: &str) -> Result<Self, Errors>
    where
        Self: Sized;
}
