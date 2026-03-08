//! Session identifier management for authentication sessions.

use std::fmt::{Display, Formatter, Result};

use uuid::Uuid;

/// Unique identifier for a signing session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionIdentifier(Uuid);

impl SessionIdentifier {
    /// Generate a new random session identifier.
    ///
    /// # Returns
    /// * `Self` - A new session identifier.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Parse a session identifier from a string.
    ///
    /// # Arguments
    /// * `input` (`&str`) - Input string to parse.
    ///
    /// # Errors
    /// `Option<Self>` - Returns `None` if the input is not a valid UUID.
    pub fn parse(input: &str) -> Option<Self> {
        Uuid::parse_str(input).ok().map(Self)
    }

    /// Get the raw bytes of the session identifier.
    ///
    /// # Returns
    /// * `[u8; 16]` - The session identifier as raw bytes.
    pub fn as_bytes(&self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl Display for SessionIdentifier {
    /// Convert the session identifier to a string.
    ///
    /// # Arguments
    /// * `formatter` (`&mut Formatter<'_>`) - The formatter to write to.
    ///
    /// # Returns
    /// * `Result` - The session identifier as a string.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result {
        write!(formatter, "{}", self.0)
    }
}

impl Default for SessionIdentifier {
    /// Generate a default session identifier.
    ///
    /// # Returns
    /// * `Self` - A new random session identifier.
    fn default() -> Self {
        Self::new()
    }
}
