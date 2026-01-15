//! Types for secrets.

use crate::secrets::secret::Secret;

/// Key share bytes (opaque).
pub type KeyShare = Secret<Vec<u8>>;
