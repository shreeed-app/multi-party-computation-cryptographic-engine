//! FROST-based protocols.

// Note: both algorithm files can be combined into a single file using a macro,
// but for clarity and maintainability, they are kept separate.
pub mod ed25519;
pub mod schnorr_secp256k1;
pub mod stored_key;
pub mod wire;
