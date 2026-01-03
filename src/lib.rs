//! MPC Signer Engine Library

#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(missing_docs)]

pub mod auth;
pub mod engine;
pub mod messages;
pub mod protocols;
pub mod secrets;

/// Protobuf generated code.
pub mod proto {
    /// Signer service definitions.
    pub mod signer {
        /// Version 1 of the signer service.
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/signer.v1.rs"));
        }
    }
}
