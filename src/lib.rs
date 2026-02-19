//! Library.

#![feature(register_tool)]
#![feature(impl_trait_in_bindings)]
#![register_tool(dylint)]
#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![deny(
    dylint::security_panic_usage,
    dylint::security_indexing_usage,
    dylint::security_missing_type,
    dylint::security_unsafe_usage
)]

pub mod auth;
pub mod config;
pub mod logging;
pub mod protocols;
pub mod runtime;
pub mod secrets;
pub mod service;
pub mod transport;

/// Protobuf generated code.
/// Allow warnings about dylint security lints in generated code: we don't want
/// to modify generated code, and it may contain patterns that trigger security
/// lints but are safe in this context.
#[allow(warnings)]
#[allow(
    security_panic_usage,
    security_indexing_usage,
    security_missing_type,
    security_unsafe_usage
)]
pub mod proto {
    /// Signer service definitions.
    pub mod signer {
        /// Version 1 of the signer service.
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/signer.v1.rs"));
        }
    }

    /// Protobuf file descriptor set used for gRPC reflection.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/proto_descriptor.bin"));
}
