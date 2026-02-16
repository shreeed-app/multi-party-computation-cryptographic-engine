//! Protocol factory definitions.

use crate::{
    protocols::{
        algorithm::Algorithm,
        cggmp24::node::tasks::ecdsa_secp256k1::Cggmp24EcdsaSecp256k1NodeSigning,
        frost::node::{
            keys::{
                ed25519::FrostEd25519NodeKeyGeneration,
                schnorr_secp256k1::FrostSchnorrSecp256k1NodeKeyGeneration,
            },
            tasks::{
                ed25519::FrostEd25519NodeSigning,
                schnorr_secp256k1::FrostSchnorrSecp256k1NodeSigning,
            },
        },
        protocol::Protocol,
        types::{KeyGenerationInit, ProtocolInit, SigningInit},
    },
    transport::error::Error,
};

/// Factory responsible for instantiating protocols.
pub struct ProtocolFactory;

impl ProtocolFactory {
    /// Create a new protocol instance.
    ///
    /// # Arguments
    /// * `protocol_init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Error::UnsupportedAlgorithm` if the algorithm is not supported or
    ///   the role (Controller) is not implemented yet.
    ///
    /// # Returns
    /// * `Box<dyn Protocol>` - Initialized protocol instance.
    pub fn create(
        protocol_init: ProtocolInit,
    ) -> Result<Box<dyn Protocol>, Error> {
        match protocol_init {
            ProtocolInit::KeyGeneration(init) => match init {
                KeyGenerationInit::Node(init) => match init.common.algorithm {
                    // Frost ed25519 node key generation.
                    Algorithm::FrostEd25519 => {
                        Ok(Box::new(FrostEd25519NodeKeyGeneration::try_new(
                            ProtocolInit::KeyGeneration(
                                KeyGenerationInit::Node(init),
                            ),
                        )?))
                    },
                    // Frost schnorr secp256k1 node key generation.
                    Algorithm::FrostSchnorrSecp256k1 => Ok(Box::new(
                        FrostSchnorrSecp256k1NodeKeyGeneration::try_new(
                            ProtocolInit::KeyGeneration(
                                KeyGenerationInit::Node(init),
                            ),
                        )?,
                    )),
                    // CGGMP-24 secp256k1 node key generation.
                    Algorithm::Cggmp24EcdsaSecp256k1 => Ok(Box::new(
                        Cggmp24EcdsaSecp256k1NodeSigning::try_new(
                            ProtocolInit::KeyGeneration(
                                KeyGenerationInit::Node(init),
                            ),
                        )?,
                    )),
                },

                KeyGenerationInit::Controller(_) => {
                    Err(Error::UnsupportedAlgorithm(
                        "Controller key generation not implemented".into(),
                    ))
                },
            },

            ProtocolInit::Signing(init) => match init {
                SigningInit::Node(init) => match init.common.algorithm {
                    // Frost ed25519 node signing.
                    Algorithm::FrostEd25519 => {
                        Ok(Box::new(FrostEd25519NodeSigning::try_new(
                            ProtocolInit::Signing(SigningInit::Node(init)),
                        )?))
                    },
                    // Frost schnorr secp256k1 node signing.
                    Algorithm::FrostSchnorrSecp256k1 => Ok(Box::new(
                        FrostSchnorrSecp256k1NodeSigning::try_new(
                            ProtocolInit::Signing(SigningInit::Node(init)),
                        )?,
                    )),
                    // CGGMP-24 secp256k1 node signing.
                    Algorithm::Cggmp24EcdsaSecp256k1 => Ok(Box::new(
                        Cggmp24EcdsaSecp256k1NodeSigning::try_new(
                            ProtocolInit::Signing(SigningInit::Node(init)),
                        )?,
                    )),
                },

                SigningInit::Controller(_) => {
                    Err(Error::UnsupportedAlgorithm(
                        "Controller signing not implemented".into(),
                    ))
                },
            },
        }
    }
}
