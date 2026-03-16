//! Protocol factory definitions.

use crate::{
    protocols::{
        algorithm::Algorithm,
        cggmp24::{
            controller::{
                keys::{
                    auxiliary::ecdsa_secp256k1::Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration,
                    ecdsa_secp256k1::Cggmp24EcdsaSecp256k1ControllerKeyGeneration,
                },
                tasks::ecdsa_secp256k1::Cggmp24EcdsaSecp256k1ControllerSigning,
            },
            node::{
                keys::{
                    auxiliary::ecdsa_secp256k1::Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration,
                    ecdsa_secp256k1::Cggmp24EcdsaSecp256k1NodeKeyGeneration,
                },
                tasks::ecdsa_secp256k1::Cggmp24EcdsaSecp256k1NodeSigning,
            },
        },
        frost::{
            controller::{
                keys::FrostControllerKeyGeneration,
                tasks::{
                    ed25519::FrostEd25519ControllerSigning,
                    schnorr_secp256k1::FrostSchnorrSecp256k1ControllerSigning,
                },
            },
            node::{
                keys::{
                    ed25519::FrostEd25519NodeKeyGeneration,
                    schnorr_secp256k1::FrostSchnorrSecp256k1NodeKeyGeneration,
                },
                tasks::{
                    ed25519::FrostEd25519NodeSigning,
                    schnorr_secp256k1::FrostSchnorrSecp256k1NodeSigning,
                },
            },
        },
        protocol::Protocol,
        types::{
            AuxiliaryGenerationInit,
            KeyGenerationInit,
            ProtocolInit,
            SigningInit,
        },
    },
    transport::errors::Errors,
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
    ) -> Result<Box<dyn Protocol>, Errors> {
        tracing::debug!(?protocol_init, "Creating protocol instance.");

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
                        Cggmp24EcdsaSecp256k1NodeKeyGeneration::try_new(
                            ProtocolInit::KeyGeneration(
                                KeyGenerationInit::Node(init),
                            ),
                        )?,
                    )),
                },

                KeyGenerationInit::Controller(init) => {
                    match init.common.algorithm {
                        // Frost ed25519 node key generation.s
                        Algorithm::FrostEd25519 | Algorithm::FrostSchnorrSecp256k1 => Ok(Box::new(
                            FrostControllerKeyGeneration::try_new(
                                ProtocolInit::KeyGeneration(
                                    KeyGenerationInit::Controller(init),
                                ),
                            )?,
                        )),
                        // CGGMP-24 secp256k1 node key generation.
                        Algorithm::Cggmp24EcdsaSecp256k1 => Ok(Box::new(
                            Cggmp24EcdsaSecp256k1ControllerKeyGeneration::try_new(
                                ProtocolInit::KeyGeneration(
                                    KeyGenerationInit::Controller(init),
                                ),
                            )?,
                        )),
                    }
                },
            },

            ProtocolInit::AuxiliaryGeneration(init) => match init {
                // Auxiliary generation is currently only supported for
                // CGGMP-24 secp256k1.
                AuxiliaryGenerationInit::Node(init) => {
                    match init.common.algorithm {
                        Algorithm::Cggmp24EcdsaSecp256k1 => Ok(Box::new(
                            Cggmp24EcdsaSecp256k1NodeAuxiliaryGeneration::try_new(
                                ProtocolInit::AuxiliaryGeneration(
                                    AuxiliaryGenerationInit::Node(init),
                                ),
                            )?,
                        )),
                        algorithm => Err(Errors::UnsupportedAlgorithm(
                            format!(
                                "Auxiliary generation is not supported \
                                for this algorithm: {}", 
                                algorithm.as_str()
                            ),
                        )),
                    }
                },

                AuxiliaryGenerationInit::Controller(init) => {
                    match init.common.algorithm {
                        Algorithm::Cggmp24EcdsaSecp256k1 => Ok(Box::new(
                            Cggmp24EcdsaSecp256k1ControllerAuxiliaryGeneration::try_new(
                                ProtocolInit::AuxiliaryGeneration(
                                    AuxiliaryGenerationInit::Controller(init),
                                ),
                            )?,
                        )),
                        algorithm => Err(Errors::UnsupportedAlgorithm(
                            format!(
                                "Auxiliary generation is not supported \
                                for this algorithm: {}", 
                                algorithm.as_str()
                            ),
                        )),
                    }
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

                SigningInit::Controller(init) => match init.common.algorithm {
                    // Frost ed25519 node signing.
                    Algorithm::FrostEd25519 => {
                        Ok(Box::new(FrostEd25519ControllerSigning::try_new(
                            ProtocolInit::Signing(SigningInit::Controller(
                                init,
                            )),
                        )?))
                    },
                    // Frost schnorr secp256k1 node signing.
                    Algorithm::FrostSchnorrSecp256k1 => Ok(Box::new(
                        FrostSchnorrSecp256k1ControllerSigning::try_new(
                            ProtocolInit::Signing(SigningInit::Controller(
                                init,
                            )),
                        )?,
                    )),
                    // CGGMP-24 secp256k1 node signing.
                    Algorithm::Cggmp24EcdsaSecp256k1 => Ok(Box::new(
                        Cggmp24EcdsaSecp256k1ControllerSigning::try_new(
                            ProtocolInit::Signing(SigningInit::Controller(
                                init,
                            )),
                        )?,
                    )),
                },
            },
        }
    }
}
