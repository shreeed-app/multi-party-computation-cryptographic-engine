//! Protocol factory definitions.

use crate::{
    messages::error::Error,
    protocols::{
        algorithm::Algorithm,
        cggmp24::ecdsa_secp256k1::Cggmp24EcdsaSecp256k1Protocol,
        frost::{
            ed25519::FrostEd25519Protocol,
            schnorr_secp256k1::FrostSchnorrSecp256k1Protocol,
        },
        signing::SigningProtocol,
        types::ProtocolInit,
    },
};

/// Factory responsible for instantiating signing protocols.
/// This is the single dispatch point for protocol selection.
pub struct ProtocolFactory;

impl ProtocolFactory {
    /// Create a new signing protocol instance.
    ///
    /// # Arguments
    /// * `init` (`ProtocolInit`) - Protocol initialization context.
    ///
    /// # Errors
    /// * `Error::UnsupportedAlgorithm` if the algorithm is not supported or
    ///   cannot be parsed.
    ///
    /// # Returns
    /// * `Box<dyn SigningProtocol>` - Initialized protocol instance.
    pub fn create(
        init: ProtocolInit,
    ) -> Result<Box<dyn SigningProtocol>, Error> {
        match init.algorithm {
            Algorithm::FrostEd25519 => {
                match FrostEd25519Protocol::try_new(init) {
                    Ok(protocol) => Ok(Box::new(protocol)),
                    Err(error) => Err(error),
                }
            },

            Algorithm::FrostSchnorrSecp256k1 => {
                match FrostSchnorrSecp256k1Protocol::try_new(init) {
                    Ok(protocol) => Ok(Box::new(protocol)),
                    Err(error) => Err(error),
                }
            },

            Algorithm::Cggmp24EcdsaSecp256k1 => {
                Ok(Box::new(Cggmp24EcdsaSecp256k1Protocol::try_new(init)?))
            },
        }
    }
}
