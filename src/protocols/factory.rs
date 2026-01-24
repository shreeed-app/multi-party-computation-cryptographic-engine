//! Protocol factory definitions.

use crate::messages::error::Error;
use crate::protocols::algorithm::Algorithm;
use crate::protocols::frost::algorithm::ed25519::FrostEd25519Protocol;
use crate::protocols::frost::algorithm::schnorr_secp256k1::FrostSchnorrSecp256k1Protocol;
use crate::protocols::signing::SigningProtocol;
use crate::protocols::types::ProtocolInit;

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
    /// * `Error::UnsupportedAlgorithm` if the algorithm is not
    ///   supported or cannot be parsed.
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
            }

            Algorithm::FrostSchnorrSecp256k1 => {
                match FrostSchnorrSecp256k1Protocol::try_new(init) {
                    Ok(protocol) => Ok(Box::new(protocol)),
                    Err(error) => Err(error),
                }
            }

            _ => Err(Error::UnsupportedAlgorithm(
                init.algorithm.as_str().into(),
            )),
        }
    }
}
