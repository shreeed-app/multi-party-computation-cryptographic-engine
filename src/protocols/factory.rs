//! Protocol factory definitions.

use std::str::FromStr;

use crate::messages::error::Error;
use crate::protocols::algorithm::Algorithm;
use crate::protocols::eddsa::frost_ed25519::FrostEd25519Protocol;
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
        let algorithm: Algorithm = match Algorithm::from_str(&init.algorithm) {
            Ok(algorithm) => algorithm,
            Err(_) => {
                return Err(Error::UnsupportedAlgorithm(
                    init.algorithm.clone(),
                ));
            }
        };

        match algorithm {
            Algorithm::FrostEd25519 => {
                match FrostEd25519Protocol::try_new(init) {
                    Ok(protocol) => Ok(Box::new(protocol)),
                    Err(error) => Err(error),
                }
            }

            Algorithm::FrostSecp256k1 => {
                Err(Error::UnsupportedAlgorithm(init.algorithm.clone()))
            }
            Algorithm::Gg18Secp256k1 => {
                Err(Error::UnsupportedAlgorithm(init.algorithm.clone()))
            }
            Algorithm::Gg20Secp256k1 => {
                Err(Error::UnsupportedAlgorithm(init.algorithm.clone()))
            }
        }
    }
}
