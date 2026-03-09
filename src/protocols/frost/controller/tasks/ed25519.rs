//! FROST(ed25519) curve implementation for controller-side signing.

use std::collections::BTreeMap;

use frost_ed25519::{
    Error,
    Identifier,
    Signature,
    SigningPackage,
    aggregate,
    keys::PublicKeyPackage,
    round1::SigningCommitments,
    round2::SignatureShare,
};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};

use super::protocol::{FrostControllerSigning, FrostControllerSigningCurve};
use crate::{protocols::algorithm::Algorithm, transport::errors::Errors};

/// Concrete type alias for FROST(ed25519) controller signing.
pub type FrostEd25519ControllerSigning =
    FrostControllerSigning<FrostEd25519ControllerSigningCurve>;

/// FROST(ed25519) curve descriptor for controller-side signing.
pub struct FrostEd25519ControllerSigningCurve;

impl FrostControllerSigningCurve for FrostEd25519ControllerSigningCurve {
    type Identifier = Identifier;
    type SigningCommitments = SigningCommitments;
    type SigningPackage = SigningPackage;
    type SignatureShare = SignatureShare;
    type PublicKeyPackage = PublicKeyPackage;
    type Signature = Signature;

    fn algorithm() -> Algorithm {
        Algorithm::FrostEd25519
    }

    fn identifier_from_u16(id: u16) -> Result<Self::Identifier, Errors> {
        Identifier::try_from(id).map_err(|error: Error| {
            Errors::InvalidParticipant(format!(
                "Failed to create ed25519 identifier from {}: {}",
                id, error
            ))
        })
    }

    fn deserialize_public_key_package(
        bytes: &[u8],
    ) -> Result<Self::PublicKeyPackage, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize ed25519 public key package: {}",
                error
            ))
        })
    }

    fn deserialize_commitments(
        bytes: &[u8],
    ) -> Result<Self::SigningCommitments, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize ed25519 signing commitments: {}",
                error
            ))
        })
    }

    fn build_signing_package(
        commitments: BTreeMap<Self::Identifier, Self::SigningCommitments>,
        message: &[u8],
    ) -> Result<Self::SigningPackage, Errors> {
        Ok(SigningPackage::new(commitments, message))
    }

    fn serialize_signing_package(
        package: &Self::SigningPackage,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize ed25519 signing package: {}",
                    error
                ))
            },
        )
    }

    fn deserialize_signature_share(
        bytes: &[u8],
    ) -> Result<Self::SignatureShare, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize ed25519 signature share: {}",
                error
            ))
        })
    }

    fn aggregate(
        signing_package: &Self::SigningPackage,
        shares: &BTreeMap<Self::Identifier, Self::SignatureShare>,
        public_key_package: &Self::PublicKeyPackage,
    ) -> Result<Self::Signature, Errors> {
        aggregate(signing_package, shares, public_key_package).map_err(
            |error: Error| {
                Errors::InvalidSignature(format!(
                    "Failed to aggregate ed25519 signature shares: {}",
                    error
                ))
            },
        )
    }

    fn serialize_signature(
        signature: &Self::Signature,
    ) -> Result<Vec<u8>, Errors> {
        signature.serialize().map(|bytes: Vec<u8>| bytes.to_vec()).map_err(
            |error: Error| {
                Errors::InvalidSignature(format!(
                    "Failed to serialize ed25519 signature: {}",
                    error
                ))
            },
        )
    }
}
