//! FROST(ed25519) curve implementation for node-side signing.

use frost_ed25519::{
    Error,
    Identifier,
    SigningPackage,
    keys::KeyPackage,
    rand_core::OsRng,
    round1::{SigningCommitments, SigningNonces, commit},
    round2::{SignatureShare, sign},
};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};

use super::protocol::FrostNodeSigning;
use crate::{
    protocols::{
        algorithm::Algorithm,
        frost::node::tasks::protocol::FrostSigningCurve,
    },
    transport::errors::Errors,
};

/// Concrete type alias for FROST(ed25519) node signing.
pub type FrostEd25519NodeSigning = FrostNodeSigning<FrostEd25519SigningCurve>;

/// FROST(ed25519) curve descriptor for signing.
pub struct FrostEd25519SigningCurve;

impl FrostSigningCurve for FrostEd25519SigningCurve {
    type Identifier = Identifier;
    type KeyPackage = KeyPackage;
    type SigningNonces = SigningNonces;
    type SigningCommitments = SigningCommitments;
    type SigningPackage = SigningPackage;
    type SignatureShare = SignatureShare;

    fn algorithm() -> Algorithm {
        Algorithm::FrostEd25519
    }

    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<Self::Identifier, Errors> {
        Identifier::try_from(identifier).map_err(|error: Error| {
            Errors::InvalidKeyShare(format!(
                "Failed to create ed25519 identifier from {}: {}",
                identifier, error
            ))
        })
    }

    fn deserialize_key_package(
        bytes: &[u8],
    ) -> Result<Self::KeyPackage, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidKeyShare(format!(
                "Failed to deserialize ed25519 key package: {}",
                error
            ))
        })
    }

    fn commit(
        key_package: &Self::KeyPackage,
    ) -> Result<(Self::SigningNonces, Self::SigningCommitments), Errors> {
        Ok(commit(key_package.signing_share(), &mut OsRng))
    }

    fn serialize_commitments(
        commitments: &Self::SigningCommitments,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(commitments).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize ed25519 commitments: {}",
                    error
                ))
            },
        )
    }

    fn deserialize_signing_package(
        bytes: &[u8],
    ) -> Result<Self::SigningPackage, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize ed25519 signing package: {}",
                error
            ))
        })
    }

    fn signing_package_message(package: &Self::SigningPackage) -> &[u8] {
        package.message()
    }

    fn signing_package_contains(
        package: &Self::SigningPackage,
        identifier: &Self::Identifier,
    ) -> bool {
        package.signing_commitments().contains_key(identifier)
    }

    fn sign(
        package: &Self::SigningPackage,
        nonces: &Self::SigningNonces,
        key_package: &Self::KeyPackage,
    ) -> Result<Self::SignatureShare, Errors> {
        sign(package, nonces, key_package).map_err(|error: Error| {
            Errors::FailedToSign(format!("ed25519 signing failed: {}", error))
        })
    }

    fn serialize_signature_share(
        share: &Self::SignatureShare,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(share).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize ed25519 signature share: {}",
                    error
                ))
            },
        )
    }
}
