//! FROST(schnorr-secp256k1) curve implementation for node-side key generation.

use std::collections::BTreeMap;

use frost_secp256k1::{
    Error,
    Identifier,
    keys::{
        KeyPackage,
        PublicKeyPackage,
        dkg::{part1, part2, part3, round1, round2},
    },
    rand_core::OsRng,
};
use postcard::{Error as PostcardError, from_bytes, to_allocvec};

use crate::{
    protocols::{
        algorithm::Algorithm,
        frost::node::keys::protocol::{FrostCurve, FrostNodeKeyGeneration},
    },
    transport::errors::Errors,
};

/// Concrete type alias for FROST(schnorr-secp256k1) node key generation.
pub type FrostSchnorrSecp256k1NodeKeyGeneration =
    FrostNodeKeyGeneration<FrostSchnorrSecp256k1Curve>;

/// FROST(schnorr-secp256k1) curve descriptor. Implements `FrostCurve` by
/// delegating to the `frost_secp256k1` crate.
pub struct FrostSchnorrSecp256k1Curve;

impl FrostCurve for FrostSchnorrSecp256k1Curve {
    type Identifier = Identifier;
    type Round1SecretPackage = round1::SecretPackage;
    type Round1Package = round1::Package;
    type Round2SecretPackage = round2::SecretPackage;
    type Round2Package = round2::Package;
    type KeyPackage = KeyPackage;
    type PublicKeyPackage = PublicKeyPackage;

    fn algorithm() -> Algorithm {
        Algorithm::FrostSchnorrSecp256k1
    }

    fn identifier_from_u16(
        identifier: u16,
    ) -> Result<Self::Identifier, Errors> {
        Identifier::try_from(identifier).map_err(|error: Error| {
            Errors::InvalidProtocolInit(format!(
                "Failed to create FROST secp256k1 Identifier from {}: {}",
                identifier, error
            ))
        })
    }

    fn part1(
        identifier: Self::Identifier,
        participants: u16,
        threshold: u16,
    ) -> Result<(Self::Round1SecretPackage, Self::Round1Package), Errors> {
        part1(identifier, participants, threshold, OsRng).map_err(
            |error: Error| {
                Errors::InvalidMessage(format!(
                    "Failed to generate round 1 secret and package: {}",
                    error
                ))
            },
        )
    }

    fn part2(
        secret: Self::Round1SecretPackage,
        round1_packages: &BTreeMap<Self::Identifier, Self::Round1Package>,
    ) -> Result<
        (
            Self::Round2SecretPackage,
            BTreeMap<Self::Identifier, Self::Round2Package>,
        ),
        Errors,
    > {
        part2(secret, round1_packages).map_err(|error: Error| {
            Errors::InvalidMessage(format!(
                "Failed to compute round 2 packages: {}",
                error
            ))
        })
    }

    fn part3(
        round2_secret: &Self::Round2SecretPackage,
        round1_packages: &BTreeMap<Self::Identifier, Self::Round1Package>,
        round2_packages: &BTreeMap<Self::Identifier, Self::Round2Package>,
    ) -> Result<(Self::KeyPackage, Self::PublicKeyPackage), Errors> {
        part3(round2_secret, round1_packages, round2_packages).map_err(
            |error: Error| {
                Errors::InvalidMessage(format!(
                    "Failed to finalize DKG: {}",
                    error
                ))
            },
        )
    }

    fn serialize_round1_package(
        package: &Self::Round1Package,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize round 1 package: {}",
                    error
                ))
            },
        )
    }

    fn deserialize_round1_package(
        bytes: &[u8],
    ) -> Result<Self::Round1Package, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize round 1 package: {}",
                error
            ))
        })
    }

    fn serialize_round2_package(
        package: &Self::Round2Package,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize round 2 package: {}",
                    error
                ))
            },
        )
    }

    fn deserialize_round2_package(
        bytes: &[u8],
    ) -> Result<Self::Round2Package, Errors> {
        from_bytes(bytes).map_err(|error: PostcardError| {
            Errors::InvalidMessage(format!(
                "Failed to deserialize round 2 package: {}",
                error
            ))
        })
    }

    fn serialize_key_package(
        package: &Self::KeyPackage,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize key package: {}",
                    error
                ))
            },
        )
    }

    fn serialize_public_key_package(
        package: &Self::PublicKeyPackage,
    ) -> Result<Vec<u8>, Errors> {
        to_allocvec(package).map(|value: Vec<u8>| value.to_vec()).map_err(
            |error: PostcardError| {
                Errors::InvalidMessage(format!(
                    "Failed to serialize public key package: {}",
                    error
                ))
            },
        )
    }

    fn verifying_key(
        package: &Self::PublicKeyPackage,
    ) -> Result<Vec<u8>, Errors> {
        package.verifying_key().serialize().map_err(|error: Error| {
            Errors::InvalidMessage(format!(
                "Failed to serialize verifying key: {}",
                error
            ))
        })
    }
}
