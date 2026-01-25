use std::collections::{BTreeMap, HashMap};

use mpc_signer_engine::{
    auth::session::identifier::SessionId,
    engine::{api::EngineApi, builder::EngineBuilder, core::Engine},
    messages::error::Error,
    protocols::{
        algorithm::Algorithm,
        frost::{stored_key::FrostStoredKey, wire::FrostWire},
        types::{ProtocolInit, RoundMessage},
    },
    secrets::secret::Secret,
};
use rand_core::{OsRng, RngCore};
use rkyv::{from_bytes, rancor::Error as RkyvError, to_bytes};

/// Overall test setup configuration.
struct TestSetup {
    /// Signing threshold.
    threshold: u16,
    /// Total number of participants.
    total: u16,
    /// Message to be signed.
    message: Vec<u8>,
}

/// Individual participant setup data.
struct Participant {
    /// Serialized key share blob.
    key_share_blob: Vec<u8>,
}

/// Generate a random message of the given length.
///
/// # Arguments
/// * `len` (`usize`) - Length of the message in bytes.
///
/// # Returns
/// * `Vec<u8>` - Randomly generated message.
fn random_message(len: usize) -> Vec<u8> {
    let mut message: Vec<u8> = vec![0u8; len];
    OsRng.fill_bytes(&mut message);
    message
}

/// Define a suite of FROST tests for a given implementation.
macro_rules! define_frost_suite {
    (
        // Name of the module to create for the tests.
        $mod_name:ident,
        // Crate to use (e.g., frost_secp256k1).
        $frost_crate:path,
        // Variant of the Algorithm enum to use.
        $algorithm_variant:expr
    ) => {
        mod $mod_name {
            use frost_impl::{
                Identifier,
                Signature,
                SigningPackage,
                aggregate,
                keys::{
                    IdentifierList,
                    KeyPackage,
                    PublicKeyPackage,
                    SecretShare,
                    generate_with_dealer,
                },
                round1::SigningCommitments,
                round2::SignatureShare,
            };
            use $frost_crate as frost_impl;

            use super::*;

            struct Participants<'l> {
                public_key_package: PublicKeyPackage,
                participants: HashMap<u16, Participant>,
                setup: &'l TestSetup,
            }

            /// Generate key shares and public key package for testing.
            ///
            /// # Arguments
            /// * `setup` (`&TestSetup`) - Test setup data.
            ///
            /// # Returns
            /// * `Result<TestSetup, Error>` - Test setup data or error.
            fn generate_keys<'l>(
                setup: &'l TestSetup,
            ) -> Result<Participants<'l>, Error> {
                let (shares, public_key_package): (
                    BTreeMap<Identifier, SecretShare>,
                    PublicKeyPackage,
                ) = generate_with_dealer(
                    setup.total,
                    setup.threshold,
                    IdentifierList::Default,
                    OsRng,
                )
                .map_err(|_| Error::InvalidKeyShare)?;

                let mut participants: HashMap<u16, Participant> =
                    HashMap::new();

                for identifier_u16 in 1..=setup.total {
                    let identifier: Identifier =
                        Identifier::try_from(identifier_u16)
                            .map_err(|_| Error::InvalidKeyShare)?;
                    let share: &SecretShare = shares.get(&identifier).unwrap();
                    let key_package: KeyPackage =
                        KeyPackage::try_from(share.clone())
                            .map_err(|_| Error::InvalidKeyShare)?;

                    let key_package_bytes: Vec<u8> =
                        postcard::to_allocvec(&key_package)
                            .map_err(|_| Error::InvalidKeyShare)?;

                    let stored_key: FrostStoredKey = FrostStoredKey {
                        identifier: identifier_u16 as u32,
                        key_package: key_package_bytes,
                    };

                    let blob: Vec<u8> = to_bytes::<RkyvError>(&stored_key)
                        .map_err(|_| Error::InvalidKeyShare)?
                        .into_vec();

                    participants.insert(
                        identifier_u16,
                        Participant { key_share_blob: blob },
                    );
                }

                Ok(Participants { public_key_package, participants, setup })
            }

            /// Perform a FROST signing operation with the given participants.
            ///
            /// # Arguments
            /// * `setup` (`&TestSetup`) - Test setup data.
            /// * `key_ids` (`Vec<u16>`) - List of participant key IDs to use.
            /// * `threshold` (`u16`) - Threshold number of participants.
            /// * `participants` (`u16`) - Total number of participants.
            /// * `message` (`Vec<u8>`) - Message to sign.
            ///
            /// # Returns
            /// * `Result<(SigningPackage, BTreeMap<Identifier,
            ///   SignatureShare>), Error>` - Signing package and signature
            ///   shares or error.
            fn sign(
                participants: &Participants,
            ) -> Result<
                (SigningPackage, BTreeMap<Identifier, SignatureShare>),
                Error,
            > {
                let mut sessions: HashMap<u16, (Engine, SessionId)> =
                    HashMap::new();
                let mut commitments: BTreeMap<Identifier, SigningCommitments> =
                    BTreeMap::new();

                // Round 0: start sessions and collect commitments.
                for (key_id, participant) in &participants.participants {
                    let engine: Engine = EngineBuilder::new().build();

                    let (session_id, round_message): (
                        SessionId,
                        RoundMessage,
                    ) = engine.start_session(ProtocolInit {
                        key_id: key_id.to_string(),
                        algorithm: $algorithm_variant,
                        threshold: participants.setup.threshold as u32,
                        participants: participants.setup.total as u32,
                        message: participants.setup.message.clone(),
                        key_share: Secret::new(
                            participant.key_share_blob.clone(),
                        ),
                    })?;

                    let FrostWire::Commitments { identifier, commitments: c } =
                        from_bytes::<FrostWire, RkyvError>(
                            &round_message.payload,
                        )
                        .map_err(|_| Error::InvalidMessage)?
                    else {
                        return Err(Error::InvalidMessage);
                    };

                    commitments.insert(
                        Identifier::try_from(
                            u16::try_from(identifier)
                                .map_err(|_| Error::InvalidKeyShare)?,
                        )
                        .map_err(|_| Error::InvalidKeyShare)?,
                        postcard::from_bytes(&c)
                            .map_err(|_| Error::InvalidMessage)?,
                    );

                    sessions.insert(*key_id, (engine, session_id));
                }

                let signing_package: SigningPackage = SigningPackage::new(
                    commitments,
                    &participants.setup.message,
                );

                let payload: Vec<u8> =
                    to_bytes::<RkyvError>(&FrostWire::SigningPackage {
                        signing_package: postcard::to_allocvec(
                            &signing_package,
                        )
                        .map_err(|_| Error::InvalidMessage)?,
                    })
                    .map_err(|_| Error::InvalidMessage)?
                    .into_vec();

                // Round 1: submit signing package and collect signature
                // shares.
                let mut shares: BTreeMap<Identifier, SignatureShare> =
                    BTreeMap::new();

                for key_id in participants.participants.keys() {
                    let (engine, session_id): &(Engine, SessionId) =
                        &sessions[key_id];

                    let round_message: RoundMessage = engine.submit_round(
                        *session_id,
                        RoundMessage {
                            round: 1,
                            from: Some(*key_id as u32),
                            to: None,
                            payload: payload.clone(),
                        },
                    )?;

                    let FrostWire::SignatureShare {
                        identifier,
                        signature_share,
                    } = from_bytes::<FrostWire, RkyvError>(
                        &round_message.payload,
                    )
                    .map_err(|_| Error::InvalidMessage)?
                    else {
                        return Err(Error::InvalidMessage);
                    };

                    shares.insert(
                        Identifier::try_from(
                            u16::try_from(identifier)
                                .map_err(|_| Error::InvalidKeyShare)?,
                        )
                        .map_err(|_| Error::InvalidKeyShare)?,
                        postcard::from_bytes(&signature_share)
                            .map_err(|_| Error::InvalidMessage)?,
                    );

                    engine.finalize(*session_id)?;
                }

                Ok((signing_package, shares))
            }

            /// Test successful signing and verification.
            #[test]
            fn test_success() {
                let setup: TestSetup = TestSetup {
                    threshold: 2,
                    total: 3,
                    message: random_message(32),
                };

                let participants: Participants<'_> =
                    generate_keys(&setup).expect("Key generation failed.");

                let (package, shares): (
                    SigningPackage,
                    BTreeMap<Identifier, SignatureShare>,
                ) = sign(&participants).expect("Signing failed.");

                let signature: Signature = aggregate(
                    &package,
                    &shares,
                    &participants.public_key_package,
                )
                .expect("Aggregation failed.");

                assert!(
                    participants
                        .public_key_package
                        .verifying_key()
                        .verify(&participants.setup.message, &signature)
                        .is_ok()
                );
            }

            /// Test that using the wrong public key package
            /// fails verification.
            #[test]
            fn test_wrong_public_key_fails() {
                let setup: TestSetup = TestSetup {
                    threshold: 2,
                    total: 3,
                    message: random_message(32),
                };
                let correct_participants: Participants<'_> =
                    generate_keys(&setup).expect("Key generation failed.");
                let wrong_participants: Participants<'_> =
                    generate_keys(&setup).expect("Key generation failed.");

                let (package, shares): (
                    SigningPackage,
                    BTreeMap<Identifier, SignatureShare>,
                ) = sign(&correct_participants).expect("Signing failed.");

                let signature: Signature = aggregate(
                    &package,
                    &shares,
                    &correct_participants.public_key_package,
                )
                .expect("Aggregation failed.");

                assert!(
                    wrong_participants
                        .public_key_package
                        .verifying_key()
                        .verify(
                            &correct_participants.setup.message,
                            &signature
                        )
                        .is_err()
                );
            }

            /// Test that insufficient threshold of participants fails signing.
            #[test]
            fn test_insufficient_threshold_fails() {
                let setup: TestSetup = TestSetup {
                    threshold: 3,
                    total: 3,
                    message: random_message(32),
                };
                let mut participants: Participants<'_> =
                    generate_keys(&setup).expect("Key generation failed.");

                participants.participants.remove(&1);

                let result: Result<
                    (SigningPackage, BTreeMap<Identifier, SignatureShare>),
                    Error,
                > = sign(&participants);
                assert!(result.is_err());
            }

            /// Test that tampering with the signing package causes
            /// aggregation to fail.
            #[test]
            fn test_message_tampering_fails() {
                let setup: TestSetup = TestSetup {
                    threshold: 2,
                    total: 3,
                    message: random_message(32),
                };
                let participants: Participants<'_> =
                    generate_keys(&setup).expect("Key generation failed.");

                let (package, shares): (
                    SigningPackage,
                    BTreeMap<Identifier, SignatureShare>,
                ) = sign(&participants).unwrap();

                let bad_package: SigningPackage = SigningPackage::new(
                    package.signing_commitments().clone(),
                    random_message(32).as_slice(),
                );

                assert!(
                    aggregate(
                        &bad_package,
                        &shares,
                        &participants.public_key_package
                    )
                    .is_err()
                );
            }

            /// Test that an invalid key share causes session start to fail.
            #[test]
            fn test_invalid_key_share_fails() {
                let engine: Engine = EngineBuilder::new().build();

                let result: Result<(SessionId, RoundMessage), Error> = engine
                    .start_session(ProtocolInit {
                        key_id: "1".to_string(),
                        algorithm: $algorithm_variant,
                        threshold: 2,
                        participants: 3,
                        message: vec![],
                        key_share: Secret::new(vec![0xde, 0xad, 0xbe, 0xef]),
                    });

                assert!(matches!(result, Err(Error::InvalidKeyShare)));
            }
        }
    };
}

define_frost_suite!(
    secp256k1_tests,
    frost_secp256k1,
    Algorithm::FrostSchnorrSecp256k1
);

define_frost_suite!(ed25519_tests, frost_ed25519, Algorithm::FrostEd25519);
