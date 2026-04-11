//! Deterministic signer set derivation for CGGMP24 threshold signing.

use std::num::TryFromIntError;

use sha2::{Digest, Sha256};

use crate::transport::errors::Errors;

/// Deterministically compute the set of signing participants from the key
/// identifier, threshold, and participant count.
///
/// All nodes and the controller derive the same signer set independently from
/// these public values. The signer selection rule:
///
/// 1. Hash the `key_identifier` using SHA-256.
/// 2. Interpret the first 8 bytes of the hash as a big-endian `u64`.
/// 3. Reduce modulo `participants` to obtain a starting index.
/// 4. Select `threshold` consecutive participant identifiers starting from
///    this index, with wrap-around.
///
/// # Errors
/// * `Errors::InvalidMessage` - If the hash cannot be computed or converted.
///
/// # Returns
/// * `Vec<u16>` - Sorted list of participant indices in the signer set.
pub fn compute_parties(
    key_identifier: &str,
    threshold: u32,
    participants: u32,
) -> Result<Vec<u16>, Errors> {
    // Hash the key identifier to derive a deterministic starting index —
    // all nodes compute the same hash for the same key identifier.
    let digest: [u8; 32] = Sha256::digest(key_identifier.as_bytes()).into();

    // Convert participants to u16 once — reused in modulo operations.
    let participants_u16: u16 =
        u16::try_from(participants).map_err(|error: TryFromIntError| {
            Errors::InvalidMessage(error.to_string())
        })?;

    // Reduce the hash modulo participants to get a starting index in
    // [0, participants).
    let first_eight_bytes: [u8; 8] = digest
        .iter()
        .copied()
        .take(8)
        .collect::<Vec<u8>>()
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            Errors::InvalidMessage(format!(
                "Failed to extract first 8 bytes from digest: got {} bytes.",
                bytes.len()
            ))
        })?;

    let start: u16 = u16::try_from(
        u64::from_be_bytes(first_eight_bytes) % u64::from(participants_u16),
    )
    .map_err(|error: TryFromIntError| {
        Errors::InvalidMessage(format!(
            "Failed to convert hash to start index: {}",
            error
        ))
    })?;

    // Convert threshold to u16 for arithmetic.
    let threshold_u16: u16 =
        u16::try_from(threshold).map_err(|error: TryFromIntError| {
            Errors::InvalidMessage(format!(
                "Threshold exceeds u16 range: {}",
                error
            ))
        })?;

    // Select `threshold` consecutive participant indices starting from
    // `start`, wrapping around modulo `participants`.
    let mut parties: Vec<u16> = (0..threshold_u16)
        .map(|index: u16| (start + index) % participants_u16)
        .collect();

    // Sort to ensure a canonical ordering — required by CGGMP24 signing.
    parties.sort();

    Ok(parties)
}
