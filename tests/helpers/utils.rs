use rand_core::{OsRng, RngCore};

/// Generate a random message of the specified length.
///
/// # Arguments
/// * `len` (`usize`) - Length of the message in bytes.
///
/// # Returns
/// A vector containing the random message bytes.
pub fn random_message(len: usize) -> Vec<u8> {
    let mut message: Vec<u8> = vec![0u8; len];
    OsRng.fill_bytes(&mut message);
    message
}
