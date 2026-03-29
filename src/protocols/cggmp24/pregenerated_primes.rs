//! Pre-generated Paillier primes for test-fast-crypto feature.

use cggmp24::key_refresh::PregeneratedPrimes;

use crate::protocols::cggmp24::security_level::Cggmp24SecurityLevel;

/// Load or generate Paillier primes depending on the active feature flag.
///
/// Under `test-fast-crypto`, loads hardcoded primes from
/// `tests/fixtures/paillier_primes.json` to avoid the expensive prime
/// generation step. In production, generates fresh primes using the operating
/// system random number generator.
///
/// # Arguments
/// * `_identifier` (`u16`) - 0-based node identifier, used to select which set
///   of pre-generated primes to use.
pub fn pregenerate_primes(
    _identifier: u16,
) -> PregeneratedPrimes<Cggmp24SecurityLevel> {
    // In test mode, load pre-generated primes from a JSON file to speed up
    // tests, as prime generation is the most time-consuming part of the
    // protocol.
    #[cfg(feature = "test-fast-crypto")]
    {
        use std::fs::read_to_string;

        use serde_json::from_str;

        const PRIMES_PATH: &str = join_path!(
            env!("CARGO_MANIFEST_DIR"),
            "tests",
            "fixtures",
            "paillier_primes.json"
        );

        if let Ok(json) = read_to_string(PRIMES_PATH) {
            let primes: Vec<PregeneratedPrimes<Cggmp24SecurityLevel>> =
                from_str(&json).unwrap();
            let index: usize = _identifier as usize % primes.len();
            primes.into_iter().nth(index).unwrap()
        } else {
            use rand_core::OsRng;

            tracing::warn!(
                "Paillier primes not found at {}, generating fresh primes.",
                PRIMES_PATH
            );
            PregeneratedPrimes::<Cggmp24SecurityLevel>::generate(&mut OsRng)
        }
    }
    // In production, generate fresh primes using the operating system random
    // number generator.
    #[cfg(not(feature = "test-fast-crypto"))]
    {
        use rand_core::OsRng;

        PregeneratedPrimes::<Cggmp24SecurityLevel>::generate(&mut OsRng)
    }
}
