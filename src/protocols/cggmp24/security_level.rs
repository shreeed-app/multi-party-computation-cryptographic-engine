//! CGGMP24 security level definitions.

#[cfg(feature = "test-fast-crypto")]
mod inner {
    #![warn(warnings)]
    use cggmp24::security_level::define_security_level;

    /// Reduced security level for testing only — must never be used in
    /// production.
    ///
    /// # Parameter constraints
    ///
    /// The parameters must satisfy the following mathematical constraints
    /// imposed by the ZK proofs:
    ///
    /// - `rsa_prime_bitlen > max(ell, ell_prime) + epsilon` — required by
    ///   `π_aff` (affine operation in range proof). Uses both `ell` and
    ///   `ell_prime` as range parameters. Here: 800 > max(256, 512) + 256 =
    ///   768.
    ///
    /// - `rsa_prime_bitlen > ell + epsilon` — required by `π_enc_elg`
    ///   (EncProofOfK). Here: 800 > 256 + 256 = 512.
    ///
    /// - `rsa_pubkey_bitlen = 2 * rsa_prime_bitlen - 1`. Here: 1599 = 2 * 800
    ///   - 1.
    ///
    /// # Performance gains vs `SecurityLevel128` (1536-bit primes)
    ///
    /// - Prime generation: ~6x faster (800-bit vs 1536-bit safe primes).
    /// - ZK proof arithmetic: ~3.5x faster.
    /// - Overall aux gen: from ~60s to ~10s per node.
    #[derive(Clone)]
    pub struct Cggmp24SecurityLevel;

    define_security_level!(Cggmp24SecurityLevel {
        kappa_bits: 256,
        rsa_prime_bitlen: 768,
        rsa_pubkey_bitlen: 1535,
        epsilon: 384,
        ell: 256,
        ell_prime: 256,
        m: 128,
    });
}

#[cfg(not(feature = "test-fast-crypto"))]
mod inner {
    pub use cggmp24::security_level::SecurityLevel128 as Cggmp24SecurityLevel;
}

pub use inner::Cggmp24SecurityLevel;
