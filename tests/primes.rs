//! Generates and saves pre-generated Paillier primes for testing.

#[allow(dead_code)]
mod helpers;

use std::{
    fs::{create_dir_all, write},
    thread::{JoinHandle, spawn},
};

use app::{
    join_path,
    protocols::cggmp24::security_level::Cggmp24SecurityLevel,
};
use cggmp24::key_refresh::PregeneratedPrimes;
use rand_core::OsRng;
use tracing_subscriber::{EnvFilter, fmt};

use crate::helpers::config::ClusterConfig;

const FOLDER_PATH: &str = join_path!("tests", "fixtures");
const FILE_PATH: &str = join_path!(FOLDER_PATH, "paillier_primes.json");

/// Utility to generate and save pre-generated Paillier primes for testing.
/// This is used to create the `FILE_PATH` file, which is loaded during tests
/// when the `test-fast-crypto` feature is enabled to speed up tests by
/// avoiding the expensive prime generation step.
#[cfg(test)]
#[test]
fn pregenerate_primes() {
    let _ = fmt().with_env_filter(EnvFilter::from_default_env()).try_init();

    let config: &ClusterConfig = ClusterConfig::get();

    tracing::info!(
        node_count = config.node_count,
        "Generating Paillier primes."
    );

    let handles: Vec<JoinHandle<PregeneratedPrimes<Cggmp24SecurityLevel>>> =
        (0..config.node_count)
            .map(|index: usize| {
                spawn(move || {
                    tracing::info!(index, "Generating primes for node.");
                    let primes: PregeneratedPrimes<Cggmp24SecurityLevel> =
                        PregeneratedPrimes::<Cggmp24SecurityLevel>::generate(
                            &mut OsRng,
                        );
                    tracing::info!(index, "Primes generated for node.");
                    primes
                })
            })
            .collect();

    let primes: Vec<PregeneratedPrimes<Cggmp24SecurityLevel>> = handles
        .into_iter()
        .map(|handle: JoinHandle<PregeneratedPrimes<Cggmp24SecurityLevel>>| {
            handle.join().unwrap()
        })
        .collect();

    let json: String = serde_json::to_string_pretty(&primes).unwrap();
    create_dir_all(FOLDER_PATH).unwrap();
    write(FILE_PATH, &json).unwrap();

    tracing::info!(
        node_count = config.node_count,
        path = FILE_PATH,
        "Primes written."
    );
}
