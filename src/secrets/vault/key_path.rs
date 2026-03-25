//! Vault key path utilities.

/// Build a scoped Vault key path for a single participant.
///
/// # Arguments
/// * `base` (`&str`) - The base key identifier (e.g. `"<base>"`).
/// * `participant_id` (`u32`) - The participant's index.
///
/// # Returns
/// * `String` - Scoped path in the form `"<base>/<participant_id>"`.
pub fn scoped(base: &str, participant_id: u32) -> String {
    // Strip any accidental trailing separator before appending to produce a
    // canonical path with exactly one separator.
    format!("{}/{}", base.trim_end_matches('/'), participant_id)
}

/// Extract the base key identifier from a scoped Vault path.
///
/// Returns everything before the last `'/'`, or the original string if no
/// separator is present.
///
/// # Arguments
/// * `path` (`&str`) - A scoped path such as `"<base>/<participant_id>"`.
///
/// # Returns
/// * `&str` - The base portion, e.g. `"<base>"`.
pub fn base(path: &str) -> &str {
    path.rsplit_once('/').map(|(base, _): (&str, &str)| base).unwrap_or(path)
}
