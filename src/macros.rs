//! Macros used across the codebase.

/// Join path components with `/` at compile time.
#[macro_export]
macro_rules! join_path {
    ($base:expr, $($part:expr),+) => {
        const_format::concatcp!($base, $("/", $part),+)
    };
}
