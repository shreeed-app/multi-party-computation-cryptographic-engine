//! Wrapper type for sensitive data stored in memory.

use std::fmt::{Debug, Formatter, Result as FmtResult};

use zeroize::Zeroize;

/// `Secret<T>` ensures, the value is zeroized on drop, is not accidentally
/// cloned, and access is always explicitly controlled.
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Secret<T> {
    /// Create a new secret value.
    ///
    /// # Arguments
    /// * `value` (`T`) - Sensitive value to protect in memory.
    ///
    /// # Returns
    /// * `Secret<T>` - Wrapped secret.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Borrow the secret immutably for a limited scope.
    ///
    /// # Arguments
    /// * `func` (`impl FnOnce(&T) -> R`) - Closure to execute with the secret
    ///   reference.
    ///
    /// # Returns
    /// * `R` - Result of the closure execution.
    pub fn with_ref<R>(&self, func: impl FnOnce(&T) -> R) -> R {
        func(&self.inner)
    }

    /// Borrow the secret mutably for a limited scope.
    ///
    /// # Arguments
    /// * `func` (`impl FnOnce(&mut T) -> R`) - Closure to execute with the
    ///   mutable secret reference.
    ///
    /// # Returns
    /// * `R` - Result of the closure execution.
    pub fn with_mut<R>(&mut self, func: impl FnOnce(&mut T) -> R) -> R {
        func(&mut self.inner)
    }
}

impl<T: Zeroize> Debug for Secret<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    /// Zeroize the inner value on drop.
    ///
    /// # Returns
    /// * `()` - Returns unit.
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}
