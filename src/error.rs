/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

/// Errors returned by fallible big-number operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A destination buffer did not match the encoded magnitude length.
    #[error("buffer length mismatch: expected {expected} bytes, received {actual}")]
    BufferLength {
        /// The required buffer length.
        expected: usize,
        /// The provided buffer length.
        actual: usize,
    },

    /// A requested bit length was too large for the backend.
    #[error("bit length {actual} exceeds the backend maximum of {maximum}")]
    BitLengthTooLarge {
        /// The requested bit length.
        actual: usize,
        /// The largest supported bit length.
        maximum: usize,
    },

    /// A requested bit length was too small for the operation.
    #[error("bit length {actual} is below the required minimum of {minimum}")]
    BitLengthTooSmall {
        /// The requested bit length.
        actual: usize,
        /// The smallest supported bit length.
        minimum: usize,
    },

    /// The lower bound of a range was not less than its upper bound.
    #[error("lower bound must be less than upper bound")]
    InvalidRange,

    /// A modulus was negative, zero, or one.
    #[error("modulus must be a positive integer greater than one")]
    InvalidModulus,

    /// A prime field was requested with a composite modulus.
    #[error("field modulus is not prime")]
    ModulusNotPrime,

    /// Arithmetic operands were bound to groups with different moduli.
    #[error("group operands have different moduli")]
    MismatchedGroups,

    /// A value had no multiplicative inverse for the selected modulus.
    #[error("value is not invertible for this modulus")]
    NonInvertible,

    /// Operating-system randomness was unavailable while seeding a generator.
    #[cfg(any(
        feature = "crypto",
        feature = "gmp",
        feature = "openssl",
        feature = "rust"
    ))]
    #[error(transparent)]
    Random(#[from] rand::rngs::SysError),

    /// OpenSSL rejected an operation.
    #[cfg(feature = "openssl")]
    #[error(transparent)]
    OpenSsl(#[from] openssl::error::ErrorStack),

    /// Pure-Rust prime generation rejected an operation.
    #[cfg(feature = "rust")]
    #[error(transparent)]
    PrimeGeneration(#[from] glass_pumpkin::error::Error),
}

/// A result returned by a fallible big-number operation.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(any(
    feature = "crypto",
    feature = "gmp",
    feature = "openssl",
    feature = "rust"
))]
pub(crate) fn validate_bit_length(actual: usize, minimum: usize, maximum: usize) -> Result<()> {
    if actual < minimum {
        Err(Error::BitLengthTooSmall { actual, minimum })
    } else if actual > maximum {
        Err(Error::BitLengthTooLarge { actual, maximum })
    } else {
        Ok(())
    }
}
