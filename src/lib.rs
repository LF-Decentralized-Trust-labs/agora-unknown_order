/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! This crate handles groups of unknown order.
//!
//! I've seen this commonly across multiple projects where they need a multiprecision library
//! and use one of three libraries: [Gnu MP BigNum Library](https://gmplib.org/), [OpenSSL's BigNum Library](https://www.openssl.org/docs/man1.0.2/man3/bn.html)
//! and [Rust's BigInt Library](https://crates.io/crates/num-bigint), depending on the needs and requirements (licensing, performance, platform target).
//!
//! This library wraps them all into a common API, so they can be used interchangeably.
//!
//! Groups of unknown order require using a modulus that is the composite of two big prime numbers. This
//! library is designed to facilitate these use cases such as RSA, [Paillier](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_16.pdf), [Hyperelliptic Curves](https://eprint.iacr.org/2020/196),
//! [Accumulators](https://eprint.iacr.org/2018/1188), [CL signatures](http://cs.brown.edu/people/alysyans/papers/camlys02b.pdf).
//!
//! The modulus is not known at compile time which excludes using certain traits like `ff::PrimeField`, so
//! unfortunately, the caller needs to remember to use methods prefixed with `mod` to achieve the desired results.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    missing_docs,
    trivial_casts,
    unconditional_recursion,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    unused_extern_crates,
    unused_parens,
    while_true,
    warnings
)]

#[cfg(any(feature = "rust", feature = "gmp", feature = "openssl"))]
#[macro_use]
mod macros;

#[cfg(any(
    feature = "rust",
    feature = "gmp",
    feature = "openssl",
    feature = "crypto"
))]
extern crate alloc;
#[cfg(any(test, feature = "openssl", feature = "gmp", feature = "rust"))]
#[macro_use]
extern crate std;

#[cfg(any(
    feature = "rust",
    feature = "gmp",
    feature = "openssl",
    feature = "crypto"
))]
pub(crate) fn encode_signed_hex(negative: bool, bytes: &[u8]) -> alloc::string::String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = alloc::string::String::with_capacity(bytes.len() * 2 + usize::from(negative));
    if negative {
        encoded.push('-');
    }
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(any(
    feature = "rust",
    feature = "gmp",
    feature = "openssl",
    feature = "crypto"
))]
pub(crate) fn decode_hex(encoded: &str) -> Option<alloc::vec::Vec<u8>> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let mut encoded = encoded.as_bytes();
    let mut bytes = alloc::vec::Vec::with_capacity(encoded.len().div_ceil(2));
    if !encoded.len().is_multiple_of(2) {
        bytes.push(nibble(encoded[0])?);
        encoded = &encoded[1..];
    }
    for pair in encoded.as_chunks::<2>().0 {
        bytes.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(bytes)
}

#[cfg(any(
    feature = "rust",
    feature = "gmp",
    feature = "openssl",
    feature = "crypto"
))]
pub(crate) fn decode_signed_hex(encoded: &str) -> Option<(bool, alloc::vec::Vec<u8>)> {
    let (negative, magnitude) = encoded
        .strip_prefix('-')
        .map_or((false, encoded), |magnitude| (true, magnitude));
    decode_hex(magnitude).map(|bytes| (negative, bytes))
}

#[cfg(feature = "openssl")]
pub(crate) fn ct_eq_bytes(
    lhs_negative: bool,
    lhs: &[u8],
    rhs_negative: bool,
    rhs: &[u8],
) -> subtle::Choice {
    use subtle::ConstantTimeEq;

    let mut difference = 0u8;
    let len = lhs.len().max(rhs.len());
    for index in 0..len {
        let lhs_byte = if index < lhs.len() {
            lhs[lhs.len() - index - 1]
        } else {
            0
        };
        let rhs_byte = if index < rhs.len() {
            rhs[rhs.len() - index - 1]
        } else {
            0
        };
        difference |= lhs_byte ^ rhs_byte;
    }

    (lhs_negative as u8).ct_eq(&(rhs_negative as u8)) & difference.ct_eq(&0)
}

#[cfg(feature = "openssl")]
pub(crate) fn fmt_bytes_radix(
    f: &mut core::fmt::Formatter<'_>,
    negative: bool,
    bytes: &[u8],
    radix: u16,
    uppercase: bool,
) -> core::fmt::Result {
    use core::fmt::Write;

    let bits_per_digit = match radix {
        2 => 1,
        8 => 3,
        16 => 4,
        _ => return Err(core::fmt::Error),
    };
    if negative {
        f.write_char('-')?;
    }
    let Some(first_nonzero) = bytes.iter().position(|byte| *byte != 0) else {
        return f.write_char('0');
    };

    let first_bit = first_nonzero * 8 + bytes[first_nonzero].leading_zeros() as usize;
    let significant_bits = bytes.len() * 8 - first_bit;
    let mut digit_width = (significant_bits - 1) % bits_per_digit + 1;
    let mut bit_index = first_bit;
    while bit_index < bytes.len() * 8 {
        let mut digit = 0u8;
        for offset in 0..digit_width {
            let index = bit_index + offset;
            digit = (digit << 1) | ((bytes[index / 8] >> (7 - index % 8)) & 1);
        }
        let encoded = match digit {
            0..=9 => b'0' + digit,
            _ if uppercase => b'A' + (digit - 10),
            _ => b'a' + (digit - 10),
        };
        f.write_char(char::from(encoded))?;
        bit_index += digit_width;
        digit_width = bits_per_digit;
    }
    Ok(())
}

#[cfg(feature = "crypto")]
mod crypto_backend;
#[cfg(feature = "gmp")]
mod gmp_backend;
#[cfg(feature = "openssl")]
mod openssl_backend;
#[cfg(feature = "rust")]
mod rust_backend;

mod error;
mod gcd_result;
mod group;

/// The `crypto-bigint` backend.
#[cfg(feature = "crypto")]
pub mod crypto {
    pub use crate::crypto_backend::{Bn as BigNumber, Sign};
}

/// The GNU MP backend.
#[cfg(feature = "gmp")]
pub mod gmp {
    pub use crate::gmp_backend::Bn as BigNumber;
}

/// The OpenSSL backend.
#[cfg(feature = "openssl")]
pub mod openssl {
    pub use crate::openssl_backend::Bn as BigNumber;
}

/// The `num-bigint` backend.
#[cfg(feature = "rust")]
pub mod rust {
    pub use crate::rust_backend::Bn as BigNumber;
}

#[cfg(all(
    feature = "crypto",
    not(any(feature = "gmp", feature = "openssl", feature = "rust"))
))]
pub use crypto::BigNumber;
#[cfg(all(
    feature = "gmp",
    not(any(feature = "crypto", feature = "openssl", feature = "rust"))
))]
pub use gmp::BigNumber;
#[cfg(all(
    feature = "openssl",
    not(any(feature = "crypto", feature = "gmp", feature = "rust"))
))]
pub use openssl::BigNumber;
#[cfg(all(
    feature = "rust",
    not(any(feature = "crypto", feature = "gmp", feature = "openssl"))
))]
pub use rust::BigNumber;

pub use error::*;
pub use gcd_result::*;
pub use group::*;
