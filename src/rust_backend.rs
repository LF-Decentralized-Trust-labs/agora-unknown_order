/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::GcdResult;
use alloc::{vec, vec::Vec};
use core::{
    cmp::{Eq, Ord, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    iter::{Product, Sum},
    mem::swap,
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
};
use glass_pumpkin::{prime, safe_prime};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::identities::{One, Zero};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use rand_core::Rng as RngCore;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

fn default_rng() -> crate::Result<StdRng> {
    Ok(StdRng::try_from_rng(&mut SysRng)?)
}

/// Big number
#[derive(Ord, PartialOrd)]
pub struct Bn(pub(crate) BigInt);

get_mod_impl!();

impl core::hash::Hash for Bn {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.0, state);
    }
}

clone_impl!(|b: &Bn| b.0.clone());
default_impl!(BigInt::default);
display_impl!(native);
eq_impl!();
#[cfg(target_pointer_width = "64")]
from_impl!(BigInt::from, i128);
#[cfg(target_pointer_width = "64")]
from_impl!(BigInt::from, u128);
from_impl!(BigInt::from, usize);
from_impl!(BigInt::from, u64);
from_impl!(BigInt::from, u32);
from_impl!(BigInt::from, u16);
from_impl!(BigInt::from, u8);
from_impl!(BigInt::from, isize);
from_impl!(BigInt::from, i64);
from_impl!(BigInt::from, i32);
from_impl!(BigInt::from, i16);
from_impl!(BigInt::from, i8);
iter_impl!();
serdes_impl!();
zeroize_impl!(|b: &mut Bn| b.0.set_zero());
binops_impl!(Add, add, AddAssign, add_assign, +, +=, |lhs: &BigInt, rhs: &BigInt| lhs + rhs);
binops_impl!(Sub, sub, SubAssign, sub_assign, -, -=, |lhs: &BigInt, rhs: &BigInt| lhs - rhs);
binops_impl!(Mul, mul, MulAssign, mul_assign, *, *=, |lhs: &BigInt, rhs: &BigInt| lhs * rhs);
binops_impl!(Div, div, DivAssign, div_assign, /, /=, |lhs: &BigInt, rhs: &BigInt| lhs / rhs);
binops_impl!(Rem, rem, RemAssign, rem_assign, %, %=, |lhs: &BigInt, rhs: &BigInt| lhs % rhs);
neg_impl!(|b: &BigInt| Bn(-b), |b: BigInt| Bn(-b));
shift_impl!(
    Shl,
    shl,
    ShlAssign,
    shl_assign,
    |lhs, rhs| Bn(lhs << rhs),
    |lhs, rhs| Bn(lhs << rhs)
);
shift_impl!(
    Shr,
    shr,
    ShrAssign,
    shr_assign,
    |lhs, rhs| Bn(lhs >> rhs),
    |lhs, rhs| Bn(lhs >> rhs)
);
#[cfg(feature = "wasm")]
wasm_slice_impl!(Bn);

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut lhs = self.0.iter_u32_digits();
        let mut rhs = other.0.iter_u32_digits();
        let mut difference = 0u32;
        loop {
            match (lhs.next(), rhs.next()) {
                (Some(lhs), Some(rhs)) => difference |= lhs ^ rhs,
                (Some(lhs), None) => difference |= lhs,
                (None, Some(rhs)) => difference |= rhs,
                (None, None) => break,
            }
        }
        u8::from(self.0.sign() == Sign::Minus).ct_eq(&u8::from(other.0.sign() == Sign::Minus))
            & difference.ct_eq(&0)
    }
}

impl Bn {
    fn reduce_mod_assign(&mut self, modulus: &BigInt) {
        self.0 %= modulus;
        if self.0.sign() == Sign::Minus {
            self.0 += modulus;
        }
    }

    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let nn = get_mod(n);
        if exponent.0 < BigInt::zero() {
            match self.invert(&nn) {
                None => Self::zero(),
                Some(a) => {
                    let e = -exponent.0.clone();
                    Self(a.0.modpow(&e, &nn.0))
                }
            }
        } else {
            Self(self.0.modpow(&exponent.0, &nn.0))
        }
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        Self((&self.0 + &rhs.0).mod_floor(&nn.0))
    }

    pub(crate) fn modadd_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        self.0 += &rhs.0;
        self.reduce_mod_assign(&modulus.0);
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        Self((&self.0 - &rhs.0).mod_floor(&nn.0))
    }

    pub(crate) fn modsub_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        self.0 -= &rhs.0;
        self.reduce_mod_assign(&modulus.0);
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        Self((&self.0 * &rhs.0).mod_floor(&nn.0))
    }

    pub(crate) fn modmul_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        self.0 *= &rhs.0;
        self.reduce_mod_assign(&modulus.0);
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        match rhs.invert(&nn) {
            None => Self::zero(),
            Some(r) => Self((&self.0 * &r.0).mod_floor(&nn.0)),
        }
    }

    pub(crate) fn moddiv_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        match rhs.invert(&modulus) {
            None => *self = Self::zero(),
            Some(inverse) => {
                self.0 *= inverse.0;
                self.reduce_mod_assign(&modulus.0);
            }
        }
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let nn = get_mod(n);
        let r = self.0.mod_floor(&nn.0);
        if r.is_zero() {
            Self::zero()
        } else {
            Self(&nn.0 - &r)
        }
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        let nn = get_mod(n);
        Self(self.0.mod_floor(&nn.0))
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, n: &Self) -> Option<Self> {
        if self.0.is_zero() || n.is_zero() || n.is_one() {
            return None;
        }

        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (n.0.clone(), self.0.clone());

        while !new_r.is_zero() {
            let quotient = &r / &new_r;

            swap(&mut t, &mut new_t);
            new_t -= &quotient * &t;

            swap(&mut r, &mut new_r);
            new_r -= quotient * &r;
        }
        if r > BigInt::one() {
            return None;
        } else if t < BigInt::zero() {
            t += &n.0;
        }

        Some(Self(t))
    }

    /// Return zero
    pub fn zero() -> Self {
        Self(BigInt::zero())
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Return whether this value is negative.
    pub fn is_negative(&self) -> bool {
        self.0.sign() == Sign::Minus
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.0.is_one()
    }

    /// Return one
    pub fn one() -> Self {
        Self(BigInt::one())
    }

    /// Return the bit length
    pub fn bit_length(&self) -> usize {
        self.0.bits() as usize
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Self) -> Self {
        Self(self.0.gcd(&other.0))
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Self) -> Self {
        Self(self.0.lcm(&other.0))
    }

    /// Generate a random value less than `n`
    pub fn random(n: &Self) -> crate::Result<Self> {
        Ok(Self::from_rng(n, &mut default_rng()?))
    }

    /// Generate a random value with `n` bits
    pub fn random_bits(n: u32) -> crate::Result<Self> {
        Ok(Self::from_rng_bits(n, &mut default_rng()?))
    }

    /// Generate a random value less than `n` using the specific random number generator
    pub fn from_rng(n: &Self, rng: &mut impl RngCore) -> Self {
        let bits = n.0.bits() as usize;
        let len_bytes = (bits - 1) / 8 + 1;
        let high_bits = len_bytes * 8 - bits;
        let mut t = vec![0u8; len_bytes];
        loop {
            rng.fill_bytes(&mut t);
            if high_bits > 0 {
                t[0] &= u8::MAX >> high_bits;
            }
            let b = BigInt::from_bytes_be(Sign::Plus, &t);
            if b < n.0 {
                return Self(b);
            }
        }
    }

    /// Generate a random value between [lower, upper)
    pub fn random_range(lower: &Self, upper: &Self) -> crate::Result<Self> {
        Self::random_range_with_rng(lower, upper, &mut default_rng()?)
    }

    /// Generate a random value between [lower, upper) using the specific random number generator
    pub fn random_range_with_rng(
        lower: &Self,
        upper: &Self,
        rng: &mut impl RngCore,
    ) -> crate::Result<Self> {
        if lower >= upper {
            return Err(crate::Error::InvalidRange);
        }
        let range = upper - lower;
        Ok(lower + Self::from_rng(&range, rng))
    }

    /// Generate a random value with `n` bits using the specific random number generator
    pub fn from_rng_bits(n: u32, rng: &mut impl RngCore) -> Self {
        let n = n as usize;
        if n == 0 {
            return Self::zero();
        }
        let mut t = vec![0u8; n.div_ceil(8)];
        rng.fill_bytes(&mut t);
        let excess_bits = t.len() * 8 - n;
        if excess_bits > 0 {
            t[0] &= u8::MAX >> excess_bits;
        }
        let b = BigInt::from_bytes_be(Sign::Plus, &t);
        Self(&b | BigInt::one() << (n - 1))
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self(BigInt::from_bytes_be(
            Sign::Plus,
            hasher.finalize().as_slice(),
        ))
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        Self(BigInt::from_bytes_be(Sign::Plus, b.as_ref()))
    }

    /// Convert this big number to a big-endian byte sequence
    pub fn to_bytes(&self) -> Vec<u8> {
        let (_, bytes) = self.0.to_bytes_be();
        bytes
    }

    /// Convert this big number to a big-endian byte sequence and store it in `buffer`.
    /// The sign is not included
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) -> crate::Result<()> {
        let expected = self
            .bit_length()
            .div_ceil(8)
            .max(usize::from(self.is_zero()));
        if buffer.len() != expected {
            return Err(crate::Error::BufferLength {
                expected,
                actual: buffer.len(),
            });
        }
        let len = buffer.len();
        buffer.fill(0);
        for (word_index, word) in self.0.iter_u32_digits().enumerate() {
            for (byte_index, byte) in word.to_le_bytes().into_iter().enumerate() {
                let from_end = word_index * size_of::<u32>() + byte_index;
                if from_end < len {
                    buffer[len - from_end - 1] = byte;
                }
            }
        }
        Ok(())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Self) -> GcdResult<Self> {
        let result = self.0.extended_gcd(&other.0);
        GcdResult {
            gcd: Self(result.gcd),
            x: Self(result.x),
            y: Self(result.y),
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> crate::Result<Self> {
        Self::safe_prime_from_rng(size, &mut default_rng()?)
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl RngCore) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 128, usize::MAX)?;
        Ok(Self(BigInt::from(safe_prime::from_rng(size, rng)?)))
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> crate::Result<Self> {
        Self::prime_from_rng(size, &mut default_rng()?)
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl RngCore) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 128, usize::MAX)?;
        Ok(Self(BigInt::from(prime::from_rng(size, rng)?)))
    }

    /// True if a prime number
    pub fn is_prime(&self) -> crate::Result<bool> {
        Ok(match self.0.to_biguint() {
            None => false,
            Some(b) => prime::strong_check_with(&b, &mut default_rng()?),
        })
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (d, r) = self.0.div_rem(&other.0);
        (Self(d), Self(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_prime() {
        let n = Bn::safe_prime(1024).unwrap();
        assert_eq!(n.0.bits(), 1024);
        assert!(n.is_prime().unwrap());
        let sg: Bn = n >> 1;
        assert!(sg.is_prime().unwrap())
    }

    #[test]
    fn ct_eq() {
        let a = Bn::from(8);
        let b = Bn::from(8);

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1u8);
    }
}
