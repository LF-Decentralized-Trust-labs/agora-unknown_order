/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::GcdResult;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::{
    cmp::{Eq, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    iter::{Product, Sum},
    mem::swap,
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
};
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use rand_core::Rng as RngCore;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

trait OpenSslResultExt<T> {
    fn or_abort(self) -> T;
}

impl<T> OpenSslResultExt<T> for Result<T, openssl::error::ErrorStack> {
    fn or_abort(self) -> T {
        match self {
            Ok(value) => value,
            Err(_) => std::process::abort(),
        }
    }
}

std::thread_local! {
    static BIG_NUM_CONTEXT: RefCell<BigNumContext> =
        RefCell::new(BigNumContext::new().or_abort());
}

fn with_context<T>(f: impl FnOnce(&mut BigNumContext) -> T) -> T {
    BIG_NUM_CONTEXT.with(|context| f(&mut context.borrow_mut()))
}

fn default_rng() -> crate::Result<StdRng> {
    Ok(StdRng::try_from_rng(&mut SysRng)?)
}

trait OpenSslShift {
    fn openssl_shift(self) -> i32;
}

impl OpenSslShift for i32 {
    fn openssl_shift(self) -> i32 {
        self
    }
}

macro_rules! openssl_shift_impl {
    ($($type:ty),+ $(,)?) => {
        $(
            impl OpenSslShift for $type {
                fn openssl_shift(self) -> i32 {
                    self as i32
                }
            }
        )+
    };
}

openssl_shift_impl!(u8, u16, u32, u64, usize, i8, i16, i64, isize);

fn openssl_shl<T: OpenSslShift>(lhs: &BigNum, rhs: T) -> Bn {
    let mut value = BigNum::new().or_abort();
    let shift = rhs.openssl_shift();
    if shift == 1 {
        BigNumRef::lshift1(&mut value, lhs).or_abort();
    } else {
        BigNumRef::lshift(&mut value, lhs, shift).or_abort();
    }
    Bn(value)
}

fn openssl_shr<T: OpenSslShift>(lhs: &BigNum, rhs: T) -> Bn {
    let mut value = BigNum::new().or_abort();
    let shift = rhs.openssl_shift();
    if shift == 1 {
        BigNumRef::rshift1(&mut value, lhs).or_abort();
    } else {
        BigNumRef::rshift(&mut value, lhs, shift).or_abort();
    }
    Bn(value)
}

/// Big number
#[derive(Ord, PartialOrd)]
pub struct Bn(pub(crate) BigNum);

impl core::hash::Hash for Bn {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.to_vec().hash(state)
    }
}

fn from_isize(d: isize) -> BigNum {
    from_signed_bytes(&d.unsigned_abs().to_be_bytes(), d < 0)
}

fn from_signed_bytes(bytes: &[u8], negative: bool) -> BigNum {
    let mut value = BigNum::from_slice(bytes).or_abort();
    value.set_negative(negative);
    value
}

clone_impl!(|b: &Bn| b.0.to_owned().or_abort());
default_impl!(|| BigNum::new().or_abort());
display_impl!(bytes);
eq_impl!();
from_impl!(
    |d: usize| BigNum::from_slice(&d.to_be_bytes()).or_abort(),
    usize
);
#[cfg(target_pointer_width = "64")]
from_impl!(
    |d: i128| { from_signed_bytes(&d.unsigned_abs().to_be_bytes(), d < 0) },
    i128
);
#[cfg(target_pointer_width = "64")]
from_impl!(
    |d: u128| BigNum::from_slice(&d.to_be_bytes()).or_abort(),
    u128
);
from_impl!(
    |d: u64| BigNum::from_slice(&d.to_be_bytes()).or_abort(),
    u64
);
from_impl!(|d: u32| BigNum::from_u32(d).or_abort(), u32);
from_impl!(|d: u16| BigNum::from_u32(d as u32).or_abort(), u16);
from_impl!(|d: u8| BigNum::from_u32(d as u32).or_abort(), u8);
from_impl!(from_isize, isize);
from_impl!(
    |d: i64| from_signed_bytes(&d.unsigned_abs().to_be_bytes(), d < 0),
    i64
);
from_impl!(
    |d: i32| from_signed_bytes(&d.unsigned_abs().to_be_bytes(), d < 0),
    i32
);
from_impl!(
    |d: i16| from_signed_bytes(&d.unsigned_abs().to_be_bytes(), d < 0),
    i16
);
from_impl!(
    |d: i8| from_signed_bytes(&d.unsigned_abs().to_be_bytes(), d < 0),
    i8
);
iter_impl!();
serdes_impl!();
zeroize_impl!(|b: &mut Bn| b.0.clear());

impl Add<&Bn> for &Bn {
    type Output = Bn;

    fn add(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().or_abort();
        BigNumRef::checked_add(&mut bn, &self.0, &rhs.0).or_abort();
        Bn(bn)
    }
}

impl Sub<&Bn> for &Bn {
    type Output = Bn;

    fn sub(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().or_abort();
        BigNumRef::checked_sub(&mut bn, &self.0, &rhs.0).or_abort();
        Bn(bn)
    }
}

impl Mul<&Bn> for &Bn {
    type Output = Bn;

    fn mul(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::checked_mul(&mut bn, &self.0, &rhs.0, ctx).or_abort();
        });
        Bn(bn)
    }
}

impl Div<&Bn> for &Bn {
    type Output = Bn;

    fn div(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::checked_div(&mut bn, &self.0, &rhs.0, ctx).or_abort();
        });
        Bn(bn)
    }
}

impl Rem<&Bn> for &Bn {
    type Output = Bn;

    fn rem(self, rhs: &Self::Output) -> Self::Output {
        let mut bn = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::checked_rem(&mut bn, &self.0, &rhs.0, ctx).or_abort();
        });
        Bn(bn)
    }
}

impl<'b> AddAssign<&'b Bn> for Bn {
    fn add_assign(&mut self, rhs: &'b Bn) {
        let mut result = BigNum::new().or_abort();
        BigNumRef::checked_add(&mut result, &self.0, &rhs.0).or_abort();
        self.0 = result;
    }
}

impl<'b> SubAssign<&'b Bn> for Bn {
    fn sub_assign(&mut self, rhs: &'b Bn) {
        let mut result = BigNum::new().or_abort();
        BigNumRef::checked_sub(&mut result, &self.0, &rhs.0).or_abort();
        self.0 = result;
    }
}

impl<'b> MulAssign<&'b Bn> for Bn {
    fn mul_assign(&mut self, rhs: &'b Bn) {
        let mut result = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::checked_mul(&mut result, &self.0, &rhs.0, ctx).or_abort();
        });
        self.0 = result;
    }
}

impl<'b> DivAssign<&'b Bn> for Bn {
    fn div_assign(&mut self, rhs: &'b Bn) {
        let mut result = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::checked_div(&mut result, &self.0, &rhs.0, ctx).or_abort();
        });
        self.0 = result;
    }
}

impl<'b> RemAssign<&'b Bn> for Bn {
    fn rem_assign(&mut self, rhs: &'b Bn) {
        let mut result = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::checked_rem(&mut result, &self.0, &rhs.0, ctx).or_abort();
        });
        self.0 = result;
    }
}

ops_impl!(Add, add, AddAssign, add_assign, +, +=);
ops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
ops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
ops_impl!(Div, div, DivAssign, div_assign, /, /=);
ops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);
neg_impl!(
    |b: &BigNum| {
        let mut n = b.to_owned().or_abort();
        n.set_negative(!b.is_negative());
        Bn(n)
    },
    |mut b: BigNum| {
        let negative = !b.is_negative();
        b.set_negative(negative);
        Bn(b)
    }
);
shift_impl!(Shl, shl, ShlAssign, shl_assign, openssl_shl);
shift_impl!(Shr, shr, ShrAssign, shr_assign, openssl_shr);

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let lhs = self.to_bytes();
        let rhs = other.to_bytes();
        crate::ct_eq_bytes(self.0.is_negative(), &lhs, other.0.is_negative(), &rhs)
    }
}

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut bn = BigNum::new().or_abort();
        if exponent.0.is_negative() {
            match self.invert(n) {
                None => {}
                Some(a) => {
                    let e = -exponent.clone();
                    with_context(|ctx| {
                        BigNumRef::mod_exp(&mut bn, &a.0, &e.0, &n.0, ctx).or_abort();
                    });
                }
            }
        } else {
            with_context(|ctx| {
                BigNumRef::mod_exp(&mut bn, &self.0, &exponent.0, &n.0, ctx).or_abort();
            });
        }
        Self(bn)
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut t = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::mod_add(&mut t, &self.0, &rhs.0, &n.0, ctx).or_abort();
        });
        Bn(t)
    }

    pub(crate) fn modadd_assign(&mut self, rhs: &Self, n: &Self) {
        *self = self.modadd(rhs, n);
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut t = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::mod_sub(&mut t, &self.0, &rhs.0, &n.0, ctx).or_abort();
        });
        Bn(t)
    }

    pub(crate) fn modsub_assign(&mut self, rhs: &Self, n: &Self) {
        *self = self.modsub(rhs, n);
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut t = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::mod_mul(&mut t, &self.0, &rhs.0, &n.0, ctx).or_abort();
        });
        Bn(t)
    }

    pub(crate) fn modmul_assign(&mut self, rhs: &Self, n: &Self) {
        *self = self.modmul(rhs, n);
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut t = BigNum::new().or_abort();
        match rhs.invert(n) {
            Some(inverse) => {
                with_context(|ctx| {
                    BigNumRef::mod_mul(&mut t, &self.0, &inverse.0, &n.0, ctx).or_abort();
                });
                Bn(t)
            }
            None => Self::zero(),
        }
    }

    pub(crate) fn moddiv_assign(&mut self, rhs: &Self, n: &Self) {
        *self = self.moddiv(rhs, n);
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut t = BigNum::new().or_abort();
        let zero = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::mod_sub(&mut t, &zero, &self.0, &n.0, ctx).or_abort();
        });
        Bn(t)
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let mut t = BigNum::new().or_abort();
        with_context(|ctx| BigNumRef::nnmod(&mut t, &self.0, &n.0, ctx).or_abort());
        Bn(t)
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, modulus: &Bn) -> Option<Bn> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }
        let mut bn = BigNum::new().or_abort();
        with_context(|ctx| BigNumRef::mod_inverse(&mut bn, &self.0, &modulus.0, ctx))
            .ok()
            .map(|()| Self(bn))
    }

    /// Return zero
    pub fn zero() -> Self {
        Self(BigNum::new().or_abort())
    }

    /// Return one
    pub fn one() -> Self {
        Self(BigNum::from_u32(1).or_abort())
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.0.num_bits() == 0
    }

    /// Return whether this value is negative.
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.0.num_bits() == 1 && self.0.is_bit_set(0)
    }

    /// Return the bit length
    pub fn bit_length(&self) -> usize {
        self.0.num_bits() as usize
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Bn) -> Self {
        let mut bn = BigNum::new().or_abort();
        with_context(|ctx| BigNumRef::gcd(&mut bn, &self.0, &other.0, ctx).or_abort());
        Self(bn)
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Bn) -> Self {
        if self.is_zero() && other.is_zero() {
            Self::zero()
        } else {
            self / self.gcd(other) * other
        }
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
        if n.is_zero() {
            return Self::zero();
        }
        let bits = n.bit_length();
        let count = bits.div_ceil(8);
        let excess_bits = count * 8 - bits;
        let mut bytes = vec![0u8; count];
        loop {
            rng.fill_bytes(&mut bytes);
            if excess_bits > 0 {
                bytes[0] &= u8::MAX >> excess_bits;
            }
            let value = Self::from_slice(&bytes);
            if value < *n {
                return value;
            }
        }
    }

    /// Generate a random value between [lower, upper)
    pub fn random_range(lower: &Self, upper: &Self) -> crate::Result<Self> {
        if lower >= upper {
            return Err(crate::Error::InvalidRange);
        }
        let range = upper - lower;
        Ok(lower + Self::from_rng(&range, &mut default_rng()?))
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
        if n == 0 {
            return Self::zero();
        }
        let mut t = vec![0u8; (n as usize).div_ceil(8)];
        rng.fill_bytes(&mut t);
        let excess_bits = t.len() * 8 - n as usize;
        if excess_bits > 0 {
            t[0] &= u8::MAX >> excess_bits;
        }
        let mut r = Self::from_slice(&t);
        r.0.set_bit((n - 1) as i32).or_abort();
        r
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self(BigNum::from_slice(hasher.finalize().as_slice()).or_abort())
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        Self(BigNum::from_slice(b.as_ref()).or_abort())
    }

    /// Convert this big number to a big-endian byte sequence
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Convert this big number to a big-endian byte sequence and store it in `buffer`.
    /// The sign is not included
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) -> crate::Result<()> {
        let bytes = self.to_bytes();
        if buffer.len() != bytes.len() {
            return Err(crate::Error::BufferLength {
                expected: bytes.len(),
                actual: buffer.len(),
            });
        }
        buffer.copy_from_slice(&bytes);
        Ok(())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Bn) -> GcdResult<Self> {
        let mut s = (Self::zero(), Self::one());
        let mut t = (Self::one(), Self::zero());
        let mut r = (other.clone(), self.clone());

        while !r.0.is_zero() {
            let q = &r.1 / &r.0;

            swap(&mut r.0, &mut r.1);
            r.0 -= &q * &r.1;

            swap(&mut s.0, &mut s.1);
            s.0 -= &q * &s.1;

            swap(&mut t.0, &mut t.1);
            t.0 -= &q * &t.1;
        }

        if r.1 >= Self::zero() {
            GcdResult {
                gcd: r.1,
                x: s.1,
                y: t.1,
            }
        } else {
            GcdResult {
                gcd: Self::zero() - r.1,
                x: Self::zero() - s.1,
                y: Self::zero() - t.1,
            }
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 3, i32::MAX as usize)?;
        let mut p = BigNum::new()?;
        BigNumRef::generate_prime(&mut p, size as i32, true, None, None)?;
        Ok(Self(p))
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl RngCore) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 3, i32::MAX as usize)?;
        let mut two_q = BigNum::new()?;
        let one = BigNum::from_u32(1)?;
        let mut p = BigNum::new()?;
        loop {
            let q = Self::prime_from_rng(size - 1, rng)?;
            // p = 2q + 1
            BigNumRef::lshift1(&mut two_q, &q.0)?;
            BigNumRef::checked_add(&mut p, &two_q, &one)?;

            if with_context(|ctx| BigNumRef::is_prime(&p, 25, ctx))? {
                return Ok(Self(p));
            }
        }
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 2, i32::MAX as usize)?;
        let mut p = BigNum::new()?;
        BigNumRef::generate_prime(&mut p, size as i32, false, None, None)?;
        Ok(Self(p))
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl RngCore) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 2, i32::MAX as usize)?;
        let byte_len = size.div_ceil(8);
        let extra_bits = byte_len * 8 - size;
        let mut bytes = vec![0u8; byte_len];
        loop {
            rng.fill_bytes(&mut bytes);
            if extra_bits > 0 {
                bytes[0] &= u8::MAX >> extra_bits;
            }
            let mut candidate = BigNum::from_slice(&bytes)?;
            // Set MSB to ensure correct bit length
            candidate.set_bit((size - 1) as i32)?;
            // Set LSB to ensure odd
            candidate.set_bit(0)?;

            if with_context(|ctx| BigNumRef::is_prime(&candidate, 25, ctx))? {
                return Ok(Self(candidate));
            }
        }
    }

    /// True if a prime number
    pub fn is_prime(&self) -> crate::Result<bool> {
        Ok(with_context(|ctx| BigNumRef::is_prime(&self.0, 15, ctx))?)
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let mut div = BigNum::new().or_abort();
        let mut rem = BigNum::new().or_abort();
        with_context(|ctx| {
            BigNumRef::div_rem(&mut div, &mut rem, &self.0, &other.0, ctx).or_abort();
        });
        (Self(div), Self(rem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_prime() {
        let n = Bn::safe_prime(1024).unwrap();
        assert_eq!(n.0.num_bits(), 1024);
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
