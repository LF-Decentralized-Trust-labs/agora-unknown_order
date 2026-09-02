/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::GcdResult;
use core::{
    cmp::{Eq, Ordering, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    iter::{Product, Sum},
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
};
use rand::{
    SeedableRng,
    rngs::{StdRng, SysRng},
};
use rand_core::Rng as RngCore;
use rug::{Complete, Integer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

fn default_rng() -> crate::Result<StdRng> {
    Ok(StdRng::try_from_rng(&mut SysRng)?)
}

trait GmpShift {
    fn gmp_shift(self) -> u32;
}

impl GmpShift for u32 {
    fn gmp_shift(self) -> u32 {
        self
    }
}

macro_rules! gmp_shift_impl {
    ($($type:ty),+ $(,)?) => {
        $(
            impl GmpShift for $type {
                fn gmp_shift(self) -> u32 {
                    self as u32
                }
            }
        )+
    };
}

gmp_shift_impl!(u8, u16, u64, usize, i8, i16, i32, i64, isize);

fn gmp_shl<T: GmpShift>(lhs: &Integer, rhs: T) -> Bn {
    Bn(lhs.shl(rhs.gmp_shift()).complete())
}

fn gmp_shl_owned<T: GmpShift>(lhs: Integer, rhs: T) -> Bn {
    Bn(lhs << rhs.gmp_shift())
}

fn gmp_shr<T: GmpShift>(lhs: &Integer, rhs: T) -> Bn {
    Bn(lhs.shr(rhs.gmp_shift()).complete())
}

fn gmp_shr_owned<T: GmpShift>(lhs: Integer, rhs: T) -> Bn {
    Bn(lhs >> rhs.gmp_shift())
}

/// Big number
#[derive(Ord, PartialOrd)]
pub struct Bn(pub(crate) Integer);

get_mod_impl!();

impl core::hash::Hash for Bn {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.0, state);
    }
}

clone_impl!(|b: &Bn| b.0.clone());
default_impl!(Integer::new);
display_impl!(native);
eq_impl!();
#[cfg(target_pointer_width = "64")]
from_impl!(Integer::from, i128);
#[cfg(target_pointer_width = "64")]
from_impl!(Integer::from, u128);
from_impl!(Integer::from, usize);
from_impl!(Integer::from, u64);
from_impl!(Integer::from, u32);
from_impl!(Integer::from, u16);
from_impl!(Integer::from, u8);
from_impl!(Integer::from, isize);
from_impl!(Integer::from, i64);
from_impl!(Integer::from, i32);
from_impl!(Integer::from, i16);
from_impl!(Integer::from, i8);
iter_impl!();
serdes_impl!();
zeroize_impl!(|b: &mut Bn| b.0 -= b.0.clone());

binops_impl!(Add, add, AddAssign, add_assign, +, +=, |lhs: &Integer, rhs: &Integer| (lhs + rhs).complete());
binops_impl!(Sub, sub, SubAssign, sub_assign, -, -=, |lhs: &Integer, rhs: &Integer| (lhs - rhs).complete());
binops_impl!(Mul, mul, MulAssign, mul_assign, *, *=, |lhs: &Integer, rhs: &Integer| (lhs * rhs).complete());
binops_impl!(Div, div, DivAssign, div_assign, /, /=, |lhs: &Integer, rhs: &Integer| (lhs / rhs).complete());
binops_impl!(Rem, rem, RemAssign, rem_assign, %, %=, |lhs: &Integer, rhs: &Integer| (lhs % rhs).complete());
neg_impl!(|b: &Integer| Bn(b.neg().complete()), |b: Integer| Bn(-b));
shift_impl!(Shl, shl, ShlAssign, shl_assign, gmp_shl, gmp_shl_owned);
shift_impl!(Shr, shr, ShrAssign, shr_assign, gmp_shr, gmp_shr_owned);

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let lhs = self.0.as_limbs();
        let rhs = other.0.as_limbs();
        let mut difference = 0;
        for index in 0..lhs.len().max(rhs.len()) {
            let lhs_limb = lhs.get(index).copied().map_or(0, core::convert::identity);
            let rhs_limb = rhs.get(index).copied().map_or(0, core::convert::identity);
            difference |= lhs_limb ^ rhs_limb;
        }
        u8::from(self.0.is_negative()).ct_eq(&u8::from(other.0.is_negative()))
            & difference.ct_eq(&0)
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
        match exponent.0.cmp0() {
            Ordering::Less => match self.invert(n) {
                None => Self::zero(),
                Some(a) => {
                    let e = -exponent.0.clone();
                    Self(a.0.secure_pow_mod_ref(&e, &n.0).complete())
                }
            },
            Ordering::Equal => Self::one(),
            Ordering::Greater => Self(self.0.secure_pow_mod_ref(&exponent.0, &n.0).complete()),
        }
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (&self.0 + &rhs.0).complete();
        t.modulo_mut(&nn.0);
        Self(t)
    }

    pub(crate) fn modadd_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        self.0 += &rhs.0;
        self.0.modulo_mut(&modulus.0);
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (&self.0 - &rhs.0).complete();
        t.modulo_mut(&nn.0);
        Self(t)
    }

    pub(crate) fn modsub_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        self.0 -= &rhs.0;
        self.0.modulo_mut(&modulus.0);
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (&self.0 * &rhs.0).complete();
        t.modulo_mut(&nn.0);
        Self(t)
    }

    pub(crate) fn modmul_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        self.0 *= &rhs.0;
        self.0.modulo_mut(&modulus.0);
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        match rhs.invert(&nn) {
            None => Self::zero(),
            Some(r) => {
                let mut t = (&self.0 * &r.0).complete();
                t.modulo_mut(&nn.0);
                Self(t)
            }
        }
    }

    pub(crate) fn moddiv_assign(&mut self, rhs: &Self, n: &Self) {
        let modulus = get_mod(n);
        match rhs.invert(&modulus) {
            None => *self = Self::zero(),
            Some(inverse) => {
                self.0 *= inverse.0;
                self.0.modulo_mut(&modulus.0);
            }
        }
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let nn = get_mod(n);
        let r = self.0.modulo_ref(&nn.0).complete();
        if r.cmp0() == Ordering::Equal {
            Self::zero()
        } else {
            Self((&nn.0 - &r).complete())
        }
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        let nn = get_mod(n);
        Self(self.0.modulo_ref(&nn.0).complete())
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, modulus: &Bn) -> Option<Bn> {
        if self.is_zero() || modulus.is_zero() || modulus.is_one() {
            return None;
        }
        let mut t = self.clone();
        match t.0.invert_mut(&modulus.0) {
            Ok(()) => Some(t),
            Err(()) => None,
        }
    }

    /// Return zero
    pub fn zero() -> Self {
        Self(Integer::new())
    }

    /// Return one
    pub fn one() -> Self {
        Self(Integer::from(1))
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.0.cmp0() == Ordering::Equal
    }

    /// Return whether this value is negative.
    pub fn is_negative(&self) -> bool {
        self.0.is_negative()
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.0 == 1
    }

    /// Return the bit length
    pub fn bit_length(&self) -> usize {
        self.0.significant_bits() as usize
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Bn) -> Self {
        Self(self.0.gcd_ref(&other.0).complete())
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Bn) -> Self {
        Self(self.0.lcm_ref(&other.0).complete())
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
        if n == 0 {
            return Self::zero();
        }
        let mut t = vec![0u8; (n as usize).div_ceil(8)];
        rng.fill_bytes(&mut t);
        let excess_bits = t.len() * 8 - n as usize;
        if excess_bits > 0 {
            t[0] &= u8::MAX >> excess_bits;
        }
        let mut b = Self::from_slice(t);
        b.0.set_bit(n - 1, true);
        b
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self(Integer::from_digits(
            hasher.finalize().as_slice(),
            rug::integer::Order::MsfBe,
        ))
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        Self(Integer::from_digits(b.as_ref(), rug::integer::Order::MsfBe))
    }

    /// Convert this big number to a big-endian byte sequence
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        self.0.to_digits::<u8>(rug::integer::Order::MsfBe)
    }

    /// Convert this big number to a big-endian byte sequence and store it in `buffer`.
    /// The sign is not included
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) -> crate::Result<()> {
        let expected = self.bit_length().div_ceil(8);
        if buffer.len() != expected {
            return Err(crate::Error::BufferLength {
                expected,
                actual: buffer.len(),
            });
        }
        self.0.write_digits(buffer, rug::integer::Order::MsfBe);
        Ok(())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Bn) -> GcdResult<Self> {
        let (gcd, x, y) = self.0.extended_gcd_ref(&other.0).complete();
        GcdResult {
            gcd: Self(gcd),
            x: Self(x),
            y: Self(y),
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> crate::Result<Self> {
        Self::safe_prime_from_rng(size, &mut default_rng()?)
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl RngCore) -> crate::Result<Self> {
        use rug::integer::IsPrime;

        crate::error::validate_bit_length(size, 3, u32::MAX as usize)?;
        loop {
            let mut p = Self::from_rng_bits((size - 1) as u32, rng).0;
            p.next_prime_mut();
            p <<= 1;
            p += 1;

            // Using 25 to mimic GMP's use of 25 rounds in nextprime
            if let IsPrime::Yes | IsPrime::Probably = p.is_probably_prime(25) {
                return Ok(Self(p));
            };
        }
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> crate::Result<Self> {
        Self::prime_from_rng(size, &mut default_rng()?)
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl RngCore) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 2, u32::MAX as usize)?;
        let mut p = Self::from_rng_bits(size as u32, rng).0;
        p.next_prime_mut();

        Ok(Self(p))
    }

    /// True if a prime number
    pub fn is_prime(&self) -> crate::Result<bool> {
        use rug::integer::IsPrime;
        Ok(matches!(
            self.0.is_probably_prime(25),
            IsPrime::Yes | IsPrime::Probably
        ))
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (q, r) = self.0.div_rem_euc_ref(&other.0).complete();
        (Self(q), Self(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_prime() {
        let n = Bn::safe_prime(1024).unwrap();
        assert_eq!(n.0.significant_bits(), 1024);
        assert!(n.is_prime().unwrap());
        let sg: Bn = &n >> 1;
        assert!(sg.is_prime().unwrap());
        // Make sure it doesn't produce the same prime when called twice
        let m = Bn::safe_prime(1024).unwrap();
        assert_eq!(m.0.significant_bits(), 1024);
        assert!(m.is_prime().unwrap());
        let sg: Bn = &m >> 1;
        assert!(sg.is_prime().unwrap());
        assert_ne!(n, m);
    }

    #[test]
    fn div_rem_test() {
        let a = Bn::from(11);
        let b = Bn::from(3);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q, Bn::from(3));
        assert_eq!(r, Bn::from(2));

        let a = Bn::from(23);
        let b = Bn::from(10);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q, Bn::from(2));
        assert_eq!(r, Bn::from(3));
    }

    #[test]
    fn ct_eq() {
        let a = Bn::from(8);
        let b = Bn::from(8);

        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1u8);
    }

    #[test]
    fn modpow() {
        let p = Bn::from(7);
        let q = Bn::from(13);

        let n = &p * &q;

        let e = Bn::zero();
        let g = Bn::from(3);

        let o = g.modpow(&e, &n);

        assert_eq!(o, Bn::one());
    }
}
