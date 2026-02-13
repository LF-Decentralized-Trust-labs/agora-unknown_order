/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{get_mod, GcdResult};
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
use num_bigint::{BigInt, Sign, ToBigInt};
use num_integer::Integer;
use num_traits::{
    identities::{One, Zero},
    Num,
};
use rand::Rng as RngCore;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Big number
#[derive(Ord, PartialOrd, Hash)]
#[allow(clippy::derived_hash_with_manual_eq)]
pub struct Bn(pub(crate) BigInt);

clone_impl!(|b: &Bn| b.0.clone());
default_impl!(BigInt::default);
display_impl!();
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
serdes_impl!(
    |b: &Bn| b.0.to_str_radix(16),
    |s: &str| { BigInt::from_str_radix(s, 16).ok() },
    |b: &Bn| b.0.to_signed_bytes_be(),
    |s: &[u8]| -> Option<BigInt> { Some(BigInt::from_signed_bytes_be(s)) }
);
zeroize_impl!(|b: &mut Bn| b.0.set_zero());
binops_impl!(Add, add, AddAssign, add_assign, +, +=);
binops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
binops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
binops_impl!(Div, div, DivAssign, div_assign, /, /=);
binops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);
neg_impl!(|b: &BigInt| Bn(-b));
shift_impl!(Shl, shl, ShlAssign, shl_assign, |lhs, rhs| Bn(lhs << rhs));
shift_impl!(Shr, shr, ShrAssign, shr_assign, |lhs, rhs| Bn(lhs >> rhs));
#[cfg(feature = "wasm")]
wasm_slice_impl!(Bn);

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let res = self - other;
        Choice::from(if res.0.is_zero() { 1u8 } else { 0u8 })
    }
}

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert_ne!(n.0, BigInt::zero());
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
        let mut t = (self + rhs) % &nn;
        if t < Bn::zero() {
            t += &nn;
        }
        t
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (self - rhs) % &nn;
        if t < Bn::zero() {
            t += &nn;
        }
        t
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (self * rhs) % &nn;
        if t < Bn::zero() {
            t += &nn;
        }
        t
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        match rhs.invert(&nn) {
            None => Self::zero(),
            Some(r) => {
                let mut t = (self * r) % &nn;
                if t < Bn::zero() {
                    t += &nn;
                }
                t
            }
        }
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let mut t = self.clone() % n.clone();
        t = n.clone() - t.clone();
        t %= n.clone();
        t
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut out = self.clone() % nn;
        if out < Self::zero() {
            out += n;
        }
        out
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, n: &Self) -> Option<Self> {
        if self.0.is_zero() || n.is_zero() || n.is_one() {
            return None;
        }

        // Euclid's extended algorithm, Bèzout coefficient of `n` is not needed
        //n is either prime or coprime
        //
        //function inverse(a, n)
        //    t := 0;     newt := 1;
        //    r := n;     newr := a;
        //    while newr ≠ 0
        //        quotient := r div newr
        //        (t, newt) := (newt, t - quotient * newt)
        //        (r, newr) := (newr, r - quotient * newr)
        //    if r > 1 then return "a is not invertible"
        //    if t < 0 then t := t + n
        //    return t
        //
        let (mut t, mut new_t) = (BigInt::zero(), BigInt::one());
        let (mut r, mut new_r) = (n.clone().0, self.0.clone());

        while !new_r.is_zero() {
            let quotient = &r / &new_r;
            let temp_t = t.clone();
            let temp_new_t = new_t.clone();

            t = temp_new_t.clone();
            new_t = temp_t - &quotient * temp_new_t;

            let temp_r = r.clone();
            let temp_new_r = new_r.clone();

            r = temp_new_r.clone();
            new_r = temp_r - quotient * temp_new_r;
        }
        if r > BigInt::one() {
            // Not invertible
            return None;
        } else if t < BigInt::zero() {
            t += n.clone().0
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
    pub fn random(n: &Self) -> Self {
        let mut rng = rand::rng();
        Self::from_rng(n, &mut rng)
    }

    /// Generate a random value with `n` bits
    pub fn random_bits(n: u32) -> Self {
        Self::from_rng_bits(n, &mut rand::rng())
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
    pub fn random_range(lower: &Self, upper: &Self) -> Self {
        Self::random_range_with_rng(lower, upper, &mut rand::rng())
    }

    /// Generate a random value between [lower, upper) using the specific random number generator
    pub fn random_range_with_rng(lower: &Self, upper: &Self, rng: &mut impl RngCore) -> Self {
        if lower >= upper {
            panic!("lower bound is greater than or equal to upper bound");
        }
        let range = upper - lower;
        lower + Self::from_rng(&range, rng)
    }

    /// Generate a random value with `n` bits using the specific random number generator
    pub fn from_rng_bits(n: u32, rng: &mut impl RngCore) -> Self {
        let n = n as usize;
        let mut t = vec![0u8; n.div_ceil(8)];
        rng.fill_bytes(&mut t);
        let b = BigInt::from_bytes_be(Sign::Plus, &t);
        Self(&b | BigInt::one() << n)
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
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.to_bytes())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    #[allow(clippy::many_single_char_names)]
    pub fn extended_gcd(&self, other: &Self) -> GcdResult {
        let mut s = (Self::zero(), Self::one());
        let mut t = (Self::one(), Self::zero());
        let mut r = (other.clone(), self.clone());

        while !r.0.is_zero() {
            let q = r.1.clone() / r.0.clone();
            let f = |mut r: (Self, Self)| {
                swap(&mut r.0, &mut r.1);
                r.0 -= q.clone() * r.1.clone();
                r
            };
            r = f(r);
            s = f(s);
            t = f(t);
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
    pub fn safe_prime(size: usize) -> Self {
        let mut rng = rand::rng();
        Self::safe_prime_from_rng(size, &mut rng)
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl RngCore) -> Self {
        let mut adapter = RandAdapter(rng);
        let p = safe_prime::from_rng(size, &mut adapter).unwrap();
        Self(p.to_bigint().unwrap())
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> Self {
        let mut rng = rand::rng();
        Self::prime_from_rng(size, &mut rng)
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl RngCore) -> Self {
        let mut adapter = RandAdapter(rng);
        let p = prime::from_rng(size, &mut adapter).unwrap();
        Self(p.to_bigint().unwrap())
    }

    /// True if a prime number
    pub fn is_prime(&self) -> bool {
        match self.0.to_biguint() {
            None => false,
            Some(b) => prime::strong_check(&b),
        }
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (d, r) = self.0.div_rem(&other.0);
        (Self(d), Self(r))
    }
}

/// Adapter to bridge rand 0.10 `Rng` to rand_core 0.6 `RngCore` for glass_pumpkin compatibility
struct RandAdapter<'a, R: RngCore>(&'a mut R);

impl<R: RngCore> rand_core_06::RngCore for RandAdapter<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn safe_prime() {
    let n = Bn::safe_prime(1024);
    assert_eq!(n.0.bits(), 1024);
    assert!(n.is_prime());
    let sg: Bn = n >> 1;
    assert!(sg.is_prime())
}

#[test]
fn ct_eq() {
    let a = Bn::from(8);
    let b = Bn::from(8);

    assert_eq!(a.ct_eq(&b).unwrap_u8(), 1u8);
}
