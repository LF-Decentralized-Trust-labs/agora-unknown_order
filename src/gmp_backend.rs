/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{get_mod, GcdResult};
use core::{
    cmp::{Eq, Ordering, PartialEq, PartialOrd},
    fmt::{self, Debug, Display},
    iter::{Product, Sum},
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
};
use rand::Rng as RngCore;
use rug::rand::ThreadRandState;
use rug::{Assign, Complete, Integer};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// Big number
#[derive(Ord, PartialOrd, Hash)]
#[allow(clippy::derived_hash_with_manual_eq)]
pub struct Bn(pub(crate) Integer);

clone_impl!(|b: &Bn| b.0.clone());
default_impl!(Integer::new);
display_impl!();
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

binops_impl!(Add, add, AddAssign, add_assign, +, +=);
binops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
binops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
binops_impl!(Div, div, DivAssign, div_assign, /, /=);
binops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);
neg_impl!(|b: &Integer| Bn(b.neg().complete()));
shift_impl!(Shl, shl, ShlAssign, shl_assign, |lhs: &Integer, rhs| Bn(
    lhs.shl(rhs as u32).complete()
));
shift_impl!(Shr, shr, ShrAssign, shr_assign, |lhs: &Integer, rhs| Bn(
    lhs.shr(rhs as u32).complete()
));

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let res = self - other;
        Choice::from(if res.0.cmp0() == Ordering::Equal {
            1u8
        } else {
            0u8
        })
    }
}

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert_ne!(n.0, Integer::new());
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

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (&self.0 - &rhs.0).complete();
        t.modulo_mut(&nn.0);
        Self(t)
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let nn = get_mod(n);
        let mut t = (&self.0 * &rhs.0).complete();
        t.modulo_mut(&nn.0);
        Self(t)
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
    pub fn random(n: &Self) -> Self {
        let mut rng = GmpRand::default();
        Self::from_rng(n, &mut rng)
    }

    /// Generate a random value with `n` bits
    pub fn random_bits(n: u32) -> Self {
        Self::from_rng_bits(n, &mut rand::rng())
    }

    /// Generate a random value less than `n` using the specific random number generator
    pub fn from_rng(n: &Self, rng: &mut impl RngCore) -> Self {
        let mut e_rng = ExternalRand { rng };
        let mut rand_state = ThreadRandState::new_custom(&mut e_rng);
        let size = n.0.significant_bits();
        let mut x = Integer::new();

        loop {
            x.assign(Integer::random_bits(size, &mut rand_state));
            if x < n.0 {
                return Self(x);
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
        let mut t = vec![0u8; (n as usize).div_ceil(8)];
        rng.fill_bytes(&mut t);
        let mut b = Self::from_slice(t);
        b.0.set_bit(n, true);
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
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.to_bytes())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Bn) -> GcdResult {
        let (gcd, x, y) = self.0.extended_gcd_ref(&other.0).complete();
        GcdResult {
            gcd: Self(gcd),
            x: Self(x),
            y: Self(y),
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> Self {
        Self::safe_prime_from_rng(size, &mut GmpRand::default())
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl RngCore) -> Self {
        use rug::integer::IsPrime;

        let mut e_rng = ExternalRand { rng };
        let mut rand_state = ThreadRandState::new_custom(&mut e_rng);
        let mut p = Integer::new();

        loop {
            p.assign(Integer::random_bits((size - 1) as u32, &mut rand_state));

            // Set the MSB bit so that we're sampling from [2^(size - 2), 2^(size - 1))
            p.set_bit((size - 2) as u32, true);
            p.next_prime_mut();
            p <<= 1;
            p += 1;

            // Using 25 to mimic GMP's use of 25 rounds in nextprime
            if let IsPrime::Yes | IsPrime::Probably = p.is_probably_prime(25) {
                return Self(p);
            };
        }
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> Self {
        Self::prime_from_rng(size, &mut GmpRand::default())
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl RngCore) -> Self {
        let mut e_rng = ExternalRand { rng };
        let mut rand_state = ThreadRandState::new_custom(&mut e_rng);
        let mut p = Integer::new();
        p.assign(Integer::random_bits(size as u32, &mut rand_state));

        // Set the MSB bit so that we're sampling from [2^(size - 1), 2^size)
        p.set_bit((size - 1) as u32, true);

        p.next_prime_mut();

        Self(p)
    }

    /// True if a prime number
    pub fn is_prime(&self) -> bool {
        use rug::integer::IsPrime;
        matches!(
            self.0.is_probably_prime(25),
            IsPrime::Yes | IsPrime::Probably
        )
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let (q, r) = self.0.div_rem_euc_ref(&other.0).complete();
        (Self(q), Self(r))
    }
}

struct ExternalRand<'a, T: RngCore> {
    rng: &'a mut T,
}

impl<T: RngCore> rug::rand::ThreadRandGen for ExternalRand<'_, T> {
    fn gen(&mut self) -> u32 {
        self.rng.next_u32()
    }
}

struct GmpRand {
    rng: rand::rngs::ThreadRng,
}

impl Default for GmpRand {
    fn default() -> Self {
        Self { rng: rand::rng() }
    }
}

impl rug::rand::ThreadRandGen for GmpRand {
    fn gen(&mut self) -> u32 {
        self.rng.next_u32()
    }
}

impl rand::TryRng for GmpRand {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.rng.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.rng.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.rng.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn safe_prime() {
    let n = Bn::safe_prime(1024);
    assert_eq!(n.0.significant_bits(), 1024);
    assert!(n.is_prime());
    let sg: Bn = &n >> 1;
    assert!(sg.is_prime());
    // Make sure it doesn't produce the same prime when called twice
    let m = Bn::safe_prime(1024);
    assert_eq!(m.0.significant_bits(), 1024);
    assert!(m.is_prime());
    let sg: Bn = &m >> 1;
    assert!(sg.is_prime());
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

    let o = (&g).modpow(&e, &n);

    assert_eq!(o, Bn::one());
}
