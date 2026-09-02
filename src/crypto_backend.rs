/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{GcdResult, decode_signed_hex, encode_signed_hex};
use core::{
    cmp::Ordering,
    fmt::{self, Binary, Debug, Display, Formatter, LowerHex, Octal, UpperHex},
    hash::{Hash, Hasher},
    iter::{Product, Sum},
    mem,
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
    str::FromStr,
};
use crypto_bigint::{
    BitOps, BoxedUint, ConcatenatingMul, Gcd, Integer, Limb, NonZero, Odd, RandomBits, RandomMod,
    Resize, Word,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use rand_core::CryptoRng;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// The sign of a [`BigNumber`](crate::crypto::BigNumber).
pub enum Sign {
    /// A negative value.
    Minus,
    /// Zero, which has no sign.
    None,
    /// A positive value.
    Plus,
}

impl Neg for Sign {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self::Output {
        match self {
            Self::Minus => Self::Plus,
            Self::None => Self::None,
            Self::Plus => Self::Minus,
        }
    }
}

impl Mul for Sign {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Sign::None, _) | (_, Sign::None) => Sign::None,
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => Sign::Plus,
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => Sign::Minus,
        }
    }
}

impl Display for Sign {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Minus => "-",
                _ => "",
            }
        )
    }
}

impl FromStr for Sign {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "-" => Ok(Self::Minus),
            _ => Ok(Self::Plus),
        }
    }
}

impl Serialize for Sign {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if s.is_human_readable() {
            match self {
                Self::Minus => "-".serialize(s),
                Self::None => "00".serialize(s),
                Self::Plus => None::<&str>.serialize(s),
            }
        } else {
            i8::from(self).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Sign {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            struct SignStrVisitor;

            impl<'de> Visitor<'de> for SignStrVisitor {
                type Value = Sign;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "00, -, or empty")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if v.is_empty() {
                        Ok(Sign::Plus)
                    } else if v == "00" {
                        Ok(Sign::None)
                    } else if v == "-" {
                        Ok(Sign::Minus)
                    } else {
                        Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
                    }
                }
            }
            d.deserialize_str(SignStrVisitor)
        } else {
            let sign = i8::deserialize(d)?;
            Self::try_from(sign).map_err(|_| {
                de::Error::invalid_value(de::Unexpected::Signed(sign.into()), &"-1, 0, or 1")
            })
        }
    }
}

impl From<Sign> for i8 {
    fn from(sign: Sign) -> i8 {
        match sign {
            Sign::Minus => -1,
            Sign::None => 0,
            Sign::Plus => 1,
        }
    }
}

impl From<&Sign> for i8 {
    fn from(sign: &Sign) -> i8 {
        i8::from(*sign)
    }
}

impl TryFrom<i8> for Sign {
    type Error = &'static str;

    fn try_from(sign: i8) -> Result<Self, Self::Error> {
        match sign {
            -1 => Ok(Sign::Minus),
            0 => Ok(Sign::None),
            1 => Ok(Sign::Plus),
            _ => Err("expected -1, 0, or 1"),
        }
    }
}

impl ConstantTimeEq for Sign {
    fn ct_eq(&self, other: &Self) -> Choice {
        i8::from(self).ct_eq(&i8::from(other))
    }
}

impl Sign {
    /// [`true`] if == Minus
    pub fn is_negative(&self) -> bool {
        self == &Self::Minus
    }

    /// [`true`] if == NoSign
    pub fn is_zero(&self) -> bool {
        self == &Self::None
    }

    /// [`true`] if == Plus
    pub fn is_positive(&self) -> bool {
        self == &Self::Plus
    }
}

/// Big number with dynamically-sized precision
pub struct Bn {
    pub(crate) sign: Sign,
    pub(crate) value: BoxedUint,
}

/// Return the smallest limb-aligned precision capable of storing `bits` bits.
fn precision_for_bits(bits: u32) -> u32 {
    bits.max(1).next_multiple_of(Limb::BITS)
}

/// Remove unused high limbs after an operation grows its working precision.
fn minimize(value: BoxedUint) -> BoxedUint {
    let precision = precision_for_bits(value.bits());
    value.resize(precision)
}

fn cmp_magnitude(a: &BoxedUint, b: &BoxedUint) -> Ordering {
    a.cmp_vartime(b)
}

fn add_magnitudes(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    let (mut value, carry) = a.carrying_add(b, Limb::ZERO);
    if carry != Limb::ZERO {
        let precision = value.bits_precision() + Limb::BITS;
        value = value.resize(precision);
        let last = value.as_words().len() - 1;
        value.as_mut_words()[last] = carry.0;
    }
    value
}

fn add_magnitudes_owned(mut value: BoxedUint, rhs: &BoxedUint) -> BoxedUint {
    if value.bits_precision() < rhs.bits_precision() {
        value = value.resize(rhs.bits_precision());
    }
    let overflow = value.overflowing_add_assign(rhs);
    if bool::from(overflow) {
        let precision = value.bits_precision() + Limb::BITS;
        value = value.resize(precision);
        let last = value.as_words().len() - 1;
        value.as_mut_words()[last] = 1;
    }
    value
}

fn add_magnitudes_owned_pair(mut lhs: BoxedUint, mut rhs: BoxedUint) -> BoxedUint {
    if lhs.bits_precision() < rhs.bits_precision() {
        mem::swap(&mut lhs, &mut rhs);
    }
    add_magnitudes_owned(lhs, &rhs)
}

fn sub_magnitudes(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    minimize(sub_magnitudes_fixed(a, b))
}

fn sub_magnitudes_owned(mut value: BoxedUint, rhs: &BoxedUint) -> BoxedUint {
    value -= rhs;
    minimize(value)
}

fn sub_magnitudes_fixed(a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
    let (value, _) = a.borrowing_sub(b, Limb::ZERO);
    value
}

impl Clone for Bn {
    fn clone(&self) -> Self {
        Self {
            sign: self.sign,
            value: self.value.clone(),
        }
    }
}

impl Default for Bn {
    fn default() -> Self {
        Self {
            sign: Sign::None,
            value: BoxedUint::zero(),
        }
    }
}

impl Display for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.sign, self.value.to_string_radix_vartime(10))
    }
}

impl Debug for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:?}", self.sign, self.value)
    }
}

impl Binary for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.sign, self.value.to_string_radix_vartime(2))
    }
}

impl Octal for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.sign, self.value.to_string_radix_vartime(8))
    }
}

impl LowerHex for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.sign, self.value.to_string_radix_vartime(16))
    }
}

impl UpperHex for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut value = self.value.to_string_radix_vartime(16);
        value.make_ascii_uppercase();
        write!(f, "{}{}", self.sign, value)
    }
}

impl Eq for Bn {}

impl PartialEq for Bn {
    fn eq(&self, other: &Self) -> bool {
        if self.sign != other.sign {
            return false;
        }
        cmp_magnitude(&self.value, &other.value) == Ordering::Equal
    }
}

impl PartialOrd for Bn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bn {
    fn cmp(&self, other: &Self) -> Ordering {
        let scmp = self.sign.cmp(&other.sign);
        if scmp != Ordering::Equal {
            return scmp;
        }

        match self.sign {
            Sign::None => Ordering::Equal,
            Sign::Plus => cmp_magnitude(&self.value, &other.value),
            Sign::Minus => cmp_magnitude(&other.value, &self.value),
        }
    }
}

impl Hash for Bn {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sign.hash(state);
        let words = self.value.as_words();
        let significant_words = words
            .iter()
            .rposition(|word| *word != 0)
            .map_or(&words[..0], |last| &words[..=last]);
        significant_words.hash(state);
    }
}

macro_rules! from_uint_impl {
    ($($type:tt),+$(,)*) => {
        $(
            impl From<$type> for Bn {
                fn from(value: $type) -> Self {
                    Self {
                        sign: if value != 0 { Sign::Plus } else { Sign::None },
                        value: minimize(BoxedUint::from(value))
                    }
                }
            }
        )+
    };
}

macro_rules! from_sint_impl {
    ($($stype:tt => $utype:tt),+$(,)*) => {
        $(
            impl From<$stype> for Bn {
                fn from(value: $stype) -> Self {
                    let (sign, value) = match 0.cmp(&value) {
                            Ordering::Greater => (Sign::Minus, value.unsigned_abs() as $utype),
                            Ordering::Equal => (Sign::None, 0 as $utype),
                            Ordering::Less => (Sign::Plus, value as $utype),
                    };
                    Self {
                        sign,
                        value: minimize(BoxedUint::from(value))
                    }
                }
            }
        )+
    };
}

macro_rules! ops_impl {
    (@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt, $($rhs:ty),+) => {$(
        impl<'a> $ops<$rhs> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $opr Bn::from(rhs)
            }
        }

        impl $ops<$rhs> for Bn {
            type Output = Self;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $opr Self::from(rhs)
            }
        }

        impl $ops_assign<$rhs> for Bn {
            fn $func_assign(&mut self, rhs: $rhs) {
                *self $opr_assign Self::from(rhs);
            }
        }
    )*};
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt) => {
        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, u8, u16, u32, u64, usize);
        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, i8, i16, i32, i64, isize);
    };
}

impl From<usize> for Bn {
    fn from(value: usize) -> Self {
        Self {
            sign: if value == 0 { Sign::None } else { Sign::Plus },
            value: minimize(BoxedUint::from(value as u64)),
        }
    }
}

#[cfg(target_pointer_width = "64")]
from_uint_impl!(u128);
from_uint_impl!(u64, u32, u16, u8);
#[cfg(target_pointer_width = "64")]
from_sint_impl!(i128 => u128);
from_sint_impl!(isize => u64, i64 => u64, i32 => u32, i16 => u16, i8 => u8);

impl Neg for Bn {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            sign: -self.sign,
            value: self.value,
        }
    }
}

impl Neg for &Bn {
    type Output = Bn;

    fn neg(self) -> Self::Output {
        Bn {
            sign: -self.sign,
            value: self.value.clone(),
        }
    }
}

impl<'a> Add<&'a Bn> for &Bn {
    type Output = Bn;

    fn add(self, rhs: &'a Bn) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self.clone(),
            (Sign::None, _) => rhs.clone(),
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => Bn {
                sign: self.sign,
                value: add_magnitudes(&self.value, &rhs.value),
            },
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                match cmp_magnitude(&self.value, &rhs.value) {
                    Ordering::Less => Bn {
                        sign: rhs.sign,
                        value: sub_magnitudes(&rhs.value, &self.value),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: sub_magnitudes(&self.value, &rhs.value),
                    },
                    Ordering::Equal => Bn::default(),
                }
            }
        }
    }
}

impl Add<Bn> for &Bn {
    type Output = Bn;

    fn add(self, rhs: Bn) -> Self::Output {
        rhs + self
    }
}

impl Add<&Bn> for Bn {
    type Output = Self;

    fn add(self, rhs: &Bn) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self,
            (Sign::None, _) => rhs.clone(),
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => Bn {
                sign: self.sign,
                value: add_magnitudes_owned(self.value, &rhs.value),
            },
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                match cmp_magnitude(&self.value, &rhs.value) {
                    Ordering::Less => Bn {
                        sign: rhs.sign,
                        value: sub_magnitudes(&rhs.value, &self.value),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: sub_magnitudes_owned(self.value, &rhs.value),
                    },
                    Ordering::Equal => Bn::zero(),
                }
            }
        }
    }
}

impl Add for Bn {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self,
            (Sign::None, _) => rhs,
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => Bn {
                sign: self.sign,
                value: add_magnitudes_owned_pair(self.value, rhs.value),
            },
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                match cmp_magnitude(&self.value, &rhs.value) {
                    Ordering::Less => Bn {
                        sign: rhs.sign,
                        value: sub_magnitudes_owned(rhs.value, &self.value),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: sub_magnitudes_owned(self.value, &rhs.value),
                    },
                    Ordering::Equal => Bn::zero(),
                }
            }
        }
    }
}

impl AddAssign for Bn {
    fn add_assign(&mut self, rhs: Self) {
        let n = mem::replace(self, Bn::zero());
        *self = n + rhs;
    }
}

impl AddAssign<&Bn> for Bn {
    fn add_assign(&mut self, rhs: &Bn) {
        let n = mem::replace(self, Bn::zero());
        *self = n + rhs;
    }
}

impl<'a> Sub<&'a Bn> for &Bn {
    type Output = Bn;

    fn sub(self, rhs: &'a Bn) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self.clone(),
            (Sign::None, _) => -rhs.clone(),
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => Bn {
                sign: self.sign,
                value: add_magnitudes(&self.value, &rhs.value),
            },
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => {
                match cmp_magnitude(&self.value, &rhs.value) {
                    Ordering::Less => Bn {
                        sign: -self.sign,
                        value: sub_magnitudes(&rhs.value, &self.value),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: sub_magnitudes(&self.value, &rhs.value),
                    },
                    Ordering::Equal => Bn::zero(),
                }
            }
        }
    }
}

impl Sub<Bn> for &Bn {
    type Output = Bn;

    fn sub(self, rhs: Bn) -> Self::Output {
        -(rhs - self)
    }
}

impl Sub<&Bn> for Bn {
    type Output = Self;

    fn sub(self, rhs: &Bn) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self,
            (Sign::None, _) => -rhs,
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => Bn {
                sign: self.sign,
                value: add_magnitudes_owned(self.value, &rhs.value),
            },
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => {
                match cmp_magnitude(&self.value, &rhs.value) {
                    Ordering::Less => Bn {
                        sign: -self.sign,
                        value: sub_magnitudes(&rhs.value, &self.value),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: sub_magnitudes_owned(self.value, &rhs.value),
                    },
                    Ordering::Equal => Bn::zero(),
                }
            }
        }
    }
}

impl Sub for Bn {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        match (self.sign, rhs.sign) {
            (_, Sign::None) => self,
            (Sign::None, _) => -rhs,
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => Bn {
                sign: self.sign,
                value: add_magnitudes_owned_pair(self.value, rhs.value),
            },
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => {
                match cmp_magnitude(&self.value, &rhs.value) {
                    Ordering::Less => Bn {
                        sign: -self.sign,
                        value: sub_magnitudes_owned(rhs.value, &self.value),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: sub_magnitudes_owned(self.value, &rhs.value),
                    },
                    Ordering::Equal => Bn::zero(),
                }
            }
        }
    }
}

impl SubAssign for Bn {
    fn sub_assign(&mut self, rhs: Self) {
        let n = mem::replace(self, Bn::zero());
        *self = n - rhs;
    }
}

impl SubAssign<&Bn> for Bn {
    fn sub_assign(&mut self, rhs: &Bn) {
        let n = mem::replace(self, Bn::zero());
        *self = n - rhs;
    }
}

impl<'a> Mul<&'a Bn> for &Bn {
    type Output = Bn;

    fn mul(self, rhs: &'a Bn) -> Self::Output {
        let sign = self.sign * rhs.sign;
        if sign == Sign::None {
            return Bn::default();
        }
        Bn {
            sign,
            value: minimize(self.value.concatenating_mul(&rhs.value)),
        }
    }
}

impl Mul<Bn> for &Bn {
    type Output = Bn;

    fn mul(self, rhs: Bn) -> Self::Output {
        self * &rhs
    }
}

impl Mul<&Bn> for Bn {
    type Output = Self;

    fn mul(self, rhs: &Bn) -> Self::Output {
        &self * rhs
    }
}

impl Mul for Bn {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        &self * &rhs
    }
}

impl MulAssign<&Bn> for Bn {
    fn mul_assign(&mut self, rhs: &Bn) {
        let n = mem::replace(self, Bn::zero());
        *self = &n * rhs;
    }
}

impl MulAssign for Bn {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl<'a> Div<&'a Bn> for &Bn {
    type Output = Bn;

    fn div(self, rhs: &'a Bn) -> Self::Output {
        let (q, _) = self.div_rem(rhs);
        q
    }
}

impl Div<Bn> for &Bn {
    type Output = Bn;

    fn div(self, rhs: Bn) -> Self::Output {
        self / &rhs
    }
}

impl Div<&Bn> for Bn {
    type Output = Self;

    fn div(self, rhs: &Bn) -> Self::Output {
        &self / rhs
    }
}

impl Div for Bn {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        &self / &rhs
    }
}

impl DivAssign<&Bn> for Bn {
    fn div_assign(&mut self, rhs: &Bn) {
        *self = &*self / rhs;
    }
}

impl DivAssign for Bn {
    fn div_assign(&mut self, rhs: Self) {
        *self = &*self / rhs;
    }
}

impl<'a> Rem<&'a Bn> for &Bn {
    type Output = Bn;

    fn rem(self, rhs: &'a Bn) -> Self::Output {
        let (_, r) = self.div_rem(rhs);
        r
    }
}

impl Rem<Bn> for &Bn {
    type Output = Bn;

    fn rem(self, rhs: Bn) -> Self::Output {
        self % &rhs
    }
}

impl Rem<&Bn> for Bn {
    type Output = Self;

    fn rem(self, rhs: &Bn) -> Self::Output {
        &self % rhs
    }
}

impl Rem for Bn {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        &self % &rhs
    }
}

impl RemAssign<&Bn> for Bn {
    fn rem_assign(&mut self, rhs: &Bn) {
        *self = &*self % rhs;
    }
}

impl RemAssign for Bn {
    fn rem_assign(&mut self, rhs: Self) {
        *self = &*self % &rhs;
    }
}

macro_rules! shift_impl {
(@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $ref_op:expr, $owned_op:expr, $($rhs:ty),+) => {$(
    impl<'a> $ops<$rhs> for &'a Bn {
        type Output = Bn;

        fn $func(self, rhs: $rhs) -> Self::Output {
            $ref_op(self, rhs as u32)
        }
    }

    impl $ops<$rhs> for Bn {
        type Output = Self;

        fn $func(self, rhs: $rhs) -> Self::Output {
            $owned_op(self, rhs as u32)
        }
    }

        impl $ops_assign<$rhs> for Bn {
            fn $func_assign(&mut self, rhs: $rhs) {
                let value = mem::replace(self, Bn::zero());
                *self = $owned_op(value, rhs as u32);
            }
        }
)*};
($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $ref_op:expr, $owned_op:expr) => {
    shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $ref_op, $owned_op, u8, u16, u32, u64, usize);
    shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $ref_op, $owned_op, i8, i16, i32, i64, isize);
};
}

shift_impl!(Shl, shl, ShlAssign, shl_assign, inner_shl, inner_shl_owned);
shift_impl!(Shr, shr, ShrAssign, shr_assign, inner_shr, inner_shr_owned);
ops_impl!(Add, add, AddAssign, add_assign, +, +=);
ops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
ops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
ops_impl!(Div, div, DivAssign, div_assign, /, /=);
ops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);

fn inner_shl(lhs: &Bn, rhs: u32) -> Bn {
    inner_shl_owned(lhs.clone(), rhs)
}

fn inner_shl_owned(mut lhs: Bn, rhs: u32) -> Bn {
    if lhs.is_zero() {
        return lhs;
    }
    let new_precision = precision_for_bits(lhs.value.bits() + rhs);
    lhs.value = lhs.value.resize(new_precision);
    lhs.value.shl_assign(rhs);
    lhs
}

/// Idea borrowed from [num-bigint](https://github.com/rust-num/num-bigint/blob/master/src/bigint/shift.rs#L100)
/// Negative values need a rounding adjustment if there are any ones in the
/// bits that get shifted out.
fn shr_round_down(n: &Bn, shift: u32) -> bool {
    if n.sign.is_negative() {
        let zeros = n.value.trailing_zeros();
        shift > 0 && zeros < shift
    } else {
        false
    }
}

fn inner_shr(lhs: &Bn, rhs: u32) -> Bn {
    inner_shr_owned(lhs.clone(), rhs)
}

fn inner_shr_owned(mut lhs: Bn, rhs: u32) -> Bn {
    let round_down = shr_round_down(&lhs, rhs);
    lhs.value.shr_assign(rhs);
    if round_down {
        lhs.value += 1u8;
    }
    lhs.value = minimize(lhs.value);
    if bool::from(lhs.value.is_zero()) {
        Bn::zero()
    } else {
        lhs
    }
}

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let lhs = self.value.as_words();
        let rhs = other.value.as_words();
        let mut difference: Word = 0;
        for index in 0..lhs.len().max(rhs.len()) {
            let lhs_word = lhs.get(index).copied().unwrap_or(0);
            let rhs_word = rhs.get(index).copied().unwrap_or(0);
            difference |= lhs_word ^ rhs_word;
        }
        self.sign.ct_eq(&other.sign) & difference.ct_eq(&0)
    }
}

impl Serialize for Bn {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = self.to_bytes();
        if bytes.is_empty() {
            bytes.push(0);
        }
        if s.is_human_readable() {
            encode_signed_hex(self.sign.is_negative(), &bytes).serialize(s)
        } else {
            let is_neg = self.sign.is_negative();
            bytes.insert(0, if is_neg { 1u8 } else { 0u8 });
            s.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for Bn {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            struct BnStrVisitor;

            impl<'de> Visitor<'de> for BnStrVisitor {
                type Value = Bn;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a hex encoded string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    let (is_neg, bytes) = decode_signed_hex(s).ok_or_else(|| {
                        de::Error::invalid_value(de::Unexpected::Str(s), &"valid hex")
                    })?;
                    let bn = if bytes.is_empty() {
                        Bn::zero()
                    } else {
                        Bn::from_slice(&bytes)
                    };
                    if bn.is_zero() {
                        Ok(Bn::zero())
                    } else if is_neg {
                        Ok(-bn)
                    } else {
                        Ok(bn)
                    }
                }
            }

            d.deserialize_str(BnStrVisitor)
        } else {
            struct BnBytesVisitor;

            impl<'de> Visitor<'de> for BnBytesVisitor {
                type Value = Bn;

                fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                    write!(f, "a bytestring")
                }

                fn visit_bytes<E>(self, s: &[u8]) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if s.is_empty() {
                        return Err(de::Error::invalid_length(0, &self));
                    }
                    let is_neg = s[0] == 1;
                    let bn = if s.len() == 1 {
                        Bn::zero()
                    } else {
                        Bn::from_slice(&s[1..])
                    };
                    if bn.is_zero() {
                        Ok(Bn::zero())
                    } else if is_neg {
                        Ok(-bn)
                    } else {
                        Ok(bn)
                    }
                }
            }

            d.deserialize_bytes(BnBytesVisitor)
        }
    }
}

impl Zeroize for Bn {
    fn zeroize(&mut self) {
        self.sign = Sign::None;
        self.value.zeroize();
    }
}

impl Sum for Bn {
    fn sum<I: Iterator<Item = Bn>>(iter: I) -> Self {
        let mut b = Bn::zero();
        for i in iter {
            b += i;
        }
        b
    }
}

impl Product for Bn {
    fn product<I: Iterator<Item = Bn>>(iter: I) -> Self {
        let mut b = Bn::one();
        for i in iter {
            b *= i;
        }
        b
    }
}

/// Get a default OS-level cryptographic RNG
fn default_rng() -> crate::Result<rand::rngs::StdRng> {
    use rand::SeedableRng;

    Ok(rand::rngs::StdRng::try_from_rng(&mut rand::rngs::SysRng)?)
}

impl Bn {
    fn from_positive(value: BoxedUint) -> Self {
        if bool::from(value.is_zero()) {
            Self::zero()
        } else {
            Self {
                sign: Sign::Plus,
                value: minimize(value),
            }
        }
    }

    fn from_residue(value: BoxedUint) -> Self {
        if bool::from(value.is_zero()) {
            Self {
                sign: Sign::None,
                value,
            }
        } else {
            Self {
                sign: Sign::Plus,
                value,
            }
        }
    }

    fn modulus(n: &Self) -> Option<&NonZero<BoxedUint>> {
        n.value.as_nz_vartime()
    }

    fn residue(&self, modulus: &NonZero<BoxedUint>) -> BoxedUint {
        Self::reduce_residue(self.sign, self.value.clone(), modulus)
    }

    fn take_residue(&mut self, modulus: &NonZero<BoxedUint>) -> BoxedUint {
        let sign = mem::replace(&mut self.sign, Sign::None);
        let value = mem::replace(&mut self.value, BoxedUint::zero());
        Self::reduce_residue(sign, value, modulus)
    }

    fn reduce_residue(sign: Sign, value: BoxedUint, modulus: &NonZero<BoxedUint>) -> BoxedUint {
        let modulus_value = modulus.as_ref();
        let precision = modulus_value.bits_precision();
        let remainder = match cmp_magnitude(&value, modulus_value) {
            Ordering::Less => value.resize(precision),
            Ordering::Equal => BoxedUint::zero().resize(precision),
            Ordering::Greater => value.rem_vartime(modulus),
        };

        if sign.is_negative() && !bool::from(remainder.is_zero()) {
            sub_magnitudes_fixed(modulus_value, &remainder)
        } else {
            remainder
        }
    }

    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };

        if modulus.as_ref().bits() == 1 {
            return Self::zero();
        }

        let mut base = self.residue(modulus);
        if exponent.sign.is_negative() {
            let inverse = base.invert_mod(modulus);
            if bool::from(inverse.is_none()) {
                return Self::zero();
            }
            let Some(inverse) = Option::from(inverse) else {
                return Self::zero();
            };
            base = inverse;
        }

        if exponent.is_zero() {
            return Self::from_residue(BoxedUint::one().resize(modulus.as_ref().bits_precision()));
        }

        let value = if bool::from(modulus.as_ref().is_odd()) {
            let Some(odd_modulus) = Option::from(Odd::new(modulus.as_ref().clone())) else {
                return Self::zero();
            };
            let params = BoxedMontyParams::new_vartime(odd_modulus);
            BoxedMontyForm::new(base, &params)
                .pow(&exponent.value)
                .retrieve()
        } else {
            let mut result = BoxedUint::one().resize(modulus.as_ref().bits_precision());
            let exponent_bits = exponent.value.bits_vartime();
            for bit in 0..exponent_bits {
                if exponent.value.bit_vartime(bit) {
                    result = result.mul_mod(&base, modulus);
                }
                if bit + 1 < exponent_bits {
                    base = base.square_mod(modulus);
                }
            }
            result
        };

        Self::from_residue(value)
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        let lhs = self.residue(modulus);
        let rhs = rhs.residue(modulus);
        Self::from_residue(lhs.add_mod(&rhs, modulus))
    }

    pub(crate) fn modadd_assign(&mut self, rhs: &Self, n: &Self) {
        let Some(modulus) = Self::modulus(n) else {
            *self = Self::zero();
            return;
        };
        let lhs = self.take_residue(modulus);
        let rhs = rhs.residue(modulus);
        *self = Self::from_residue(lhs.add_mod(&rhs, modulus));
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        let lhs = self.residue(modulus);
        let rhs = rhs.residue(modulus);
        Self::from_residue(lhs.sub_mod(&rhs, modulus))
    }

    pub(crate) fn modsub_assign(&mut self, rhs: &Self, n: &Self) {
        let Some(modulus) = Self::modulus(n) else {
            *self = Self::zero();
            return;
        };
        let lhs = self.take_residue(modulus);
        let rhs = rhs.residue(modulus);
        *self = Self::from_residue(lhs.sub_mod(&rhs, modulus));
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        let lhs = self.residue(modulus);
        let rhs = rhs.residue(modulus);
        Self::from_residue(lhs.mul_mod(&rhs, modulus))
    }

    pub(crate) fn modmul_assign(&mut self, rhs: &Self, n: &Self) {
        let Some(modulus) = Self::modulus(n) else {
            *self = Self::zero();
            return;
        };
        let lhs = self.take_residue(modulus);
        let rhs = rhs.residue(modulus);
        *self = Self::from_residue(lhs.mul_mod(&rhs, modulus));
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        let inverse = rhs.residue(modulus).invert_mod(modulus);
        if bool::from(inverse.is_none()) {
            return Self::zero();
        }
        let lhs = self.residue(modulus);
        let Some(inverse) = Option::from(inverse) else {
            return Self::zero();
        };
        Self::from_residue(lhs.mul_mod(&inverse, modulus))
    }

    pub(crate) fn moddiv_assign(&mut self, rhs: &Self, n: &Self) {
        let Some(modulus) = Self::modulus(n) else {
            *self = Self::zero();
            return;
        };
        let inverse = rhs.residue(modulus).invert_mod(modulus);
        if bool::from(inverse.is_none()) {
            *self = Self::zero();
            return;
        }
        let lhs = self.take_residue(modulus);
        let Some(inverse) = Option::from(inverse) else {
            *self = Self::zero();
            return;
        };
        *self = Self::from_residue(lhs.mul_mod(&inverse, modulus));
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        let value = self.residue(modulus);
        if bool::from(value.is_zero()) {
            Self::from_residue(value)
        } else {
            Self::from_residue(sub_magnitudes_fixed(modulus.as_ref(), &value))
        }
    }

    /// Compute self mod n
    pub fn nmod(&self, n: &Self) -> Self {
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        Self::from_residue(self.residue(modulus))
    }

    /// Computes the multiplicative inverse of this element, failing if the element is zero.
    pub fn invert(&self, n: &Self) -> Option<Self> {
        if self.is_zero() || n.is_zero() || n.is_one() {
            return None;
        }
        let modulus = Self::modulus(n)?;
        let result = self.residue(modulus).invert_mod(modulus);
        if bool::from(result.is_some()) {
            Option::from(result).map(Self::from_residue)
        } else {
            None
        }
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.sign.is_zero() || bool::from(self.value.is_zero())
    }

    /// Return whether this value is negative.
    pub fn is_negative(&self) -> bool {
        self.sign.is_negative()
    }

    /// self == 1
    pub fn is_one(&self) -> bool {
        self.sign.is_positive() && self.value.bits() == 1
    }

    /// Return the bit length
    pub fn bit_length(&self) -> usize {
        self.value.bits() as usize
    }

    /// Compute the greatest common divisor
    pub fn gcd(&self, other: &Self) -> Self {
        Self::from_positive(self.value.gcd_vartime(&other.value))
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() && other.is_zero() {
            Self::zero()
        } else {
            let value = self / self.gcd(other) * other;
            if value.sign.is_negative() {
                -value
            } else {
                value
            }
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
    pub fn from_rng(n: &Self, rng: &mut impl CryptoRng) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let Some(modulus) = Self::modulus(n) else {
            return Self::zero();
        };
        Self::from_positive(BoxedUint::random_mod_vartime(rng, modulus))
    }

    /// Generate a random value between [lower, upper)
    pub fn random_range(lower: &Self, upper: &Self) -> crate::Result<Self> {
        Self::random_range_with_rng(lower, upper, &mut default_rng()?)
    }

    /// Generate a random value between [lower, upper) using the specific random number generator
    pub fn random_range_with_rng(
        lower: &Self,
        upper: &Self,
        rng: &mut impl CryptoRng,
    ) -> crate::Result<Self> {
        if lower >= upper {
            return Err(crate::Error::InvalidRange);
        }
        let range = upper - lower;
        Ok(lower + Self::from_rng(&range, rng))
    }

    /// Generate a random value with `n` bits using the specific random number generator
    pub fn from_rng_bits(n: u32, rng: &mut impl CryptoRng) -> Self {
        if n < 1 {
            return Self::zero();
        }
        let mut m: BoxedUint = RandomBits::random_bits(rng, n);
        // Set the high bit to ensure the number is exactly n bits
        m.set_bit_vartime(n - 1, true);
        Self {
            sign: Sign::Plus,
            value: m,
        }
    }

    /// Hash a byte sequence to a big number
    pub fn from_digest<D>(hasher: D) -> Self
    where
        D: digest::Digest,
    {
        Self::from_slice(hasher.finalize().as_slice())
    }

    /// Convert a byte sequence to a big number
    pub fn from_slice<B>(b: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        let b = b.as_ref();
        let first_nonzero = b.iter().position(|byte| *byte != 0).unwrap_or(b.len());
        let b = &b[first_nonzero..];
        let value = minimize(BoxedUint::from_be_slice_vartime(b));
        if bool::from(value.is_zero()) {
            Self {
                sign: Sign::None,
                value,
            }
        } else {
            Self {
                sign: Sign::Plus,
                value,
            }
        }
    }

    /// Convert this big number to a big-endian byte sequence, the sign is not included
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        if bool::from(self.value.is_zero()) {
            return alloc::vec::Vec::new();
        }
        let mut bytes = self.value.to_be_bytes().into_vec();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        if start > 0 {
            let len = bytes.len();
            bytes.copy_within(start.., 0);
            bytes.truncate(len - start);
        }
        bytes
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
        let len = buffer.len();
        buffer.fill(0);
        for (word_index, word) in self.value.as_words().iter().enumerate() {
            let word_bytes = word.to_le_bytes();
            for (byte_index, byte) in word_bytes.into_iter().enumerate() {
                let from_end = word_index * word_bytes.len() + byte_index;
                if from_end < len {
                    buffer[len - from_end - 1] = byte;
                }
            }
        }
        Ok(())
    }

    /// Compute the extended euclid algorithm and return the Bézout coefficients and GCD
    pub fn extended_gcd(&self, other: &Self) -> GcdResult<Self> {
        let mut self_coefficients = (Self::zero(), Self::one());
        let mut other_coefficients = (Self::one(), Self::zero());
        let mut remainders = (other.clone(), self.clone());

        while !remainders.0.is_zero() {
            let quotient = &remainders.1 / &remainders.0;

            mem::swap(&mut remainders.0, &mut remainders.1);
            remainders.0 -= &quotient * &remainders.1;

            mem::swap(&mut self_coefficients.0, &mut self_coefficients.1);
            self_coefficients.0 -= &quotient * &self_coefficients.1;

            mem::swap(&mut other_coefficients.0, &mut other_coefficients.1);
            other_coefficients.0 -= &quotient * &other_coefficients.1;
        }

        if remainders.1 >= Self::zero() {
            GcdResult {
                gcd: remainders.1,
                x: self_coefficients.1,
                y: other_coefficients.1,
            }
        } else {
            GcdResult {
                gcd: Self::zero() - remainders.1,
                x: Self::zero() - self_coefficients.1,
                y: Self::zero() - other_coefficients.1,
            }
        }
    }

    /// Generate a safe prime with `size` bits
    pub fn safe_prime(size: usize) -> crate::Result<Self> {
        Self::safe_prime_from_rng(size, &mut default_rng()?)
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl CryptoRng) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 3, u32::MAX as usize)?;
        Ok(Self {
            sign: Sign::Plus,
            value: minimize(crypto_primes::random_prime(
                rng,
                crypto_primes::Flavor::Safe,
                size as u32,
            )),
        })
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> crate::Result<Self> {
        Self::prime_from_rng(size, &mut default_rng()?)
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl CryptoRng) -> crate::Result<Self> {
        crate::error::validate_bit_length(size, 2, u32::MAX as usize)?;
        Ok(Self {
            sign: Sign::Plus,
            value: minimize(crypto_primes::random_prime(
                rng,
                crypto_primes::Flavor::Any,
                size as u32,
            )),
        })
    }

    /// True if a prime number
    pub fn is_prime(&self) -> crate::Result<bool> {
        Ok(crypto_primes::is_prime(
            crypto_primes::Flavor::Any,
            &self.value,
        ))
    }

    /// Return zero
    pub fn zero() -> Self {
        Self::default()
    }

    /// Return one
    pub fn one() -> Self {
        Self {
            sign: Sign::Plus,
            value: BoxedUint::one(),
        }
    }

    /// Simultaneous integer division and modulus
    pub fn div_rem(&self, other: &Self) -> (Self, Self) {
        let Some(divisor) = Option::from(NonZero::new(other.value.clone())) else {
            return (Self::zero(), self.clone());
        };
        let (d, r) = self.value.div_rem_vartime(&divisor);
        let d = minimize(d);
        let r = minimize(r);
        let quotient_sign = if bool::from(d.is_zero()) {
            Sign::None
        } else if other.sign == Sign::Minus {
            -self.sign
        } else {
            self.sign
        };
        let rem_sign = if bool::from(r.is_zero()) {
            Sign::None
        } else {
            self.sign
        };
        (
            Self {
                sign: quotient_sign,
                value: d,
            },
            Self {
                sign: rem_sign,
                value: r,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let from_hex = |value| Bn::from_slice(crate::decode_hex(value).unwrap());
        let bn1 = from_hex("684982f082a4b2953bd04e1761dea837fec1a725");
        let bn2 = from_hex("400000000000000000000000000000000001a671");
        let bn3 = from_hex("a84982f082a4b2953bd04e1761dea837fec34d96");
        let bn4 = from_hex("284982f082a4b2953bd04e1761dea837fec000b4");
        let bn5 = from_hex(
            "1a1260bc20a92ca54ef41385d877aa0dffb115e0764b43852914d478c7ad03a73c948eaaad01c555",
        );
        assert_eq!(&bn1 + &bn2, bn3);
        assert_eq!(&bn1 - &bn2, bn4);
        assert_eq!(&bn2 - &bn1, -bn4);
        assert_eq!(&bn1 * &bn2, bn5);
        assert_eq!(&bn1 * -&bn2, -bn5.clone());
        assert_eq!(&-bn1 * -&bn2, bn5);
    }

    #[test]
    fn primes() {
        let p1 = Bn::prime_from_rng(256, &mut default_rng().unwrap()).unwrap();
        assert!(p1.is_prime().unwrap());
    }

    #[test]
    fn bytes() {
        let p1 = Bn::prime_from_rng(256, &mut default_rng().unwrap()).unwrap();
        let bytes = p1.to_bytes();
        let p2 = Bn::from_slice(&bytes);
        assert_eq!(p1, p2);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn dynamic_precision() {
        let wide = Bn::from(u128::MAX);
        assert_eq!(wide.to_bytes(), u128::MAX.to_be_bytes());

        let carry = Bn::from(u64::MAX) + Bn::one();
        assert_eq!(carry, Bn::from(1u128 << 64));

        let product = Bn::from(u64::MAX) * Bn::from(u64::MAX);
        assert_eq!(product, Bn::from((u64::MAX as u128).pow(2)));

        let shifted = Bn::one() << 130usize;
        assert_eq!(shifted.bit_length(), 131);
        assert_eq!(shifted.to_bytes().len(), 17);

        let minimum = Bn::from(i128::MIN);
        assert_eq!(minimum, -Bn::from(1u128 << 127));

        let modulus = (Bn::one() << 127usize) + Bn::one();
        let fixed_width = Bn::from(5u8).nmod(&modulus);
        assert_eq!(fixed_width, Bn::from(5u8));
        assert_eq!(&fixed_width + Bn::one(), Bn::from(6u8));
        assert_eq!(&fixed_width - Bn::one(), Bn::from(4u8));

        let mut bytes = [0u8; 1];
        Bn::one().copy_bytes_into_buffer(&mut bytes).unwrap();
        assert_eq!(bytes, [1]);
    }

    #[test]
    fn modular_arithmetic_with_signed_values_and_even_modulus() {
        let n = Bn::from(5);
        assert_eq!(Bn::from(3), Bn::from(-3).modadd(&Bn::from(-4), &n));
        assert_eq!(Bn::from(3), Bn::from(-3).modmul(&Bn::from(4), &n));
        assert_eq!(Bn::from(3), Bn::from(-3).modneg(&n));
        assert_eq!(Bn::from(2), Bn::from(-3).nmod(&-n));
        assert_eq!(Bn::from(-1), Bn::from(-6) % Bn::from(5));

        let even_modulus = Bn::from(6);
        assert_eq!(
            Bn::from(4),
            Bn::from(-2).modpow(&Bn::from(3), &even_modulus)
        );
        assert_eq!(Bn::from(7), Bn::from(-3).invert(&Bn::from(11)).unwrap());
    }
}
