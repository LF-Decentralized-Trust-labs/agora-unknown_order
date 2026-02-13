/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::*;
use core::hash::Hasher;
use core::{
    cmp::{self, Ordering},
    fmt::{self, Binary, Debug, Display, Formatter, LowerHex, Octal, UpperHex},
    hash::Hash,
    iter::{Product, Sum},
    mem,
    ops::{
        Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
        ShrAssign, Sub, SubAssign,
    },
    str::FromStr,
};
use crypto_bigint::rand_core::CryptoRng;
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    rand_core, BoxedUint, CheckedAdd, CheckedSub, Integer, NonZero, Odd, RandomBits, RandomMod,
    Resize,
};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Sign {
    Minus,
    None,
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

/// Normalize two BoxedUint values to the same precision
fn normalize(a: &BoxedUint, b: &BoxedUint) -> (BoxedUint, BoxedUint) {
    let prec = a.bits_precision().max(b.bits_precision()).max(64);
    (a.clone().resize(prec), b.clone().resize(prec))
}

/// Normalize three BoxedUint values to the same precision
fn normalize3(a: &BoxedUint, b: &BoxedUint, c: &BoxedUint) -> (BoxedUint, BoxedUint, BoxedUint) {
    let prec = a
        .bits_precision()
        .max(b.bits_precision())
        .max(c.bits_precision())
        .max(64);
    (
        a.clone().resize(prec),
        b.clone().resize(prec),
        c.clone().resize(prec),
    )
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
        let bytes = self.value.to_be_bytes();
        let lz = self.value.leading_zeros() / 8;
        let start = lz as usize;
        let slice = if start < bytes.len() {
            &bytes[start..]
        } else {
            // All zeros or empty
            &[0u8][..]
        };
        let repr = multibase::encode(multibase::Base::Base10, slice);
        // The leading digit will be a '9' to indicate the encoding so drop it
        write!(f, "{}{}", self.sign, &repr[1..])
    }
}

impl Debug for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:?}", self.sign, self.value)
    }
}

impl Binary for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.iter() {
            write!(f, "{:b}", b)?;
        }
        Ok(())
    }
}

impl Octal for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.iter() {
            write!(f, "{:o}", b)?;
        }
        Ok(())
    }
}

impl LowerHex for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.iter() {
            write!(f, "{:x}", b)?;
        }
        Ok(())
    }
}

impl UpperHex for Bn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sign)?;
        let bytes = self.value.to_be_bytes();
        for b in bytes.iter() {
            write!(f, "{:X}", b)?;
        }
        Ok(())
    }
}

impl Eq for Bn {}

impl PartialEq for Bn {
    fn eq(&self, other: &Self) -> bool {
        if self.sign != other.sign {
            return false;
        }
        let (lv, rv) = normalize(&self.value, &other.value);
        lv == rv
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

        let (lv, rv) = normalize(&self.value, &other.value);
        match self.sign {
            Sign::None => Ordering::Equal,
            Sign::Plus => lv.cmp(&rv),
            Sign::Minus => rv.cmp(&lv),
        }
    }
}

impl Hash for Bn {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.sign.hash(state);
        self.value.to_be_bytes().hash(state);
    }
}

macro_rules! from_uint_impl {
    ($($type:tt),+$(,)*) => {
        $(
            impl From<$type> for Bn {
                fn from(value: $type) -> Self {
                    Self {
                        sign: if value != 0 { Sign::Plus } else { Sign::None },
                        value: BoxedUint::from(value as u64)
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
                            Ordering::Greater => (Sign::Minus, (-value) as $utype),
                            Ordering::Equal => (Sign::None, 0 as $utype),
                            Ordering::Less => (Sign::Plus, value as $utype),
                    };
                    Self {
                        sign,
                        value: BoxedUint::from(value as u64)
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
                *self = &*self $opr &Self::from(rhs);
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
            value: BoxedUint::from(value as u64),
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
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => {
                let (lv, rv) = normalize(&self.value, &rhs.value);
                Bn {
                    sign: self.sign,
                    value: Option::from(lv.checked_add(&rv)).expect("overflow"),
                }
            }
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                let (lv, rv) = normalize(&self.value, &rhs.value);
                match lv.cmp(&rv) {
                    Ordering::Less => Bn {
                        sign: rhs.sign,
                        value: Option::from(rv.checked_sub(&lv)).unwrap(),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: Option::from(lv.checked_sub(&rv)).unwrap(),
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
        self + &rhs
    }
}

impl Add<&Bn> for Bn {
    type Output = Self;

    fn add(self, rhs: &Bn) -> Self::Output {
        &self + rhs
    }
}

impl Add for Bn {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
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
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                let (lv, rv) = normalize(&self.value, &rhs.value);
                Bn {
                    sign: self.sign,
                    value: Option::from(lv.checked_add(&rv)).unwrap(),
                }
            }
            (Sign::Plus, Sign::Plus) | (Sign::Minus, Sign::Minus) => {
                let (lv, rv) = normalize(&self.value, &rhs.value);
                match lv.cmp(&rv) {
                    Ordering::Less => Bn {
                        sign: -self.sign,
                        value: Option::from(rv.checked_sub(&lv)).unwrap(),
                    },
                    Ordering::Greater => Bn {
                        sign: self.sign,
                        value: Option::from(lv.checked_sub(&rv)).unwrap(),
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
        self - &rhs
    }
}

impl Sub<&Bn> for Bn {
    type Output = Self;

    fn sub(self, rhs: &Bn) -> Self::Output {
        &self - rhs
    }
}

impl Sub for Bn {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
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
        // Use enough precision for the product
        let prec = (self.value.bits_precision() + rhs.value.bits_precision()).max(64);
        let lv = self.value.clone().resize(prec);
        let rv = rhs.value.clone().resize(prec);
        Bn {
            sign,
            value: lv.checked_mul(&rv).expect("overflow"),
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
(@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr, $($rhs:ty),+) => {$(
    #[allow(clippy::unnecessary_cast)]
    impl<'a> $ops<$rhs> for &'a Bn {
        type Output = Bn;

        fn $func(self, rhs: $rhs) -> Self::Output {
            $opr(self, rhs as u32)
        }
    }

    #[allow(clippy::unnecessary_cast)]
    impl $ops<$rhs> for Bn {
        type Output = Self;

        fn $func(self, rhs: $rhs) -> Self::Output {
            $opr(&self, rhs as u32)
        }
    }

    #[allow(clippy::unnecessary_cast)]
    impl $ops_assign<$rhs> for Bn {
        fn $func_assign(&mut self, rhs: $rhs) {
            *self = $opr(self, rhs as u32);
        }
    }
)*};
($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr) => {
    shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, u8, u16, u32, u64, usize);
    shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, i8, i16, i32, i64, isize);
};
}

shift_impl!(Shl, shl, ShlAssign, shl_assign, inner_shl);
shift_impl!(Shr, shr, ShrAssign, shr_assign, inner_shr);
ops_impl!(Add, add, AddAssign, add_assign, +, +=);
ops_impl!(Sub, sub, SubAssign, sub_assign, -, -=);
ops_impl!(Mul, mul, MulAssign, mul_assign, *, *=);
ops_impl!(Div, div, DivAssign, div_assign, /, /=);
ops_impl!(Rem, rem, RemAssign, rem_assign, %, %=);

fn inner_shl(lhs: &Bn, rhs: u32) -> Bn {
    // Grow precision to accommodate the shift
    let new_prec = (lhs.value.bits_precision() + rhs)
        .next_multiple_of(64)
        .max(64);
    let v = lhs.value.clone().resize(new_prec).shl(rhs);
    if bool::from(v.is_zero()) {
        Bn::zero()
    } else {
        Bn {
            sign: lhs.sign,
            value: v,
        }
    }
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
    let round_down = shr_round_down(lhs, rhs);
    let value = lhs.value.clone().shr(rhs);
    let value = if round_down {
        let one = BoxedUint::one().resize(value.bits_precision().max(64));
        let val = value.resize(one.bits_precision());
        Option::from(val.checked_add(&one)).unwrap()
    } else {
        value
    };
    if bool::from(value.is_zero()) {
        Bn::zero()
    } else {
        Bn {
            sign: lhs.sign,
            value,
        }
    }
}

impl ConstantTimeEq for Bn {
    fn ct_eq(&self, other: &Self) -> Choice {
        let (lv, rv) = normalize(&self.value, &other.value);
        self.sign.ct_eq(&other.sign) & lv.ct_eq(&rv)
    }
}

impl Serialize for Bn {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        if s.is_human_readable() {
            alloc::format!("{}{}", self.sign, hex::encode(&bytes)).serialize(s)
        } else {
            (self.sign, bytes).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Bn {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if d.is_human_readable() {
            let s = alloc::string::String::deserialize(d)?;
            if let Some(stripped) = s.strip_prefix('-') {
                let bytes = hex::decode(stripped).map_err(|e| {
                    de::Error::invalid_value(
                        de::Unexpected::Str(&s),
                        &alloc::format!("valid hex: {}", e).as_str(),
                    )
                })?;
                if bytes.is_empty() {
                    Ok(Self::zero())
                } else {
                    let mut bn = Self::from_slice(&bytes);
                    bn.sign = Sign::Minus;
                    Ok(bn)
                }
            } else {
                let bytes = hex::decode(&s).map_err(|e| {
                    de::Error::invalid_value(
                        de::Unexpected::Str(&s),
                        &alloc::format!("valid hex: {}", e).as_str(),
                    )
                })?;
                let bn = Self::from_slice(&bytes);
                if bn.is_zero() {
                    Ok(Self::zero())
                } else {
                    Ok(bn)
                }
            }
        } else {
            let (sign, value): (Sign, alloc::vec::Vec<u8>) = Deserialize::deserialize(d)?;
            let mut bn = Self::from_slice(value);
            bn.sign = sign;
            Ok(bn)
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
fn default_rng() -> rand_core::UnwrapErr<rand::rngs::SysRng> {
    rand_core::UnwrapErr(rand::rngs::SysRng)
}

impl Bn {
    /// Returns `(self ^ exponent) mod n`
    /// Note that this rounds down
    /// which makes a difference when given a negative `self` or `n`.
    /// The result will be in the interval `[0, n)` for `n > 0`
    pub fn modpow(&self, exponent: &Self, n: &Self) -> Self {
        assert!(!bool::from(n.value.is_zero()));
        let prec = self
            .value
            .bits_precision()
            .max(exponent.value.bits_precision())
            .max(n.value.bits_precision())
            .max(64);
        let nv = n.value.clone().resize(prec);
        let odd_n =
            Option::from(Odd::new(nv.clone())).expect("modulus must be odd for Montgomery form");
        let params = BoxedMontyParams::new_vartime(odd_n);
        let mm = match exponent.sign {
            Sign::None => return Self::one(),
            Sign::Minus => match self.invert(n) {
                None => return Self::zero(),
                Some(a) => BoxedMontyForm::new(a.value.resize(prec), &params),
            },
            Sign::Plus => BoxedMontyForm::new(self.value.clone().resize(prec), &params),
        };

        let exp_value = exponent.value.clone().resize(prec);
        let value = mm.pow(&exp_value).retrieve();

        let odd: bool = exponent.value.is_odd().into();

        let (sign, value) = match (self.sign.is_negative() && odd, n.sign.is_negative()) {
            (true, false) => {
                let v = Option::from(nv.checked_sub(&value)).unwrap();
                (Sign::Plus, v)
            }
            (_, _) => (Sign::Plus, value),
        };
        Self {
            sign: if bool::from(value.is_zero()) {
                Sign::None
            } else {
                sign
            },
            value,
        }
    }

    /// Compute (self + rhs) mod n
    pub fn modadd(&self, rhs: &Self, n: &Self) -> Self {
        let (sv, rv, nv) = normalize3(&self.value, &rhs.value, &n.value);
        let nz_nv = Option::from(NonZero::new(nv.clone())).expect("modulus is zero");
        match (self.sign, rhs.sign) {
            (_, Sign::None) => {
                let zero = BoxedUint::zero().resize(nv.bits_precision());
                let mut bn = Self {
                    sign: self.sign,
                    value: sv.add_mod(&zero, &nz_nv),
                };
                if bn.sign.is_negative() {
                    let (bv, nv2) = normalize(&bn.value, &nv);
                    bn.value = Option::from(bv.checked_add(&nv2)).unwrap();
                    -bn
                } else {
                    bn
                }
            }
            (Sign::None, _) => {
                let zero = BoxedUint::zero().resize(nv.bits_precision());
                let mut bn = Self {
                    sign: rhs.sign,
                    value: rv.add_mod(&zero, &nz_nv),
                };
                if bn.sign.is_negative() {
                    let (bv, nv2) = normalize(&bn.value, &nv);
                    bn.value = Option::from(bv.checked_add(&nv2)).unwrap();
                    -bn
                } else {
                    bn
                }
            }
            (Sign::Plus, Sign::Plus) => Self {
                sign: self.sign,
                value: sv.add_mod(&rv, &nz_nv),
            },
            (Sign::Minus, Sign::Minus) => {
                let value = sv.add_mod(&rv, &nz_nv);
                let (v, n2) = normalize(&value, &nv);
                Self {
                    sign: Sign::Plus,
                    value: Option::from(v.checked_add(&n2)).unwrap(),
                }
            }
            (Sign::Plus, Sign::Minus) | (Sign::Minus, Sign::Plus) => {
                let mut bn = match sv.cmp(&rv) {
                    Ordering::Less => Self {
                        sign: rhs.sign,
                        value: rv.sub_mod(&sv, &nz_nv),
                    },
                    Ordering::Greater => Self {
                        sign: self.sign,
                        value: sv.sub_mod(&rv, &nz_nv),
                    },
                    Ordering::Equal => Self::zero(),
                };
                if bn.sign.is_negative() {
                    let (bv, nv2) = normalize(&bn.value, &nv);
                    bn.value = Option::from(bv.checked_add(&nv2)).unwrap();
                    -bn
                } else {
                    bn
                }
            }
        }
    }

    /// Compute (self - rhs) mod n
    pub fn modsub(&self, rhs: &Self, n: &Self) -> Self {
        self.modadd(&-rhs, n)
    }

    /// Compute (self * rhs) mod n
    pub fn modmul(&self, rhs: &Self, n: &Self) -> Self {
        let prec = self
            .value
            .bits_precision()
            .max(rhs.value.bits_precision())
            .max(n.value.bits_precision())
            .max(64);
        let nv = n.value.clone().resize(prec);
        let odd_n =
            Option::from(Odd::new(nv.clone())).expect("modulus must be odd for Montgomery form");
        let params = BoxedMontyParams::new_vartime(odd_n);
        let l = BoxedMontyForm::new(self.value.clone().resize(prec), &params);
        let r = BoxedMontyForm::new(rhs.value.clone().resize(prec), &params);

        let result = (l * r).retrieve();
        let sign = if bool::from(result.is_zero()) {
            Sign::None
        } else {
            self.sign * rhs.sign
        };

        match sign {
            Sign::None => Self::zero(),
            Sign::Plus => Self {
                sign,
                value: result,
            },
            Sign::Minus => {
                let (r, n2) = normalize(&result, &nv);
                Self {
                    sign: Sign::Plus,
                    value: Option::from(r.checked_add(&n2)).unwrap(),
                }
            }
        }
    }

    /// Compute (self * 1/rhs) mod n
    pub fn moddiv(&self, rhs: &Self, n: &Self) -> Self {
        let prec = rhs
            .value
            .bits_precision()
            .max(n.value.bits_precision())
            .max(64);
        let nv = n.value.clone().resize(prec);
        let odd_n = Option::from(Odd::new(nv)).expect("modulus must be odd for Montgomery form");
        let params = BoxedMontyParams::new_vartime(odd_n);
        let r = BoxedMontyForm::new(rhs.value.clone().resize(prec), &params);

        let inv = r.invert();

        if inv.is_none().into() {
            return Self::zero();
        }
        let rhs = Self {
            sign: rhs.sign,
            value: inv.unwrap().retrieve(),
        };
        self.modmul(&rhs, n)
    }

    /// Compute -self mod n
    pub fn modneg(&self, n: &Self) -> Self {
        let prec = self
            .value
            .bits_precision()
            .max(n.value.bits_precision())
            .max(64);
        let nv = n.value.clone().resize(prec);
        let odd_n = Option::from(Odd::new(nv)).expect("modulus must be odd for Montgomery form");
        let params = BoxedMontyParams::new_vartime(odd_n);
        let r = BoxedMontyForm::new(self.value.clone().resize(prec), &params);
        let value = (-r).retrieve();

        if self.sign.is_zero() || bool::from(value.is_zero()) {
            Self::zero()
        } else {
            Self {
                sign: -self.sign,
                value,
            }
        }
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
        if self.is_zero() || n.is_zero() || n.is_one() {
            return None;
        }
        let (sv, nv) = normalize(&self.value, &n.value);
        let nz_n = Option::from(NonZero::new(nv)).expect("modulus is zero");
        let result = sv.invert_mod(&nz_n);
        if result.is_some().into() {
            Some(Self {
                sign: self.sign,
                value: result.unwrap(),
            })
        } else {
            None
        }
    }

    /// self == 0
    pub fn is_zero(&self) -> bool {
        self.sign.is_zero() || bool::from(self.value.is_zero())
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
        // borrowed from num-bigint/src/biguint.rs

        // Stein's algorithm
        if self.is_zero() {
            return other.clone();
        }
        if other.is_zero() {
            return self.clone();
        }
        let mut m = self.clone();
        let mut n = other.clone();

        // find common factors of 2
        let shift = cmp::min(n.value.trailing_zeros(), m.value.trailing_zeros());

        // divide m and n by 2 until odd
        // m inside loop
        n >>= n.value.trailing_zeros() as usize;

        while !m.is_zero() {
            m >>= m.value.trailing_zeros() as usize;
            if n > m {
                mem::swap(&mut n, &mut m)
            }
            m -= &n;
        }

        n << shift as usize
    }

    /// Compute the least common multiple
    pub fn lcm(&self, other: &Self) -> Self {
        if self.is_zero() && other.is_zero() {
            Self::zero()
        } else {
            self / self.gcd(other) * other
        }
    }

    /// Generate a random value less than `n`
    pub fn random(n: &Self) -> Self {
        Self::from_rng(n, &mut default_rng())
    }

    /// Generate a random value with `n` bits
    pub fn random_bits(n: u32) -> Self {
        Self::from_rng_bits(n, &mut default_rng())
    }

    /// Generate a random value less than `n` using the specific random number generator
    pub fn from_rng(n: &Self, rng: &mut impl CryptoRng) -> Self {
        if n.is_zero() {
            return Self::zero();
        }
        let nz_n = Option::from(NonZero::new(n.value.clone())).expect("divisor is zero");
        Self {
            sign: Sign::Plus,
            value: BoxedUint::random_mod_vartime(rng, &nz_n),
        }
    }

    /// Generate a random value between [lower, upper)
    pub fn random_range(lower: &Self, upper: &Self) -> Self {
        Self::random_range_with_rng(lower, upper, &mut default_rng())
    }

    /// Generate a random value between [lower, upper) using the specific random number generator
    pub fn random_range_with_rng(lower: &Self, upper: &Self, rng: &mut impl CryptoRng) -> Self {
        if lower >= upper {
            panic!("lower bound is greater than or equal to upper bound");
        }
        let range = upper - lower;
        lower + Self::from_rng(&range, rng)
    }

    /// Generate a random value with `n` bits using the specific random number generator
    pub fn from_rng_bits(n: u32, rng: &mut impl CryptoRng) -> Self {
        if n < 1 {
            return Self::zero();
        }
        let mut m: BoxedUint = RandomBits::try_random_bits(rng, n).expect("random bits failed");
        // Set the high bit to ensure the number is exactly n bits
        let prec = m.bits_precision();
        let high_bit = BoxedUint::one().resize(prec).shl(n - 1);
        m = m.bitor(&high_bit);
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
        let bits_precision = ((b.len() * 8) as u32).next_multiple_of(64).max(64);
        let pad_len = (bits_precision / 8) as usize;
        let mut padded = alloc::vec![0u8; pad_len];
        if !b.is_empty() {
            let start = pad_len - b.len();
            padded[start..].copy_from_slice(b);
        }
        let value = BoxedUint::from_be_slice(&padded, bits_precision).expect("invalid byte length");
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
        let bytes = self.value.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        bytes[start..].to_vec()
    }

    /// Convert this big number to a big-endian byte sequence and store it in `buffer`.
    /// The sign is not included
    pub fn copy_bytes_into_buffer(&self, buffer: &mut [u8]) {
        let bytes = self.value.to_be_bytes();
        buffer.copy_from_slice(&bytes)
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
                mem::swap(&mut r.0, &mut r.1);
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
        Self::safe_prime_from_rng(size, &mut default_rng())
    }

    /// Generate a safe prime with `size` bits with a user-provided rng
    pub fn safe_prime_from_rng(size: usize, rng: &mut impl CryptoRng) -> Self {
        Self {
            sign: Sign::Plus,
            value: crypto_primes::random_prime(rng, crypto_primes::Flavor::Safe, size as u32),
        }
    }

    /// Generate a prime with `size` bits
    pub fn prime(size: usize) -> Self {
        Self::prime_from_rng(size, &mut default_rng())
    }

    /// Generate a prime with `size` bits with a user-provided rng
    pub fn prime_from_rng(size: usize, rng: &mut impl CryptoRng) -> Self {
        Self {
            sign: Sign::Plus,
            value: crypto_primes::random_prime(rng, crypto_primes::Flavor::Any, size as u32),
        }
    }

    /// True if a prime number
    pub fn is_prime(&self) -> bool {
        crypto_primes::is_prime(crypto_primes::Flavor::Any, &self.value)
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
        let (sv, ov) = normalize(&self.value, &other.value);
        let nz = Option::from(NonZero::new(ov)).expect("divisor is zero");
        let (d, r) = sv.div_rem(&nz);
        let rem_sign = if bool::from(r.is_zero()) {
            Sign::None
        } else {
            Sign::Plus
        };
        if other.sign == Sign::Minus {
            (
                Self {
                    sign: -self.sign,
                    value: d,
                },
                Self {
                    sign: rem_sign,
                    value: r,
                },
            )
        } else {
            (
                Self {
                    sign: self.sign,
                    value: d,
                },
                Self {
                    sign: rem_sign,
                    value: r,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ops() {
        let (_, v1) =
            multibase::decode("9595374401003766034096130243798882341754528442149").unwrap();
        let (_, v2) =
            multibase::decode("9365375409332725729550921208179070754913983243889").unwrap();
        let (_, v3) =
            multibase::decode("9960749810336491763647051451977953096668511686038").unwrap();
        let (_, v4) =
            multibase::decode("9229998991671040304545209035619811586840545198260").unwrap();
        let (_, v5) = multibase::decode("9217535165472977407178102302905245480306183692659917226463581384024497196271511427656856694277461").unwrap();
        let bn1 = Bn::from_slice(v1.as_slice());
        let bn2 = Bn::from_slice(v2.as_slice());
        let bn3 = Bn::from_slice(v3.as_slice());
        let bn4 = Bn::from_slice(v4.as_slice());
        let bn5 = Bn::from_slice(v5.as_slice());
        assert_eq!(&bn1 + &bn2, bn3);
        assert_eq!(&bn1 - &bn2, bn4);
        assert_eq!(&bn2 - &bn1, -bn4);
        assert_eq!(&bn1 * &bn2, bn5);
        assert_eq!(&bn1 * -&bn2, -bn5.clone());
        assert_eq!(&-bn1 * -&bn2, bn5);
    }

    #[test]
    fn primes() {
        let p1 = Bn::prime_from_rng(256, &mut default_rng());
        assert!(p1.is_prime());
    }

    #[test]
    fn bytes() {
        let p1 = Bn::prime_from_rng(256, &mut default_rng());
        let bytes = p1.to_bytes();
        let p2 = Bn::from_slice(&bytes);
        assert_eq!(p1, p2);
    }
}
