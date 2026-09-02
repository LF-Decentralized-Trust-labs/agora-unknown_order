/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use core::{
    borrow::Borrow,
    fmt::{self, Debug, Display, Formatter},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

/// Arithmetic required by [`Group`] and [`GroupValue`].
pub trait GroupElement: Sized + PartialEq {
    /// Return zero.
    fn zero() -> Self;

    /// Return one.
    fn one() -> Self;

    /// Return whether this value is zero.
    fn is_zero(&self) -> bool;

    /// Return whether this value is one.
    fn is_one(&self) -> bool;

    /// Return whether this value is negative.
    fn is_negative(&self) -> bool;

    /// Return whether this value is prime.
    fn is_prime(&self) -> crate::Result<bool>;

    /// Compute the multiplicative inverse modulo `modulus`.
    fn invert(&self, modulus: &Self) -> Option<Self>;

    /// Compute `(self ^ exponent) mod modulus`.
    fn modpow(&self, exponent: &Self, modulus: &Self) -> Self;

    /// Compute `(self + rhs) mod modulus`.
    fn modadd(&self, rhs: &Self, modulus: &Self) -> Self;

    /// Replace this value with `(self + rhs) mod modulus`.
    fn modadd_assign(&mut self, rhs: &Self, modulus: &Self) {
        *self = self.modadd(rhs, modulus);
    }

    /// Compute `(self - rhs) mod modulus`.
    fn modsub(&self, rhs: &Self, modulus: &Self) -> Self;

    /// Replace this value with `(self - rhs) mod modulus`.
    fn modsub_assign(&mut self, rhs: &Self, modulus: &Self) {
        *self = self.modsub(rhs, modulus);
    }

    /// Compute `(self * rhs) mod modulus`.
    fn modmul(&self, rhs: &Self, modulus: &Self) -> Self;

    /// Replace this value with `(self * rhs) mod modulus`.
    fn modmul_assign(&mut self, rhs: &Self, modulus: &Self) {
        *self = self.modmul(rhs, modulus);
    }

    /// Compute `(self / rhs) mod modulus`.
    fn moddiv(&self, rhs: &Self, modulus: &Self) -> Self;

    /// Replace this value with `(self / rhs) mod modulus`.
    fn moddiv_assign(&mut self, rhs: &Self, modulus: &Self) {
        *self = self.moddiv(rhs, modulus);
    }

    /// Compute `-self mod modulus`.
    fn modneg(&self, modulus: &Self) -> Self;

    /// Replace this value with `-self mod modulus`.
    fn modneg_assign(&mut self, modulus: &Self) {
        *self = self.modneg(modulus);
    }

    /// Compute `self mod modulus`.
    fn nmod(&self, modulus: &Self) -> Self;
}

#[cfg(any(
    feature = "crypto",
    feature = "gmp",
    feature = "openssl",
    feature = "rust"
))]
macro_rules! group_element_impl {
    ($type:path) => {
        impl GroupElement for $type {
            fn zero() -> Self {
                Self::zero()
            }

            fn one() -> Self {
                Self::one()
            }

            fn is_zero(&self) -> bool {
                Self::is_zero(self)
            }

            fn is_one(&self) -> bool {
                Self::is_one(self)
            }

            fn is_negative(&self) -> bool {
                Self::is_negative(self)
            }

            fn is_prime(&self) -> crate::Result<bool> {
                Self::is_prime(self)
            }

            fn invert(&self, modulus: &Self) -> Option<Self> {
                Self::invert(self, modulus)
            }

            fn modpow(&self, exponent: &Self, modulus: &Self) -> Self {
                Self::modpow(self, exponent, modulus)
            }

            fn modadd(&self, rhs: &Self, modulus: &Self) -> Self {
                Self::modadd(self, rhs, modulus)
            }

            fn modadd_assign(&mut self, rhs: &Self, modulus: &Self) {
                Self::modadd_assign(self, rhs, modulus);
            }

            fn modsub(&self, rhs: &Self, modulus: &Self) -> Self {
                Self::modsub(self, rhs, modulus)
            }

            fn modsub_assign(&mut self, rhs: &Self, modulus: &Self) {
                Self::modsub_assign(self, rhs, modulus);
            }

            fn modmul(&self, rhs: &Self, modulus: &Self) -> Self {
                Self::modmul(self, rhs, modulus)
            }

            fn modmul_assign(&mut self, rhs: &Self, modulus: &Self) {
                Self::modmul_assign(self, rhs, modulus);
            }

            fn moddiv(&self, rhs: &Self, modulus: &Self) -> Self {
                Self::moddiv(self, rhs, modulus)
            }

            fn moddiv_assign(&mut self, rhs: &Self, modulus: &Self) {
                Self::moddiv_assign(self, rhs, modulus);
            }

            fn modneg(&self, modulus: &Self) -> Self {
                Self::modneg(self, modulus)
            }

            fn nmod(&self, modulus: &Self) -> Self {
                Self::nmod(self, modulus)
            }
        }
    };
}

#[cfg(feature = "crypto")]
group_element_impl!(crate::crypto_backend::Bn);
#[cfg(feature = "gmp")]
group_element_impl!(crate::gmp_backend::Bn);
#[cfg(feature = "openssl")]
group_element_impl!(crate::openssl_backend::Bn);
#[cfg(feature = "rust")]
group_element_impl!(crate::rust_backend::Bn);

/// Parameters for arithmetic modulo a positive integer greater than one.
///
/// Use [`Group::element`] to bind reduced values to these parameters. Values bound to a group
/// automatically reduce the result of every arithmetic operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group<T> {
    modulus: T,
    prime: bool,
}

/// A value reduced modulo and bound to a [`Group`].
///
/// Binary operators return [`crate::Result`] because values created by different group parameters
/// cannot be combined and division can fail for a non-invertible divisor.
pub struct GroupValue<'group, T> {
    group: &'group Group<T>,
    value: T,
}

impl<T: Clone> Clone for GroupValue<'_, T> {
    fn clone(&self) -> Self {
        Self {
            group: self.group,
            value: self.value.clone(),
        }
    }
}

impl<T: Debug> Debug for GroupValue<'_, T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupValue")
            .field("value", &self.value)
            .field("modulus", &self.group.modulus)
            .finish()
    }
}

impl<T: Display> Display for GroupValue<'_, T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.value, formatter)
    }
}

impl<T: PartialEq> PartialEq for GroupValue<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.group.modulus == other.group.modulus
    }
}

impl<T: Eq> Eq for GroupValue<'_, T> {}

macro_rules! binops_group {
    ($ops:ident, $func:ident, $opr:ident) => {
        impl<'a, 'b, T: GroupElement> $ops<(&'a T, &'b T)> for &Group<T> {
            type Output = T;

            fn $func(self, pair: (&'a T, &'b T)) -> Self::Output {
                pair.0.$opr(pair.1, &self.modulus)
            }
        }

        impl<'a, T: GroupElement> $ops<(&'a T, T)> for &Group<T> {
            type Output = T;

            fn $func(self, pair: (&'a T, T)) -> Self::Output {
                self.$func((pair.0, &pair.1))
            }
        }

        impl<'b, T: GroupElement> $ops<(T, &'b T)> for &Group<T> {
            type Output = T;

            fn $func(self, pair: (T, &'b T)) -> Self::Output {
                self.$func((&pair.0, pair.1))
            }
        }

        impl<T: GroupElement> $ops<(T, T)> for &Group<T> {
            type Output = T;

            fn $func(self, pair: (T, T)) -> Self::Output {
                self.$func((&pair.0, &pair.1))
            }
        }

        impl<'a, 'b, T: GroupElement> $ops<(&'a T, &'b T)> for Group<T> {
            type Output = T;

            fn $func(self, pair: (&'a T, &'b T)) -> Self::Output {
                (&self).$func(pair)
            }
        }

        impl<'a, T: GroupElement> $ops<(&'a T, T)> for Group<T> {
            type Output = T;

            fn $func(self, pair: (&'a T, T)) -> Self::Output {
                (&self).$func((pair.0, &pair.1))
            }
        }

        impl<'b, T: GroupElement> $ops<(T, &'b T)> for Group<T> {
            type Output = T;

            fn $func(self, pair: (T, &'b T)) -> Self::Output {
                (&self).$func((&pair.0, pair.1))
            }
        }

        impl<T: GroupElement> $ops<(T, T)> for Group<T> {
            type Output = T;

            fn $func(self, pair: (T, T)) -> Self::Output {
                (&self).$func((&pair.0, &pair.1))
            }
        }
    };
}

macro_rules! binops_group_assign {
    ($ops:ident, $func:ident, $opr:ident) => {
        impl<'a, 'b, T: GroupElement> $ops<(&'a mut T, &'b T)> for &Group<T> {
            fn $func(&mut self, pair: (&'a mut T, &'b T)) {
                pair.0.$opr(pair.1, &self.modulus);
            }
        }

        impl<'a, T: GroupElement> $ops<(&'a mut T, T)> for &Group<T> {
            fn $func(&mut self, pair: (&'a mut T, T)) {
                (*self).$func((pair.0, &pair.1));
            }
        }

        impl<'a, 'b, T: GroupElement> $ops<(&'a mut T, &'b T)> for Group<T> {
            fn $func(&mut self, pair: (&'a mut T, &'b T)) {
                pair.0.$opr(pair.1, &self.modulus);
            }
        }

        impl<'a, T: GroupElement> $ops<(&'a mut T, T)> for Group<T> {
            fn $func(&mut self, pair: (&'a mut T, T)) {
                (*self).$func((pair.0, &pair.1));
            }
        }
    };
}

binops_group!(Add, add, modadd);
binops_group!(Sub, sub, modsub);
binops_group!(Mul, mul, modmul);
binops_group!(Div, div, moddiv);
binops_group_assign!(AddAssign, add_assign, modadd_assign);
binops_group_assign!(SubAssign, sub_assign, modsub_assign);
binops_group_assign!(MulAssign, mul_assign, modmul_assign);
binops_group_assign!(DivAssign, div_assign, moddiv_assign);

impl<T: GroupElement> Group<T> {
    /// Create modular arithmetic parameters.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidModulus`] when `modulus` is negative, zero, or one.
    pub fn new(modulus: T) -> crate::Result<Self> {
        if modulus.is_negative() || modulus.is_zero() || modulus.is_one() {
            return Err(crate::Error::InvalidModulus);
        }
        Ok(Self {
            modulus,
            prime: false,
        })
    }

    /// Create modular arithmetic parameters after verifying that the modulus is prime.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid modulus, unavailable randomness, a backend failure, or a
    /// composite modulus.
    pub fn prime_field(modulus: T) -> crate::Result<Self> {
        let mut group = Self::new(modulus)?;
        if !group.modulus.is_prime()? {
            return Err(crate::Error::ModulusNotPrime);
        }
        group.prime = true;
        Ok(group)
    }

    /// Return the modulus used by this group.
    pub fn modulus(&self) -> &T {
        &self.modulus
    }

    /// Return whether the modulus was verified as prime at construction.
    pub fn is_prime_field(&self) -> bool {
        self.prime
    }

    /// Reduce `value` and bind it to this group.
    pub fn element(&self, value: T) -> GroupValue<'_, T> {
        GroupValue {
            value: value.nmod(&self.modulus),
            group: self,
        }
    }

    /// Return the additive identity bound to this group.
    pub fn zero(&self) -> GroupValue<'_, T> {
        GroupValue {
            value: T::zero(),
            group: self,
        }
    }

    /// Return the multiplicative identity bound to this group.
    pub fn one(&self) -> GroupValue<'_, T> {
        GroupValue {
            value: T::one(),
            group: self,
        }
    }

    /// Compute `-rhs mod self`.
    pub fn neg(&self, rhs: &T) -> T {
        rhs.modneg(&self.modulus)
    }

    /// Compute the sum of the big numbers in the group.
    pub fn sum<I, U>(&self, nums: I) -> T
    where
        I: IntoIterator<Item = U>,
        U: Borrow<T>,
    {
        nums.into_iter().fold(T::zero(), |mut result, value| {
            result.modadd_assign(value.borrow(), &self.modulus);
            result
        })
    }

    /// Compute the product of the big numbers in the group.
    pub fn product<I, U>(&self, nums: I) -> T
    where
        I: IntoIterator<Item = U>,
        U: Borrow<T>,
    {
        nums.into_iter().fold(T::one(), |mut result, value| {
            result.modmul_assign(value.borrow(), &self.modulus);
            result
        })
    }
}

impl<'group, T: GroupElement> GroupValue<'group, T> {
    fn ensure_compatible(&self, other: &Self) -> crate::Result<()> {
        if self.group.modulus == other.group.modulus {
            Ok(())
        } else {
            Err(crate::Error::MismatchedGroups)
        }
    }

    /// Return this value's group parameters.
    pub fn group(&self) -> &'group Group<T> {
        self.group
    }

    /// Return the reduced value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume this group value and return its reduced integer.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Add another value from compatible group parameters.
    pub fn checked_add(&self, rhs: &Self) -> crate::Result<Self> {
        self.ensure_compatible(rhs)?;
        Ok(GroupValue {
            value: self.value.modadd(&rhs.value, &self.group.modulus),
            group: self.group,
        })
    }

    /// Add another value in place while reusing this value's storage where supported.
    pub fn checked_add_assign(&mut self, rhs: &Self) -> crate::Result<()> {
        self.ensure_compatible(rhs)?;
        self.value.modadd_assign(&rhs.value, &self.group.modulus);
        Ok(())
    }

    /// Subtract another value from compatible group parameters.
    pub fn checked_sub(&self, rhs: &Self) -> crate::Result<Self> {
        self.ensure_compatible(rhs)?;
        Ok(GroupValue {
            value: self.value.modsub(&rhs.value, &self.group.modulus),
            group: self.group,
        })
    }

    /// Subtract another value in place while reusing this value's storage where supported.
    pub fn checked_sub_assign(&mut self, rhs: &Self) -> crate::Result<()> {
        self.ensure_compatible(rhs)?;
        self.value.modsub_assign(&rhs.value, &self.group.modulus);
        Ok(())
    }

    /// Multiply by another value from compatible group parameters.
    pub fn checked_mul(&self, rhs: &Self) -> crate::Result<Self> {
        self.ensure_compatible(rhs)?;
        Ok(GroupValue {
            value: self.value.modmul(&rhs.value, &self.group.modulus),
            group: self.group,
        })
    }

    /// Multiply by another value in place while reusing this value's storage where supported.
    pub fn checked_mul_assign(&mut self, rhs: &Self) -> crate::Result<()> {
        self.ensure_compatible(rhs)?;
        self.value.modmul_assign(&rhs.value, &self.group.modulus);
        Ok(())
    }

    /// Divide by another value from compatible group parameters.
    ///
    /// # Errors
    ///
    /// Returns an error when the groups differ or `rhs` has no multiplicative inverse.
    pub fn checked_div(&self, rhs: &Self) -> crate::Result<Self> {
        self.ensure_compatible(rhs)?;
        let inverse = rhs
            .value
            .invert(&self.group.modulus)
            .ok_or(crate::Error::NonInvertible)?;
        Ok(GroupValue {
            value: self.value.modmul(&inverse, &self.group.modulus),
            group: self.group,
        })
    }

    /// Divide by another value in place while reusing this value's storage where supported.
    ///
    /// # Errors
    ///
    /// Returns an error when the groups differ or `rhs` has no multiplicative inverse.
    pub fn checked_div_assign(&mut self, rhs: &Self) -> crate::Result<()> {
        self.ensure_compatible(rhs)?;
        let inverse = rhs
            .value
            .invert(&self.group.modulus)
            .ok_or(crate::Error::NonInvertible)?;
        self.value.modmul_assign(&inverse, &self.group.modulus);
        Ok(())
    }

    /// Return the additive inverse of this value.
    pub fn negated(&self) -> Self {
        GroupValue {
            value: self.value.modneg(&self.group.modulus),
            group: self.group,
        }
    }

    /// Replace this value with its additive inverse while reusing its storage where supported.
    pub fn negate(&mut self) {
        self.value.modneg_assign(&self.group.modulus);
    }

    /// Raise this value to `exponent` within the group.
    pub fn pow(&self, exponent: &T) -> Self {
        GroupValue {
            value: self.value.modpow(exponent, &self.group.modulus),
            group: self.group,
        }
    }

    /// Raise this value to `exponent` in place.
    pub fn pow_assign(&mut self, exponent: &T) {
        self.value = self.value.modpow(exponent, &self.group.modulus);
    }
}

macro_rules! binops_group_value {
    ($ops:ident, $func:ident, $checked:ident, $checked_assign:ident) => {
        impl<'group, T: GroupElement> $ops<&GroupValue<'group, T>> for &GroupValue<'group, T> {
            type Output = crate::Result<GroupValue<'group, T>>;

            fn $func(self, rhs: &GroupValue<'group, T>) -> Self::Output {
                self.$checked(rhs)
            }
        }

        impl<'group, T: GroupElement> $ops<GroupValue<'group, T>> for &GroupValue<'group, T> {
            type Output = crate::Result<GroupValue<'group, T>>;

            fn $func(self, rhs: GroupValue<'group, T>) -> Self::Output {
                self.$checked(&rhs)
            }
        }

        impl<'group, T: GroupElement> $ops<&GroupValue<'group, T>> for GroupValue<'group, T> {
            type Output = crate::Result<GroupValue<'group, T>>;

            fn $func(mut self, rhs: &GroupValue<'group, T>) -> Self::Output {
                self.$checked_assign(rhs)?;
                Ok(self)
            }
        }

        impl<'group, T: GroupElement> $ops<GroupValue<'group, T>> for GroupValue<'group, T> {
            type Output = crate::Result<GroupValue<'group, T>>;

            fn $func(mut self, rhs: GroupValue<'group, T>) -> Self::Output {
                self.$checked_assign(&rhs)?;
                Ok(self)
            }
        }
    };
}

binops_group_value!(Add, add, checked_add, checked_add_assign);
binops_group_value!(Sub, sub, checked_sub, checked_sub_assign);
binops_group_value!(Mul, mul, checked_mul, checked_mul_assign);
binops_group_value!(Div, div, checked_div, checked_div_assign);

impl<'group, T: GroupElement> Neg for GroupValue<'group, T> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.negate();
        self
    }
}

impl<'group, T: GroupElement> Neg for &GroupValue<'group, T> {
    type Output = GroupValue<'group, T>;

    fn neg(self) -> Self::Output {
        self.negated()
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;
    use crate::crypto::BigNumber;

    #[test]
    fn values_stay_reduced() {
        let group = Group::new(BigNumber::from(7)).unwrap();
        let three = group.element(BigNumber::from(10));
        let four = group.element(BigNumber::from(11));

        assert_eq!((three + four).unwrap().into_value(), BigNumber::zero());
        assert_eq!(
            group.product(core::iter::empty::<BigNumber>()),
            BigNumber::one()
        );
    }
}
