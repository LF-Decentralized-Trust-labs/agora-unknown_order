/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#[cfg(any(feature = "rust", feature = "gmp"))]
macro_rules! binops_impl {
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt, $ref_op:expr) => {
        impl<'a, 'b> $ops<&'b Bn> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: &'b Self::Output) -> Self::Output {
                Bn($ref_op(&self.0, &rhs.0))
            }
        }

        impl<'b> $ops_assign<&'b Bn> for Bn {
            fn $func_assign(&mut self, rhs: &'b Bn) {
                self.0 $opr_assign &rhs.0;
            }
        }

        ops_impl!($ops, $func, $ops_assign, $func_assign, $opr, $opr_assign);
    };
}

#[cfg(any(feature = "gmp", feature = "rust"))]
macro_rules! get_mod_impl {
    () => {
        fn get_mod(n: &Bn) -> alloc::borrow::Cow<'_, Bn> {
            if n.is_negative() {
                alloc::borrow::Cow::Owned(-n)
            } else {
                alloc::borrow::Cow::Borrowed(n)
            }
        }
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
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                self $opr Bn::from(rhs)
            }
        }

        impl $ops_assign<$rhs> for Bn {
            fn $func_assign(&mut self, rhs: $rhs) {
                *self $opr_assign Bn::from(rhs);
            }
        }
    )*};
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt) => {
        impl<'b> $ops<&'b Bn> for Bn {
            type Output = Bn;

            fn $func(mut self, rhs: &'b Self::Output) -> Self::Output {
                self $opr_assign rhs;
                self
            }
        }

        impl<'a> $ops<Bn> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: Self::Output) -> Self::Output {
                self $opr &rhs
            }
        }

        impl $ops for Bn {
            type Output = Bn;

            fn $func(mut self, rhs: Self::Output) -> Self::Output {
                self $opr_assign &rhs;
                self
            }
        }

        impl $ops_assign for Bn {
            fn $func_assign(&mut self, rhs: Bn) {
                *self $opr_assign &rhs;
            }
        }

        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, u8, u16, u32, u64, usize);
        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, i8, i16, i32, i64, isize);
    };
}

macro_rules! neg_impl {
    ($ref_op:expr, $owned_op:expr) => {
        impl<'a> Neg for &'a Bn {
            type Output = Bn;

            fn neg(self) -> Self::Output {
                $ref_op(&self.0)
            }
        }

        impl Neg for Bn {
            type Output = Bn;

            fn neg(self) -> Self::Output {
                $owned_op(self.0)
            }
        }
    };
}

macro_rules! shift_impl {
    (@owned $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $ref_op:expr, $owned_op:expr, $($rhs:ty),+) => {$(
        impl<'a> $ops<$rhs> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $ref_op(&self.0, rhs)
            }
        }

        impl $ops<$rhs> for Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $owned_op(self.0, rhs)
            }
        }

        impl $ops_assign<$rhs> for Bn {
            fn $func_assign(&mut self, rhs: $rhs) {
                self.0 = $owned_op(core::mem::take(&mut self.0), rhs).0;
            }
        }
    )*};
    (@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr, $($rhs:ty),+) => {$(
        impl<'a> $ops<$rhs> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $opr(&self.0, rhs)
            }
        }

        impl $ops<$rhs> for Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $opr(&self.0, rhs)
            }
        }

        impl $ops_assign<$rhs> for Bn {
            fn $func_assign(&mut self, rhs: $rhs) {
                let t = $opr(&self.0, rhs);
                *self = t;
            }
        }
    )*};
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr) => {
        shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, u8, u16, u32, u64, usize);
        shift_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, i8, i16, i32, i64, isize);
    };
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $ref_op:expr, $owned_op:expr) => {
        shift_impl!(@owned $ops, $func, $ops_assign, $func_assign, $ref_op, $owned_op, u8, u16, u32, u64, usize);
        shift_impl!(@owned $ops, $func, $ops_assign, $func_assign, $ref_op, $owned_op, i8, i16, i32, i64, isize);
    };
}

macro_rules! display_impl {
    ($radix:ident) => {
        impl Display for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl Debug for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:?}", self.0)
            }
        }

        radix_impl!($radix);
    };
}

macro_rules! radix_impl {
    (native) => {
        impl fmt::Binary for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Binary::fmt(&self.0, f)
            }
        }

        impl fmt::Octal for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Octal::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }
    };
    (bytes) => {
        impl fmt::Binary for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::fmt_bytes_radix(f, self.is_negative(), &self.to_bytes(), 2, false)
            }
        }

        impl fmt::Octal for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::fmt_bytes_radix(f, self.is_negative(), &self.to_bytes(), 8, false)
            }
        }

        impl fmt::LowerHex for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::fmt_bytes_radix(f, self.is_negative(), &self.to_bytes(), 16, false)
            }
        }

        impl fmt::UpperHex for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::fmt_bytes_radix(f, self.is_negative(), &self.to_bytes(), 16, true)
            }
        }
    };
}

macro_rules! zeroize_impl {
    ($opr:expr) => {
        impl Zeroize for Bn {
            fn zeroize(&mut self) {
                $opr(self)
            }
        }
    };
}

macro_rules! default_impl {
    ($opr:expr) => {
        impl Default for Bn {
            fn default() -> Self {
                Self($opr())
            }
        }
    };
}

macro_rules! clone_impl {
    ($opr:expr) => {
        impl Clone for Bn {
            fn clone(&self) -> Self {
                Self($opr(self))
            }
        }
    };
}

macro_rules! serdes_impl {
    () => {
        impl serde::Serialize for Bn {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let mut bytes = self.to_bytes();
                if bytes.is_empty() {
                    bytes.push(0);
                }
                let is_negative = self.is_negative();
                if serializer.is_human_readable() {
                    serializer.serialize_str(&crate::encode_signed_hex(is_negative, &bytes))
                } else {
                    bytes.insert(0, if is_negative { 1u8 } else { 0u8 });
                    serializer.serialize_bytes(&bytes)
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for Bn {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct BnVisitorStr;
                struct BnVisitorBytes;

                impl<'de> serde::de::Visitor<'de> for BnVisitorStr {
                    type Value = Bn;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a hex encoded string")
                    }

                    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        let (is_neg, bytes) = crate::decode_signed_hex(s).ok_or_else(|| {
                            serde::de::Error::invalid_value(
                                serde::de::Unexpected::Str(s),
                                &"valid hex",
                            )
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

                impl<'de> serde::de::Visitor<'de> for BnVisitorBytes {
                    type Value = Bn;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(f, "a bytestring")
                    }

                    fn visit_bytes<E>(self, s: &[u8]) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        if s.is_empty() {
                            return Err(serde::de::Error::invalid_length(0, &self));
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

                if deserializer.is_human_readable() {
                    deserializer.deserialize_str(BnVisitorStr)
                } else {
                    deserializer.deserialize_bytes(BnVisitorBytes)
                }
            }
        }
    };
}

macro_rules! eq_impl {
    () => {
        impl Eq for Bn {}

        impl PartialEq for Bn {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }
    };
}

macro_rules! from_impl {
    ($opr:expr, $rhs:ty) => {
        impl From<$rhs> for Bn {
            fn from(d: $rhs) -> Self {
                Self($opr(d))
            }
        }
    };
}

macro_rules! iter_impl {
    () => {
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
    };
}

#[cfg(feature = "wasm")]
macro_rules! wasm_slice_impl {
    ($name:ident) => {
        impl wasm_bindgen::describe::WasmDescribe for $name {
            fn describe() {
                wasm_bindgen::describe::inform(wasm_bindgen::describe::SLICE)
            }
        }

        impl wasm_bindgen::convert::IntoWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            fn into_abi(self) -> Self::Abi {
                wasm_bindgen::convert::IntoWasmAbi::into_abi(self.to_bytes())
            }
        }

        impl wasm_bindgen::convert::FromWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            #[inline]
            unsafe fn from_abi(js: Self::Abi) -> Self {
                // SAFETY: `js` is provided by wasm-bindgen under the `FromWasmAbi` contract and
                // represents an owned `Vec<u8>` allocation with matching pointer and length.
                let bytes = unsafe {
                    <alloc::vec::Vec<u8> as wasm_bindgen::convert::FromWasmAbi>::from_abi(js)
                };
                $name::from_slice(bytes)
            }
        }

        impl wasm_bindgen::convert::OptionIntoWasmAbi for $name {
            fn none() -> wasm_bindgen::convert::WasmSlice {
                <alloc::vec::Vec<u8> as wasm_bindgen::convert::OptionIntoWasmAbi>::none()
            }
        }

        impl wasm_bindgen::convert::OptionFromWasmAbi for $name {
            fn is_none(slice: &wasm_bindgen::convert::WasmSlice) -> bool {
                <alloc::vec::Vec<u8> as wasm_bindgen::convert::OptionFromWasmAbi>::is_none(slice)
            }
        }

        impl core::convert::TryFrom<wasm_bindgen::JsValue> for $name {
            type Error = &'static str;

            fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
                let value = value.as_string().ok_or("unable to deserialize value")?;
                let (negative, bytes) =
                    crate::decode_signed_hex(&value).ok_or("unable to deserialize value")?;
                let number = $name::from_slice(bytes);
                if negative && !number.is_zero() {
                    Ok(-number)
                } else {
                    Ok(number)
                }
            }
        }
    };
}
