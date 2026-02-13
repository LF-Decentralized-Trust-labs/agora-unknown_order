/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#[cfg(any(feature = "rust", feature = "gmp"))]
macro_rules! binops_impl {
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt) => {
        impl<'a, 'b> $ops<&'b Bn> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: &'b Self::Output) -> Self::Output {
                Bn(self.0.clone() $opr &rhs.0.clone())
            }
        }

        impl<'b> $ops_assign<&'b Bn> for Bn {
            fn $func_assign(&mut self, rhs: &'b Bn) {
                self.0 $opr_assign rhs.0.clone();
            }
        }

        ops_impl!($ops, $func, $ops_assign, $func_assign, $opr, $opr_assign);
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
                *self = &*self $opr &Bn::from(rhs);
            }
        }
    )*};
    ($ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:tt, $opr_assign:tt) => {
        impl<'b> $ops<&'b Bn> for Bn {
            type Output = Bn;

            fn $func(self, rhs: &'b Self::Output) -> Self::Output {
                &self $opr rhs
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

            fn $func(self, rhs: Self::Output) -> Self::Output {
                &self $opr &rhs
            }
        }

        impl $ops_assign for Bn {
            fn $func_assign(&mut self, rhs: Bn) {
                *self = &*self $opr &rhs;
            }
        }

        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, u8, u16, u32, u64, usize);
        ops_impl!(@ref $ops, $func, $ops_assign, $func_assign, $opr, $opr_assign, i8, i16, i32, i64, isize);
    };
}

macro_rules! neg_impl {
    ($ops:expr) => {
        impl<'a> Neg for &'a Bn {
            type Output = Bn;

            fn neg(self) -> Self::Output {
                $ops(&self.0)
            }
        }

        impl Neg for Bn {
            type Output = Bn;

            fn neg(self) -> Self::Output {
                $ops(&self.0)
            }
        }
    };
}

macro_rules! shift_impl {
    (@ref $ops:ident, $func:ident, $ops_assign:ident, $func_assign:ident, $opr:expr, $($rhs:ty),+) => {$(
        #[allow(clippy::unnecessary_cast)]
        impl<'a> $ops<$rhs> for &'a Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $opr(&self.0, rhs)
            }
        }

        #[allow(clippy::unnecessary_cast)]
        impl $ops<$rhs> for Bn {
            type Output = Bn;

            fn $func(self, rhs: $rhs) -> Self::Output {
                $opr(&self.0, rhs)
            }
        }

        #[allow(clippy::unnecessary_cast)]
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
}

macro_rules! display_impl {
    () => {
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

        impl fmt::Binary for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let bytes = self.to_bytes();
                for b in &bytes {
                    write!(f, "{:b}", b)?;
                }
                Ok(())
            }
        }

        impl fmt::Octal for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let bytes = self.to_bytes();
                for b in &bytes {
                    write!(f, "{:o}", b)?;
                }
                Ok(())
            }
        }

        impl fmt::LowerHex for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let bytes = self.to_bytes();
                for b in &bytes {
                    write!(f, "{:x}", b)?;
                }
                Ok(())
            }
        }

        impl fmt::UpperHex for Bn {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let bytes = self.to_bytes();
                for b in &bytes {
                    write!(f, "{:X}", b)?;
                }
                Ok(())
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
    ($ser_str:expr, $des_str:expr, $ser_bytes:expr, $des_bytes:expr) => {
        impl serde::Serialize for Bn {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if serializer.is_human_readable() {
                    let str = $ser_str(self);
                    serializer.serialize_str(&str)
                } else {
                    let bytes = $ser_bytes(self);
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
                        let b = $des_str(s).ok_or_else(|| {
                            serde::de::Error::invalid_value(serde::de::Unexpected::Str(s), &self)
                        })?;
                        Ok(Bn(b))
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
                        let b = $des_bytes(s).ok_or_else(|| {
                            serde::de::Error::invalid_value(serde::de::Unexpected::Bytes(s), &self)
                        })?;
                        Ok(Bn(b))
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
                let a = self.to_bytes();
                Self::Abi {
                    ptr: a.as_ptr().into_abi(),
                    len: a.len() as u32,
                }
            }
        }

        impl wasm_bindgen::convert::FromWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            #[inline]
            unsafe fn from_abi(js: Self::Abi) -> Self {
                let ptr = <*mut u8>::from_abi(js.ptr);
                let len = js.len as usize;
                let r = core::slice::from_raw_parts(ptr, len);
                $name::from_slice(&r)
            }
        }

        impl wasm_bindgen::convert::OptionIntoWasmAbi for $name {
            fn none() -> wasm_bindgen::convert::WasmSlice {
                wasm_bindgen::convert::WasmSlice { ptr: 0, len: 0 }
            }
        }

        impl wasm_bindgen::convert::OptionFromWasmAbi for $name {
            fn is_none(slice: &wasm_bindgen::convert::WasmSlice) -> bool {
                slice.ptr == 0
            }
        }

        impl core::convert::TryFrom<wasm_bindgen::JsValue> for $name {
            type Error = &'static str;

            fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
                serde_wasm_bindgen::from_value(value).map_err(|_| "unable to deserialize value")
            }
        }
    };
}
