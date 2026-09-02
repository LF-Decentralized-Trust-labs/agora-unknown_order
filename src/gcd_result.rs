/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

/// GcdResult encapsulates the gcd result and the Bézout coefficients
#[derive(Debug, Clone)]
pub struct GcdResult<T> {
    /// Quotient
    pub gcd: T,
    /// Bézout coefficient
    pub x: T,
    /// Bézout coefficient
    pub y: T,
}
