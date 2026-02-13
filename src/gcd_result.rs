/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/

/// GcdResult encapsulates the gcd result and the Bézout coefficients
#[derive(Debug, Clone)]
pub struct GcdResult {
    /// Quotient
    pub gcd: crate::BigNumber,
    /// Bézout coefficient
    pub x: crate::BigNumber,
    /// Bézout coefficient
    pub y: crate::BigNumber,
}
