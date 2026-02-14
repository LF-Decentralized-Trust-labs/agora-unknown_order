# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### v0.12.0

- Update dependencies and streamline the API to match for all backends

### v0.10.0

- Significant speed boost in safe prime generation thanks to glass_pumpkin update 1.7

### v0.9.0

- Update crypto_backend to allow different sizes with the default as 4096. 
- Add random_bits, random_range and variants with_rngs.

### v0.7.0

- Add crypto-bigint as a backend
- Allow building with no_std

### v0.3.0

### Updated

- Changed rust-gmp to rug
- License either MIT or Apache 2.0
- Update dependencies

### v0.2.2

### Added

- impl Binary, Octal, LowerHex, UpperHex
- impl From for u128, i128

### v0.2.1

### Added
- div_rem 
  
### Fixes 

- gmp_backend compile issues with rand

### v0.2.0

- Add WASM
- Update dependencies

### v0.1.4

### Fixes

- gmp_backend prime generation was reusing seeds and generating the same prime numbers with consecutive calls

### v0.1.3

### Fixes

- More reliable gmp_backend prime generation

## v0.1.2

### Fixes

- Fix bug in gmp_backend to_bytes

## v0.1.1

### Added

- README.md updates
- Code doc updates
- Require openssl = 0.10.34+
- Added Group to easier operations
- Added std::iter::{Sum, Product} implementations to BigNumber
- Added modneg to BigNumber

## v0.1.0

### Added

- `gmp_backend::Bn` - A Big Number implementation backed by Gnu's MP Library
- `openssl_backend::Bn` - A Big Number implementation backed by Openssl's BigNum Library
- `rust_backend::Bn` - A Big Number implementation backed by Rust's BigInt crate
- `gcd_result::GcdResult` - A GCD result that contains the gcd value and the Bézout coefficients
