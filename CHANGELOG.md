# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### v0.13.0

#### Added

- Allow the `crypto`, `gmp`, `openssl`, and `rust` backends to be enabled and used simultaneously.
  Each backend is exported through its own namespace, while the top-level `BigNumber` alias remains
  available when exactly one backend is enabled.
- Add `GroupValue`, a value bound to validated runtime group parameters and automatically reduced
  after construction, addition, subtraction, multiplication, division, negation, and
  exponentiation.
- Add `Group::new` for modular rings and `Group::prime_field` for moduli verified as prime.
- Add checked group-value arithmetic and in-place operations that report mismatched moduli and
  non-invertible divisors.
- Add the public `Error` and `Result` types with errors for invalid ranges, invalid prime sizes,
  incorrect output-buffer lengths, invalid or composite moduli, mismatched groups, non-invertible
  values, unavailable system randomness, OpenSSL failures, and pure-Rust prime-generation failures.

#### Changed

- **Breaking:** Change the default backend from `crypto` to `openssl`.
- **Breaking:** Make `Group` construction fallible, keep its modulus private, and expose it through
  `Group::modulus`. Extend `GroupElement` with validation, inversion, and exponentiation operations.
- **Breaking:** Return `Result` from `random`, `random_bits`, `random_range`, `prime`, `safe_prime`,
  `is_prime`, and `copy_bytes_into_buffer` where the operation can fail.
- **Breaking:** Make `GcdResult` generic so every simultaneously enabled backend can use it without
  depending on a global `BigNumber` alias.
- Use dynamically sized `crypto_bigint::BoxedUint` values instead of fixed, over-provisioned
  precision in the `crypto` backend.
- Seed `rand` 0.10 `StdRng` instances from system entropy and propagate seeding failures instead of
  hiding `SysRng` errors behind an infallible wrapper.
- Update to Rust edition 2024 with an MSRV of Rust 1.88.
- Update dependencies, including `crypto-bigint` 0.7.5, `crypto-primes` 0.7.2, `num-bigint` 0.5,
  `rand` 0.10, and `glass_pumpkin` 2.0.0-rc1, while disabling unused default features.
- Remove the runtime `hex`, `multibase`, and `serde-wasm-bindgen` dependencies and replace their use
  with focused internal encoding and current `wasm-bindgen` conversions. Replace the archived
  `bincode` serialization test dependency with supported formats.

#### Fixed

- Preserve signs and grow precision correctly for owned and borrowed arithmetic, including values
  larger than a machine word and minimum signed integer conversions.
- Format binary, octal, lower-hex, and upper-hex values as numeric representations rather than as
  independently formatted bytes.
- Make equality, ordering, hashing, and constant-time equality consistent for signed and
  differently sized values.
- Validate random ranges, prime bit lengths, and destination buffer lengths instead of panicking or
  silently accepting invalid input.
- Return zero for modular exponentiation with a zero modulus consistently across backends.
- Correct WebAssembly ownership reconstruction while retaining an explicit safety justification for
  the `wasm-bindgen` ABI boundary.

#### Performance

- Reuse owned operands and backend storage for arithmetic, shifts, modular assignment, group-value
  operations, OpenSSL prime generation, and encoding buffers where supported.
- Remove normalization clones from `crypto-bigint` comparisons and arithmetic, minimize stored limb
  precision after operations, and borrow modular parameters where possible.
- Compare native limbs directly for constant-time equality in the `crypto`, GMP, and pure-Rust
  backends.
- Reuse thread-local OpenSSL big-number contexts and avoid temporary quotient, digit, and encoding
  allocations.
- Accept iterators directly in group sums and products without requiring an intermediate slice or
  collection.

#### Testing and tooling

- Test every backend independently and all backends together in CI, with all-feature Clippy checks
  treating warnings as errors.
- Add cross-backend tests for reduced group arithmetic, invalid group operations, signed arithmetic,
  requested random bit lengths, error paths, large values, and an RSA round trip.
- Test serde round trips with Postcard, CBOR, JSON, TOML, and YAML.
- Make the build and test scripts fail immediately and include all-feature builds and tests.
- Keep warning-denied Clippy builds compatible with the lint set in Rust 1.98.

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
