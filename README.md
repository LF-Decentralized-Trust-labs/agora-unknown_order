# unknown_order

[![Crates.io](https://img.shields.io/crates/v/unknown_order.svg)](https://crates.io/crates/unknown_order)
[![Documentation](https://docs.rs/unknown_order/badge.svg)](https://docs.rs/unknown_order)
![License](https://img.shields.io/badge/License-Apache%202.0%20OR%20MIT-green.svg)
![MSRV](https://img.shields.io/badge/rustc-1.88+-blue.svg)
[![dependency status](https://deps.rs/repo/github/mikelodder7/unknown_order/status.svg)](https://deps.rs/repo/github/mikelodder7/unknown_order)

`unknown_order` provides a common API for arithmetic in groups whose order is unknown. It supports
the `crypto-bigint`, GNU MP, OpenSSL, and `num-bigint` implementations.

## Backends

OpenSSL is enabled by default:

```toml
unknown_order = "0.13"
```

Enable one or more backends explicitly when different implementations are needed in the same
program:

```toml
unknown_order = { version = "0.13", default-features = false, features = ["crypto", "gmp", "openssl", "rust"] }
```

Each enabled backend has its own namespace:

```rust
use unknown_order::{crypto, openssl, Group};

let crypto_group = Group::new(crypto::BigNumber::from(17))?;
let openssl_group = Group::new(openssl::BigNumber::from(17))?;

assert_eq!(
    crypto_group.product([crypto::BigNumber::from(3), crypto::BigNumber::from(4)]),
    crypto::BigNumber::from(12),
);
assert_eq!(
    openssl_group.product([openssl::BigNumber::from(3), openssl::BigNumber::from(4)]),
    openssl::BigNumber::from(12),
);

# Ok::<(), unknown_order::Error>(())
```

When exactly one backend feature is enabled, its type is also available as
`unknown_order::BigNumber` for source compatibility. Multi-backend builds intentionally require the
namespaced types so backend selection is explicit.

The backends have different implementation, licensing, timing, and platform tradeoffs. OpenSSL and
GNU MP require their corresponding native libraries. The `crypto` backend is suitable for
`no_std` and WebAssembly builds.

## Example

```rust
use unknown_order::{BigNumber, Group};

let field = Group::prime_field(BigNumber::from(17))?;
let three = field.element(BigNumber::from(20));
let eleven = field.element(BigNumber::from(11));

let product = (&three * &eleven)?;
assert_eq!(product.into_value(), BigNumber::from(16));
assert_eq!(three.pow(&BigNumber::from(4)).into_value(), BigNumber::from(13));

# Ok::<(), unknown_order::Error>(())
```

Values are reduced when they enter a group and after every operation. Binary operators return a
`Result` so mixing different moduli and dividing by a non-invertible value are reported explicitly.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option.

Unless explicitly stated otherwise, contributions are dual licensed under those terms.
