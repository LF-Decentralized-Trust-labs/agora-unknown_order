#!/bin/bash

set -euo pipefail

echo "Building all backends together"
cargo build --all-features
echo "Building w/Crypto-BigInt"
cargo build --no-default-features --features=crypto
echo "Building w/Gnu MP Lib"
cargo build --no-default-features --features=gmp
echo "Building w/OpenSSL"
cargo build --no-default-features --features=openssl
echo "Building w/Rust"
cargo build --no-default-features --features=rust
