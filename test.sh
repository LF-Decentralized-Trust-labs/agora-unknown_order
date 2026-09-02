#!/bin/bash

set -euo pipefail

echo "Testing all backends together"
cargo test --all-features
echo "Testing w/Crypto-BigInt"
cargo test --no-default-features --features=crypto
echo "Testing w/Gnu MP Lib"
cargo test --no-default-features --features=gmp
echo "Testing w/OpenSSL"
cargo test --no-default-features --features=openssl
echo "Testing w/Rust"
cargo test --no-default-features --features=rust
