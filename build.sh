#!/bin/bash
cargo clean --release
cargo update
RUSTFLAGS="-C target-cpu=x86-64-v3" cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release