#!/bin/bash
cargo update
RUSTFLAGS="-C target-cpu=x86-64-v3 -Zlocation-detail=none" cargo +nightly build -Z build-std=core,std,panic_abort,alloc,proc_macro -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release
