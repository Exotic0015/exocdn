#!/bin/bash
read -r -p "Enter the target CPU (default: x86-64-v3): " user_input
TARGET_CPU=${user_input:-x86-64-v3}

echo "Updating dependencies"
cargo update

export MALLOC_CONF="thp:always,metadata_thp:always" # Enable Transparent Huge Pages
echo "Building for target CPU: $TARGET_CPU"
RUSTFLAGS="-C target-cpu=$TARGET_CPU -Zlocation-detail=none" cargo +nightly build -Z build-std=core,std,panic_abort,alloc,proc_macro -Z build-std-features=panic_immediate_abort --target x86_64-unknown-linux-gnu --release

echo "Packing the binary"
upx --best --lzma target/x86_64-unknown-linux-gnu/release/exocdn
echo "Build finished"