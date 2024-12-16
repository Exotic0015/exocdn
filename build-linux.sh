#!/bin/bash
read -r -p "Enter the target CPU (default: x86-64-v3): " user_input
TARGET_CPU=${user_input:-x86-64-v3}

read -r -p "Enable compression? y/[n]: " user_input
case $user_input in
    "y" | "Y")
    COMPRESSION="--features compression"
    echo "Building with compression support."
    ;;

    *)
    echo "Building without compression support."
    ;;
esac

echo "Updating dependencies"
cargo update

export MALLOC_CONF="thp:always,metadata_thp:always" # Enable Transparent Huge Pages
echo "Building for target CPU: $TARGET_CPU"
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="clang" RUSTFLAGS="-Clink-arg=-fuse-ld=mold -Clink-arg=-Wl,--icf=all -C target-cpu=$TARGET_CPU -Zlocation-detail=none -Zshare-generics=y -Zthreads=0" cargo +nightly build -Z build-std=core,std,panic_abort,alloc,proc_macro -Z build-std-features=panic-unwind,panic_immediate_abort ${COMPRESSION:""} --target x86_64-unknown-linux-gnu --release

echo "Packing the binary"
upx --best --lzma target/x86_64-unknown-linux-gnu/release/exocdn
echo "Build finished"
