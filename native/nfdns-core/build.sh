#!/usr/bin/env bash
# Builds libnfdns.so for Android ABIs (and optionally the host, for JVM unit tests).
# Usage: build.sh <ndk-dir> <android-out-dir|/dev/null> <host-out-dir|-> <min-sdk> [abi...]
set -euo pipefail
ndk="$1"; out="$2"; host_out="$3"; api="$4"; shift 4
cd "$(dirname "$0")"
toolchain="$ndk/toolchains/llvm/prebuilt/$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64/bin"
declare -A triple=( [arm64-v8a]=aarch64-linux-android [armeabi-v7a]=armv7-linux-androideabi
                    [x86_64]=x86_64-linux-android [x86]=i686-linux-android )
declare -A clang=( [arm64-v8a]=aarch64-linux-android [armeabi-v7a]=armv7a-linux-androideabi
                   [x86_64]=x86_64-linux-android [x86]=i686-linux-android )
targets=()
for abi in "$@"; do targets+=("${triple[$abi]}"); done
if [ ${#targets[@]} -gt 0 ] && command -v rustup >/dev/null 2>&1; then
  rustup target add "${targets[@]}" >/dev/null
fi
for abi in "$@"; do
  t="${triple[$abi]}"
  env_name="CARGO_TARGET_$(echo "$t" | tr '[:lower:]-' '[:upper:]_')_LINKER"
  export "$env_name=$toolchain/${clang[$abi]}$api-clang"
  cargo build --release --locked --target "$t"
  mkdir -p "$out/$abi"
  cp "target/$t/release/libnfdns.so" "$out/$abi/"
done
if [ "$host_out" != "-" ]; then
  cargo build --release --locked
  mkdir -p "$host_out"
  cp target/release/libnfdns.so "$host_out/"
fi
