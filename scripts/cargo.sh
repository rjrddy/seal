#!/bin/sh
set -eu
if command -v cargo >/dev/null 2>&1; then exec cargo "$@"; fi
seal_rust_root="${SEAL_RUST_ROOT:-$(pwd)/../.cache/seal-tools}"
if [ ! -x "$seal_rust_root/cargo/bin/cargo" ]; then
  echo 'Install Rust using rustup, or set SEAL_RUST_ROOT to the isolated toolchain root.' >&2
  exit 1
fi
export CARGO_HOME="$seal_rust_root/cargo"
export RUSTUP_HOME="$seal_rust_root/rustup"
export PATH="$CARGO_HOME/bin:$PATH"
exec "$CARGO_HOME/bin/cargo" "$@"
