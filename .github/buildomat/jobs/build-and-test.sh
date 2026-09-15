#!/bin/bash
#:
#: name = "build-and-test"
#: variety = "basic"
#: target = "helios-3.0"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/out/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

banner build

ptime -m cargo build --release --verbose

banner test

ptime -m cargo test --verbose

banner miri

# XXX what's the proper way to do this?
rustup component add --toolchain nightly-x86_64-unknown-illumos miri
ptime -m cargo +nightly miri test -p os-rot

