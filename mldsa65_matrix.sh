#!/bin/sh
# Three-way ML-DSA-65 view: the wrapper's native and portable-C builds, each
# measured paired against the same aws-lc-rs. One binary cannot hold both
# wrapper backends — cargo unifies a crate's features across the build graph,
# and the two backends share their C symbol names by design — so this runs
# the bench twice and stacks the tables.
set -e
cd "$(dirname "$0")"
cargo run --release --quiet --bin mldsa65
cargo run --release --quiet --no-default-features --bin mldsa65
