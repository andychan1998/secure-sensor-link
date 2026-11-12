#!/bin/sh
# Measures throughput, one kind of frame at a time, straight through the
# release binary: small frames, the largest frames the receiver accepts, and
# the largest frames possible. Three runs each; see tests/bench.rs.
#
#   scripts/bench.sh                     # all three cases
#   scripts/bench.sh small_frames        # or one: small_frames,
#                                        # largest_accepted_frames or
#                                        # largest_possible_frames
#
# The cases run one at a time (--test-threads=1), so they don't compete for
# the CPU.
#
# The figures depend on the machine, so run it on an idle one. It isn't part
# of `cargo test` or CI.
set -eu

cd "$(dirname "$0")/.."

exec cargo test --release --test bench -- --ignored --nocapture --test-threads=1 "$@"
