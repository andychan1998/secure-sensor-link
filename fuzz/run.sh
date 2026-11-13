#!/bin/sh
# Fuzzes one target for a while (default 10 minutes):
#
#   fuzz/run.sh command_line|receiver|tree [seconds]
#
# New inputs that reach new code go to fuzz/corpus/<target> (not committed).
# A failing input is saved under fuzz/artifacts/<target>; rerun it with
#   cargo +nightly fuzz run <target> <that file>
# FUZZ_TOOLCHAIN picks the toolchain (nightly by default; cargo-fuzz needs it).
set -eu
toolchain=${FUZZ_TOOLCHAIN:-nightly}
# Build for this machine's own target. Otherwise cargo-fuzz builds for the
# target it was itself built for, which for a prebuilt cargo-fuzz (as CI
# installs) is musl, and the address sanitizer can't run there.
host=$(rustc "+$toolchain" -vV | sed -n 's/^host: //p')

target=${1:?usage: fuzz/run.sh command_line|receiver|tree [seconds]}
seconds=${2:-600}
cd "$(dirname "$0")/.."

corpus="fuzz/corpus/$target"
mkdir -p "$corpus"
set -- "$corpus"
if [ -d "fuzz/seeds/$target" ]; then
    set -- "$@" "fuzz/seeds/$target"
fi
set -- "$@" -- "-max_total_time=$seconds"
if [ -f "fuzz/$target.dict" ]; then
    set -- "$@" "-dict=fuzz/$target.dict"
fi
exec cargo "+$toolchain" fuzz run --target "$host" "$target" "$@"
