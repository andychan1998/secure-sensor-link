#!/bin/sh
# Runs mutation testing, then says whether it passed on this platform.
#
#   scripts/mutants.sh [cargo mutants options, e.g. -j 2]
#
# Results go to mutants.out/, so don't pass --output.
#
# cargo mutants alone exits 3 when some mutants time out, and on macOS it
# reports mutants as missed that only a Linux-only test can catch. This
# script reads its results in mutants.out/ and applies both rules:
#
# - A timeout counts as caught: the mutant made the tests hang, and they
#   were stopped.
# - Some mutants weaken memory erasure: a key's bytes when it's dropped, and
#   the stack after each command. Only tests/memory.rs can see them, by
#   reading the running receiver's memory, and it runs on Linux only. On
#   Linux they must be caught; elsewhere they're listed as not checkable.
# - The stack ones need a release build: only an optimized build leaves a
#   copy of a key on the stack for the scrub to remove, so in the debug build
#   cargo mutants uses, removing the scrub changes nothing. On Linux, any of
#   them missed there are tested again with a release build, and must be
#   caught there.
set -u

cd "$(dirname "$0")/.."

cargo mutants "$@"
status=$?
# 0: all caught, 2: some missed, 3: some timed out. Anything else means the
# run didn't finish (bad options, failing tests before any mutation).
case $status in
0 | 2 | 3) ;;
*)
    echo
    echo "FAIL: cargo mutants stopped with exit code $status before finishing."
    exit 1
    ;;
esac

out=mutants.out
count() {
    if [ -f "$out/$1" ]; then
        wc -l <"$out/$1" | tr -d ' '
    else
        echo 0
    fi
}

# The mutants only tests/memory.rs can catch, as patterns for grep -E, and
# among them the ones that need a release build.
scrub_len_line=$(grep -n 'const STACK_SCRUB_LEN' src/protocol.rs | cut -d: -f1)
release_only="replace scrub_stack with \(\)\$
^src/protocol\.rs:$scrub_len_line:"
linux_only="replace <impl Drop for Key>::drop with \(\)\$
$release_only"

platform=$(uname -s)
case $platform in
Darwin) platform=macOS ;;
esac
missed_file=$(mktemp)
patterns=$(mktemp)
release_patterns=$(mktemp)
trap 'rm -f "$missed_file" "$patterns" "$release_patterns"' EXIT
printf '%s\n' "$linux_only" >"$patterns"
printf '%s\n' "$release_only" >"$release_patterns"
touch "$out/missed.txt"
release_caught=0
if [ "$platform" = Linux ]; then
    grep -v -E -f "$release_patterns" "$out/missed.txt" >"$missed_file" || true
    if grep -q -E -f "$release_patterns" "$out/missed.txt"; then
        echo
        echo "Testing the stack scrub's mutants again with a release build:"
        release_out="$out/release"
        cargo mutants --profile release -F "$(paste -s -d '|' "$release_patterns")" \
            --output "$release_out"
        case $? in
        0 | 2 | 3) ;;
        *)
            echo
            echo "FAIL: the release build run of cargo mutants stopped before finishing."
            exit 1
            ;;
        esac
        release_dir="$release_out/mutants.out"
        release_caught=$(cat "$release_dir/caught.txt" "$release_dir/timeout.txt" 2>/dev/null |
            wc -l | tr -d ' ')
        cat "$release_dir/missed.txt" >>"$missed_file" 2>/dev/null || true
    fi
    unchecked=''
else
    grep -v -E -f "$patterns" "$out/missed.txt" >"$missed_file" || true
    unchecked=$(grep -E -f "$patterns" "$out/missed.txt" || true)
fi
missed=$(wc -l <"$missed_file" | tr -d ' ')

echo
echo "Mutation testing on $platform: $(count caught.txt) caught, $(count timeout.txt) timed out" \
    "(also caught: the tests hung and were stopped), $(count unviable.txt) didn't compile," \
    "$missed missed."
if [ "$release_caught" -gt 0 ]; then
    echo "Of the stack scrub's mutants missed in the debug build, $release_caught were caught" \
        "by a release build, the only kind that leaves a key on the stack to scrub."
fi
if [ -n "$unchecked" ]; then
    echo
    echo "Not checkable on $platform: these weaken memory erasure, and only tests/memory.rs,"
    echo "which runs on Linux only, can catch them. CI runs tests/memory.rs on every push;"
    echo "run this script on Linux to check these too."
    printf '%s\n' "$unchecked" | sed 's/^/  /'
fi
echo
if [ "$missed" -eq 0 ]; then
    echo "PASS: every mutant this platform can check was caught."
else
    echo "FAIL: no test caught these; each one's test output is in $out/log/:"
    sed 's/^/  /' "$missed_file"
    exit 1
fi
