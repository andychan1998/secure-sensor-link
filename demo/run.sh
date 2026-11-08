#!/bin/sh
# Plays the demo session (demo/session.txt) through the receiver, one step at a
# time: each step shows what happens and the command, then the response when
# you press Enter.
#
#   demo/run.sh          step by step
#   demo/run.sh --all    everything at once
#
# Long hex values are shortened on screen; the receiver gets them in full.
set -eu

cd "$(dirname "$0")/.."
session=demo/session.txt

step=0
if [ "${1:-}" != "--all" ] && [ -t 0 ]; then
    step=1
fi

bold='' dim='' green='' red='' reset=''
if [ -t 1 ]; then
    bold=$(printf '\033[1m') dim=$(printf '\033[2m')
    green=$(printf '\033[32m') red=$(printf '\033[31m') reset=$(printf '\033[0m')
fi

cargo build --release --quiet

# Each command gets exactly one response line, in order, so the whole session
# runs first and each response is then shown under its command.
responses=$(mktemp)
trap 'rm -f "$responses"' EXIT
sed -n 's/^> //p' "$session" | "${CARGO_TARGET_DIR:-target}/release/secure-sensor-link" >"$responses"
exec 3<"$responses"

shorten() {
    sed -E \
        -e 's/("frame":")([0-9a-fA-F]{16})[0-9a-fA-F]+([0-9a-fA-F]{8})"/\1\2...\3"/' \
        -e 's/"([0-9a-f]{8})[0-9a-f]{56}"/"\1..."/g'
}

# The notes at the top of the session file, before the first section, aren't shown.
started=0
while IFS= read -r line; do
    case $line in
    '## '*)
        started=1
        printf '\n%s== %s ==%s\n' "$bold" "${line#'## '}" "$reset"
        ;;
    '# '*)
        if [ "$started" = 1 ]; then
            printf '\n%s\n' "${line#'# '}"
        fi
        ;;
    '> '*)
        printf '%s> %s%s\n' "$dim" "$(printf '%s' "${line#'> '}" | shorten)" "$reset"
        if [ "$step" = 1 ]; then
            read -r _ </dev/tty
        fi
        IFS= read -r response <&3
        case $response in
        '{"status":"ok","payload":'*)
            body=${response#'{"status":"ok","payload":'}
            printf '%sok%s %s\n' "$green" "$reset" "${body%'}'}"
            ;;
        *)
            message=$(printf '%s' "$response" |
                sed -E 's/^\{"status":"error","payload":\{"message":"(.*)"\}\}$/\1/')
            printf '%serror%s %s\n' "$red" "$reset" "$message"
            ;;
        esac
        ;;
    esac
done <"$session"
