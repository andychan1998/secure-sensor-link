# secure-sensor-link

A receiver that decodes, authenticates, and time-synchronizes camera frames arriving over a hostile link.

The design, threat model and the reasoning behind each decision are in [DESIGN.md](DESIGN.md).

## Setup

Install Rust with [rustup](https://rustup.rs) (or `brew install rustup`). Then, in this folder:

```
rustup toolchain install    # installs the version pinned in rust-toolchain.toml (1.97.0)
cargo build --release
```

## Run

The receiver reads one JSON command per line on stdin and writes one JSON response per line on stdout.

```
cargo run --release < commands.jsonl
```

Or start it and type commands; each response prints right away:

```
cargo run --release
{"command":"get_state","parameters":{}}
```

| Command | What it does |
|---|---|
| `init` | Sets the timing limits, each camera's key 0 and, optionally, `persist_interval` (default 100). Must come first, once. |
| `receive` | Checks one frame (version 1, or version 2 with a key id) and returns it with any newly paired frames. |
| `get_state` | Returns each camera's last frame, waiting frames and keys. |
| `add_key` | Provisions a new key id for a camera. |
| `revoke_key` | Revokes a key id. |
| `restart` | Simulates a power loss, then restarts from the (simulated) non-volatile storage. |

## Demo

```
demo/run.sh          # step by step: press Enter to see each response
demo/run.sh --all    # the whole session at once
```

It plays `demo/session.txt` through the receiver: normal traffic, attacks on the link, key rotation and revocation, and a power loss, using the frames from the project description's examples. The transcript test checks every response in that file, so the demo can't drift from what the receiver does.

## Test

```
cargo test                  # everything, a few seconds
cargo test --test rules     # the receiver's rules
cargo test --test keys      # key rotation and revocation
cargo test --test restart   # restarts
cargo test --test model     # random command sequences against a reference model
cargo test --test soak      # a long mixed stream through the real binary
```

Transcripts are plain text: `> ` starts a command, and the next line is its expected response (`< ` exact, `<~ ` partial). To add a test, drop a `.txt` file in `tests/transcripts/`.

**Linux only: `tests/memory.rs`.** It checks that no copy of a retired or revoked key is left behind by reading the running receiver's memory through `/proc/<pid>/mem`, which only Linux has. On macOS, reading another process's memory needs root or a debugging entitlement, and system calls that the crate's ban on `unsafe` code rules out. On a Mac, `cargo test` skips it; CI runs it on Linux.

**Property tests: `tests/model.rs` and part of `tests/restart.rs`.** Instead of fixed examples, they generate random command sequences (valid, forged, replayed and malformed frames, key changes, restarts) and check that a rule holds for every one, such as "the receiver gives exactly the responses of a plain reference implementation". A failing sequence is shrunk to the smallest one that still fails. `cargo test` runs 400 to 500 sequences each; for a longer run, raise the count:

```
PROPTEST_CASES=100000 cargo test --release --test model
```

**Soak test: `tests/soak.rs`.** Sends a long mixed stream of frames, forgeries, replays, bad lines, key changes and restarts through the real binary. It checks that every command gets the right kind of response within 10 seconds and that memory stops growing after warming up, and prints commands per second. `cargo test` sends 5,000 commands in debug builds and 50,000 in release; for a stress run:

```
SOAK_COMMANDS=1000000 cargo test --release --test soak -- --nocapture
```

## What CI runs

On every push and pull request (`.github/workflows/ci.yml`):

| Job | Runs |
|---|---|
| Test, on Linux and on macOS | `cargo fmt --check`, `cargo clippy`, `cargo doc`, then every test twice: `cargo test` and `cargo test --release` (`tests/memory.rs` on Linux only) |
| Coverage, on Linux | every test again, measuring which lines run |
| Fuzz, on Linux | each fuzz target for 60 seconds |
| Dependencies | `cargo deny check` |

Mutation testing takes about 10 minutes, so it isn't in CI; run it after larger changes.

## Check the tests

**Coverage**: which lines the tests run. Expect about 99% of lines.

```
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov --summary-only            # a table per file
cargo llvm-cov --html --open             # each line, in the browser
```

**Mutation testing**: makes small changes to the code and checks that a test fails for each one. Expect every mutant to be caught; the exclusions, each with a reason, are in `.cargo/mutants.toml`.

```
cargo install cargo-mutants
cargo mutants                            # about 10 minutes
```

**Fuzzing**: random input too, but unlike the property tests it mutates raw bytes for as long as you let it, steering toward input that reaches new code, and runs outside `cargo test`. It needs Rust's nightly toolchain, used only for fuzzing.

```
rustup toolchain install nightly
cargo install cargo-fuzz
fuzz/run.sh command_line                 # 10 minutes; add a number of seconds to change that
fuzz/run.sh receiver
fuzz/run.sh tree
```

A failing input is saved in `fuzz/artifacts/<target>/`; `cargo +nightly fuzz run <target> <file>` replays it.

**Dependencies**: checks every dependency for known vulnerabilities, its license and where it comes from, and that the receiver uses only the libraries the spec allows (the allowlist in `deny.toml`).

```
cargo install cargo-deny
cargo deny check
```

## Layout

```
src/
  main.rs       connects stdin and stdout to the protocol
  protocol.rs   bounded line reading, strict JSON commands, responses, panic safety net
  config.rs     init parameters, validated
  input.rs      reading input through a buffer that erases what it hands out
  key.rs        32-byte keys that erase themselves and never print
  keyring.rs    each camera's keys: active, retired or revoked
  frame.rs      the wire format, versions 1 and 2: RawFrame (untrusted) -> VerifiedFrame (tag checked)
  tree.rs       the payload tree: non-recursive decoder with size limits, level-order output
  receiver.rs   checks a frame in order, then commits its effects: storage first, then memory
  floor.rs      replay protection that survives a restart, within the write budget
  storage.rs    the storage trait, and the simulated non-volatile store
  timeline.rs   timestamp correction, in exact 128-bit arithmetic
  sync.rs       per-camera queues and pairing
  camera.rs     the two cameras, and one value per camera
tests/          transcripts, rules, keys, restarts, reference model, soak, command line
fuzz/           fuzz targets, seeds and dictionary (a separate crate)
demo/           the presentation demo: run.sh and the session it plays
```

## Stages

The project was built in the spec's three stages, and each finished stage is tagged:

| Tag | Stage | What it adds |
|---|---|---|
| `v1-base` | Base problem | `init`, `receive` and `get_state`: authenticated frames, replay protection, timestamp correction and pairing |
| `v2-keys` | Follow-on 1 | Key rotation and revocation: version 2 frames with a key id, `add_key` and `revoke_key` |
| `v3-restart` | Follow-on 2 | `restart` and `persist_interval`: replay protection that survives a restart, within the storage write budget |

`main` builds on `v3-restart` with CI, fuzzing, the fixes from an independent security review, the demo and the soak test.

```
git checkout v2-keys        # look at a stage; git checkout main to come back
git diff v1-base v2-keys    # what a stage changed
```
