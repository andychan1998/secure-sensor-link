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

| Command | Does |
|---|---|
| `init` | Sets the timing limits, each camera's key 0 and, optionally, `persist_interval` (default 100). Must come first, once. |
| `receive` | Checks one frame (version 1, or version 2 with a key id) and returns it with any newly paired frames. |
| `get_state` | Returns each camera's last frame, waiting frames and keys. |
| `add_key` | Provisions a new key id for a camera. |
| `revoke_key` | Revokes a key id. |
| `restart` | Simulates a power loss, then restarts from the (simulated) non-volatile storage. |

## Test

```
cargo test                  # everything, a few seconds
cargo test --test rules     # the receiver's rules
cargo test --test keys      # key rotation and revocation
cargo test --test restart   # restarts
cargo test --test model     # random command sequences against a reference model
```

`tests/memory.rs` runs only on Linux.

Transcripts are plain text: `> ` starts a command, and the next line is its expected response (`< ` exact, `<~ ` partial). To add a test, drop a `.txt` file in `tests/transcripts/`.

## Check the tests

CI runs coverage, a short fuzz of each target and the dependency check on every push. Mutation testing takes longer, so run it after larger changes.

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

**Fuzzing**: needs Rust's nightly toolchain, used only for fuzzing.

```
rustup toolchain install nightly
cargo install cargo-fuzz
fuzz/run.sh command_line                 # 10 minutes; add a number of seconds to change that
fuzz/run.sh receiver
fuzz/run.sh tree
```

A failing input is saved in `fuzz/artifacts/<target>/`; `cargo +nightly fuzz run <target> <file>` replays it.

**Dependencies**: known vulnerabilities, licenses and sources of every dependency.

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
tests/          transcripts, rules, keys, restarts, reference model, command line
fuzz/           fuzz targets, seeds and dictionary (a separate crate)
```
