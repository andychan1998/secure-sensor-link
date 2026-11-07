# secure-sensor-link

A receiver that decodes, authenticates, and time-synchronizes camera frames arriving over a hostile link. Written in Rust, using only the standard library plus `serde_json`, `hex`, `hmac` + `sha2`, and `ctutils` (constant-time comparison).

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

Every line gets exactly one response, including blank or malformed lines. Lines longer than 256 KiB get one error and are discarded.

| Command | Does |
|---|---|
| `init` | Sets the timing limits, each camera's key 0 and, optionally, `persist_interval` (default 100). Must come first, once. |
| `receive` | Checks one frame (version 1, or version 2 with a key id) and returns it with any newly paired frames. |
| `get_state` | Returns each camera's last frame, waiting frames and keys. |
| `add_key` | Provisions a new key id for a camera. Re-adding the same key is a no-op. |
| `revoke_key` | Revokes a key id at once; waiting frames that used it are dropped. |
| `restart` | Simulates a power loss: everything in memory is lost and the receiver starts again from its (simulated) non-volatile storage. |

A camera moves to a key when a frame under it is accepted, and every lower key is then retired. A retired or revoked key id can never be used or provisioned again.

Replay protection survives a restart. Before accepting a seq above its saved floor, the receiver writes a new floor, `seq + persist_interval`, to storage; after a restart, frames at or below that floor are rejected. That keeps writes within the spec's budget of `1 + (S_max - S_min) / persist_interval` per camera. Configuration and key changes are written at once. Timelines and queues start empty after a restart.

One rejected frame does change state: after a restart, a frame rejected only because it is at or below the floor, but otherwise valid, still moves its camera to the frame's key. Without the restart it would have been accepted and retired the older keys; ignoring it would let an attacker holding an old key in.

## Test

```
cargo test                  # everything, a few seconds
cargo test --test rules     # the receiver's rules and design decisions
cargo test --test keys      # key rotation and revocation
cargo test --test restart   # restarts, including a twin that never restarts
cargo test --test model     # random command sequences against a reference model
```

| Tests | Where | What they show |
|---|---|---|
| Spec examples | `tests/transcripts/spec/` | The project description's examples, response by response |
| Rules and decisions | `tests/rules.rs` | Order of checks, rejected frames change nothing, strict input, extreme values |
| Keys | `tests/keys.rs` | Rotation, retirement and revocation, and each `add_key` / `revoke_key` error |
| Restarts | `tests/restart.rs` | Each restart rule, storage write counts, and a property test running a restarted receiver beside a twin that never restarts: no replay is ever accepted twice, a restart never lets in an attacker frame the twin rejects, required frames are accepted, and writes stay within budget |
| Reference model | `tests/model.rs` | Random sequences of valid, forged, replayed and malformed frames, key additions, revocations and restarts give exactly the responses and state of a separate, plain implementation of the spec; arbitrary bytes never cause an internal error |
| Command line | `tests/cli.rs` | The real binary over stdin and stdout |
| Unit tests | `src/*.rs` | Each module, including every boundary value |

Transcripts are plain text: `> ` starts a command, and the next line is its expected response (`< ` exact, `<~ ` partial). To add a test, drop a `.txt` file in `tests/transcripts/`.

### Checking the tests themselves

Passing tests only matter if they would fail on a bug. Four tools check that. CI runs coverage, a short fuzz of each target and the dependency check on every push; mutation testing takes longer, so run it after larger changes.

**Coverage**: which lines the tests run.

```
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
cargo llvm-cov --summary-only            # a table per file
cargo llvm-cov --html --open             # each line, in the browser
```

About 99% of lines run. The rest is the fallback for a response that fails to serialize, which these types can't do.

**Mutation testing**: makes small changes to the code (flips a `<`, deletes a line, returns a default) and checks that a test fails for each one.

```
cargo install cargo-mutants
cargo mutants                            # about 10 minutes
```

Every change that compiles is caught. The few that can't change behavior are listed with reasons in `.cargo/mutants.toml`.

**Fuzzing**: feeds generated inputs for as long as you let it, steering toward inputs that reach new code. It needs Rust's nightly toolchain, used only for fuzzing.

```
rustup toolchain install nightly
cargo install cargo-fuzz
fuzz/run.sh command_line                 # 10 minutes; add a number of seconds to change that
fuzz/run.sh receiver
fuzz/run.sh tree
```

| Target | Feeds | Checks |
|---|---|---|
| `command_line` | Any input lines, after a valid `init`, starting from the spec's commands and using the protocol's words (`fuzz/seeds`, `fuzz/command_line.dict`) | Every line gets one well-formed response with a short message; no internal error; never halted |
| `receiver` | Correctly signed frames (random ones never pass the tag) in any order, with forgeries, key commands and restarts | No seq accepted twice from a camera, across restarts; no frame accepted on a revoked key, or on a key below one already used; queues stay within `max_pending`; storage writes within budget; no internal error |
| `tree` | Any payload bytes | Decoded trees are within the limits, and rebuilding one from its level-order output and encoding it again gives back exactly the input |

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

The build denies `unsafe` code, panicking calls, slice indexing, unchecked arithmetic and `as` conversions outside tests (see `Cargo.toml`), and release builds keep overflow checks on.
