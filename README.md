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

The receiver reads one JSON command per line on stdin and writes one JSON response per line on stdout. The commands, their parameters and their responses are defined in the project description, which isn't included in this repository; `demo/session.txt` has a worked example of each command.

Start it and type or paste commands; each response prints right away. The first command must be `init`, such as this one from the project description:

```
cargo run --release
{"command":"init","parameters":{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"keys":{"cam1":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","cam2":"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"}}}
{"command":"get_state","parameters":{}}
```

To run a file of commands instead, one per line: `cargo run --release < FILE`.

## Demo

```
demo/run.sh          # step by step: press Enter to see each response
demo/run.sh --all    # the whole session at once
```

It plays `demo/session.txt` through the receiver: normal traffic, attacks on the link, key rotation and revocation, and a power loss, using the frames from the project description's examples. The transcript test checks every response in that file, so the demo can't drift from what the receiver does.

## Test

### Tests

`cargo test` runs all of these, in a few seconds.

| Test | Run with | What it checks | In CI |
|---|---|---|---|
| Unit tests, `src/*.rs` | `cargo test --lib` | Each module, including every boundary value | Yes |
| Spec examples, `tests/transcripts.rs` | `cargo test --test transcripts` | The project description's three examples, response by response, and the demo session | Yes |
| Rules, `tests/rules.rs` | `cargo test --test rules` | The order of checks, input rules, error messages, extreme values, and the choices for the spec's open questions on tree limits, rejected payloads and wide pair windows | Yes |
| Keys, `tests/keys.rs` | `cargo test --test keys` | Key rotation, retirement and revocation, and each `add_key` and `revoke_key` error | Yes |
| Restarts, `tests/restart.rs` | `cargo test --test restart` | Each restart rule and the storage write counts, plus a property test: a receiver that restarts never accepts a frame that a twin which never restarts rejects | Yes |
| Reference model, `tests/model.rs` | `cargo test --test model` | Property tests: random command sequences get exactly the responses of a separate, plain implementation of the spec, and random lines and frame bytes never cause an internal error | Yes |
| Safety net, `tests/safety_net.rs` | `cargo test --test safety_net` | A storage fault in the middle of a command halts the receiver, and a restart recovers it | Yes |
| Command line, `tests/cli.rs` | `cargo test --test cli` | The real binary over stdin and stdout | Yes |
| Keys in memory, `tests/memory.rs` | `cargo test --test memory`, on Linux only | No copy of a retired or revoked key, and no key text, is left in the running receiver's memory | Yes, on Linux |
| Soak, `tests/soak.rs` | `cargo test --test soak` | A long mixed stream through the real binary: every command gets the right kind of response within 10 seconds, memory stays flat after warming up, and it reports commands per second | Yes: 5,000 commands in debug builds, 50,000 in release |

### Tools that check the tests

These check that the tests would catch a bug, and that the dependencies are sound. Each needs a one-time setup first.

| Tool | Run with | What it checks | In CI |
|---|---|---|---|
| Coverage | One-time setup: `rustup component add llvm-tools-preview` and `cargo install cargo-llvm-cov`<br>Then: `cargo llvm-cov --summary-only`, or `cargo llvm-cov --html --open` to see each line | Which lines the tests run; expect about 99% | Yes |
| Mutation testing | One-time setup: `cargo install cargo-mutants`<br>Then: `cargo mutants` | That every small change to the code (a flipped `<`, a deleted line) makes a test fail; the exceptions, each with a reason, are in `.cargo/mutants.toml` | No: it takes about 10 minutes |
| Fuzzing | One-time setup: `rustup toolchain install nightly` (used only for fuzzing) and `cargo install cargo-fuzz`<br>Then: `fuzz/run.sh <target> [seconds]` | Generated input for the `command_line`, `receiver` and `tree` targets, for as long as you let it (10 minutes by default): no crash, and the invariants hold | Yes: 60 seconds per target |
| Dependencies | One-time setup: `cargo install cargo-deny`<br>Then: `cargo deny check` | Known vulnerabilities, licenses and sources of every dependency, and that the receiver uses only the libraries the spec allows (the allowlist in `deny.toml`) | Yes |

### CI

CI runs on every push and pull request (`.github/workflows/ci.yml`). It runs the tests on Linux and on macOS, each as a debug and a release build, and also checks formatting (`cargo fmt --check`), lints (`cargo clippy`) and the docs (`cargo doc`).

### Notes

**Longer runs.** The property tests, the soak test and fuzzing all take a size:

```
PROPTEST_CASES=100000 cargo test --release --test model                  # random cases per property test (default 400)
SOAK_COMMANDS=1000000 cargo test --release --test soak -- --nocapture   # commands; prints commands per second
fuzz/run.sh receiver 3600                                                # seconds of fuzzing
```

**Property tests and fuzzing.** Both use random input. A property test builds realistic command sequences from a recipe, checks a rule against every one, and when one fails, shrinks it to the smallest sequence that still fails. Fuzzing mutates raw bytes for as long as you let it, steering toward input that reaches new code.

**Why `tests/memory.rs` runs only on Linux.** It reads the running receiver's memory through `/proc/<pid>/mem`, which only Linux has. On macOS, reading another process's memory needs root or a debugging entitlement, and system calls that the crate's ban on `unsafe` code rules out. On a Mac, `cargo test` skips it.

**Transcripts** are plain text: `> ` starts a command, and the next line is its expected response (`< ` exact, `<~ ` partial). To add a test, drop a `.txt` file in `tests/transcripts/`.

A failing fuzz input is saved in `fuzz/artifacts/<target>/`; `cargo +nightly fuzz run <target> <file>` replays it.

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
