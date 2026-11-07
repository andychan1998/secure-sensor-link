# secure-sensor-link

A receiver that decodes, authenticates, and time-synchronizes camera frames arriving over a hostile link. Written in Rust, using only the standard library plus `serde_json`, `hex`, and `hmac` + `sha2`.

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

## Test

```
cargo test                  # everything, a few seconds
cargo test --test rules     # the receiver's rules and design decisions
cargo test --test model     # random command sequences against a reference model
```

| Tests | Where | What they show |
|---|---|---|
| Spec examples | `tests/transcripts/spec/` | The project description's examples, response by response |
| Rules and decisions | `tests/rules.rs` | Order of checks, rejected frames change nothing, strict input, extreme values |
| Reference model | `tests/model.rs` | Random sequences of valid, forged, replayed and malformed frames give exactly the responses and state of a separate, plain implementation of the spec; arbitrary bytes never cause an internal error |
| Command line | `tests/cli.rs` | The real binary over stdin and stdout |
| Unit tests | `src/*.rs` | Each module, including every boundary value |

Transcripts are plain text: `> ` starts a command, and the next line is its expected response (`< ` exact, `<~ ` partial). To add a test, drop a `.txt` file in `tests/transcripts/`.

### Checking the tests themselves

```
cargo install cargo-mutants cargo-llvm-cov cargo-deny
rustup component add llvm-tools-preview

cargo mutants               # makes small changes to the code and checks the tests catch each one
cargo llvm-cov              # line and region coverage
cargo deny check            # known vulnerabilities, licenses and sources of every dependency
```

## Layout

```
src/
  main.rs       connects stdin and stdout to the protocol
  protocol.rs   bounded line reading, strict JSON commands, responses, panic safety net
  config.rs     init parameters, validated
  key.rs        32-byte keys that erase themselves and never print
  frame.rs      the wire format: RawFrame (untrusted) -> VerifiedFrame (tag checked)
  tree.rs       the payload tree: non-recursive decoder with size limits, level-order output
  receiver.rs   checks a frame in order, then commits its effects
  timeline.rs   timestamp correction, in exact 128-bit arithmetic
  sync.rs       per-camera queues and pairing
  camera.rs     the two cameras, and one value per camera
tests/          transcripts, rules, reference model, command line
```

The build denies `unsafe` code, panicking calls, slice indexing, unchecked arithmetic and `as` conversions outside tests (see `Cargo.toml`), and release builds keep overflow checks on.
