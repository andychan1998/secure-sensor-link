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
| `init` | Sets the timing limits and each camera's key 0. Must come first, once. |
| `receive` | Checks one frame (version 1, or version 2 with a key id) and returns it with any newly paired frames. |
| `get_state` | Returns each camera's last frame, waiting frames and keys. |
| `add_key` | Provisions a new key id for a camera. Re-adding the same key is a no-op. |
| `revoke_key` | Revokes a key id at once; waiting frames that used it are dropped. |

A camera moves to a key when a frame under it is accepted, and every lower key is then retired. A retired or revoked key id can never be used or provisioned again.

## Test

```
cargo test                  # everything, a few seconds
cargo test --test rules     # the receiver's rules and design decisions
cargo test --test keys      # key rotation and revocation
cargo test --test model     # random command sequences against a reference model
```

| Tests | Where | What they show |
|---|---|---|
| Spec examples | `tests/transcripts/spec/` | The project description's examples, response by response |
| Rules and decisions | `tests/rules.rs` | Order of checks, rejected frames change nothing, strict input, extreme values |
| Keys | `tests/keys.rs` | Rotation, retirement and revocation, and each `add_key` / `revoke_key` error |
| Reference model | `tests/model.rs` | Random sequences of valid, forged, replayed and malformed frames, key additions and revocations give exactly the responses and state of a separate, plain implementation of the spec; arbitrary bytes never cause an internal error |
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
  keyring.rs    each camera's keys: active, retired or revoked
  frame.rs      the wire format, versions 1 and 2: RawFrame (untrusted) -> VerifiedFrame (tag checked)
  tree.rs       the payload tree: non-recursive decoder with size limits, level-order output
  receiver.rs   checks a frame in order, then commits its effects
  timeline.rs   timestamp correction, in exact 128-bit arithmetic
  sync.rs       per-camera queues and pairing
  camera.rs     the two cameras, and one value per camera
tests/          transcripts, rules, keys, reference model, command line
```

The build denies `unsafe` code, panicking calls, slice indexing, unchecked arithmetic and `as` conversions outside tests (see `Cargo.toml`), and release builds keep overflow checks on.
