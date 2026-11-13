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

Start it and type or paste commands; each response prints on the next line. The first command must be `init`. This session, from the project description's examples, sets up the two cameras and then receives one frame from each. The second frame's response pairs the two under `synced`:

```
cargo run --release
{"command":"init","parameters":{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"keys":{"cam1":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","cam2":"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"}}}
{"status":"ok","payload":{"cameras":{"cam1":{"last_seq":null,"last_timestamp":null,"pending":[],"keys":[{"key_id":0,"status":"active"}]},"cam2":{"last_seq":null,"last_timestamp":null,"pending":[],"keys":[{"key_id":0,"status":"active"}]}}}}
{"command":"receive","parameters":{"frame":"01010000000100000000000003e8001f01000000010100000002000001000000030100000004000001000000050000fe04b3dcfd1aa96276d46024a02a89e9125a556fa6a3e1b14628fb7cd4375d82"}}
{"status":"ok","payload":{"frame":{"camera":"cam1","key_id":0,"seq":1,"timestamp":1000,"corrected":false,"tree":[1,2,3,null,null,4,5]},"synced":[]}}
{"command":"receive","parameters":{"frame":"01020000000100000000000003ed00010096af248e74798001df0e27b21440c4b3bf99400f3ea51076772b84dea76ebcc2"}}
{"status":"ok","payload":{"frame":{"camera":"cam2","key_id":0,"seq":1,"timestamp":1005,"corrected":false,"tree":[]},"synced":[{"timestamp":1002,"cam1":1,"cam2":1}]}}
```

To run a file of commands instead, one per line: `cargo run --release < FILE`.

## Demo

```
demo/run.sh          # step by step: press Enter to see each response
demo/run.sh --all    # the whole session at once
```

It plays `demo/session.txt` through the receiver: normal traffic, attacks on the link, key rotation and revocation, and a power loss, using the frames from the project description's examples. The transcript test checks every response in that file, so the demo can't drift from what the receiver does.

Transcripts, the demo session included, are plain text: `# ` lines are comments, `> ` starts a command, and the next line is its expected response: `< ` for the whole response, or `<~ ` for only the fields it lists. To add a test, drop a `.txt` file in `tests/transcripts/`.

## Test

### Tests

`cargo test` runs all of these, in about 10 seconds once built.

| Test | Run with | What it checks | In CI |
|---|---|---|---|
| Unit tests, `src/*.rs` | `cargo test --lib` | Each module, including its boundary values, plus a property test: every random tree within the limits decodes to the right level order | Yes |
| Spec examples, `tests/transcripts.rs` | `cargo test --test transcripts` | The project description's three examples, response by response, and the demo session | Yes |
| Rules, `tests/rules.rs` | `cargo test --test rules` | The order of checks, input rules, error messages, extreme values, and the choices for the spec's open questions on tree limits, rejected payloads and wide pair windows | Yes |
| Keys, `tests/keys.rs` | `cargo test --test keys` | Key rotation, retirement and revocation, and each `add_key` and `revoke_key` error | Yes |
| Restarts, `tests/restart.rs` | `cargo test --test restart` | Each restart rule and the storage write counts, plus a property test: a receiver that restarts never accepts a frame that a twin which never restarts rejects | Yes |
| Reference model, `tests/model.rs` | `cargo test --test model` | Property tests: random command sequences get exactly the responses of a separate, plain implementation of the spec, and random lines and frame bytes never cause an internal error | Yes |
| Safety net, `tests/safety_net.rs` | `cargo test --test safety_net` | A storage fault in the middle of a command gets an internal error, and the receiver rebuilds its memory from storage before the next one | Yes |
| Command line, `tests/cli.rs` | `cargo test --test cli` | The real binary over stdin and stdout | Yes |
| Keys in memory, `tests/memory.rs` | `cargo test --test memory`<br>Linux only: it reads the receiver's memory through `/proc/<pid>/mem`, which macOS doesn't have, so on a Mac `cargo test` skips it | No copy of a retired or revoked key, nor any form HMAC derives from it, and no key text, is left in the running receiver's memory<br>Run as a release build (`--release`), it also checks the stack scrub: right after a frame is checked, the active key is nowhere else. Only a release build leaves a copy of the key on the stack for the scrub to erase | Yes, on Linux |
| Soak, `tests/soak.rs` | `cargo test --test soak` | A long mixed stream through the real binary, including full-size trees and the largest possible frame: every command gets the right kind of response within 10 seconds, memory stays flat after warming up, and it reports commands per second | Yes: 5,000 commands in debug builds, 50,000 in release |

### Tools

Coverage and mutation testing check the tests themselves: which code they run, and whether they'd notice a change to it. Fuzzing looks for inputs the tests don't try, and the dependency check covers the libraries. Run each tool's one-time setup before its first use.

| Tool | One-time setup | Run with | What it checks | In CI |
|---|---|---|---|---|
| Coverage | `rustup component add llvm-tools-preview`<br>`cargo install cargo-llvm-cov` | `cargo llvm-cov --summary-only`, or `cargo llvm-cov --html --open` to see each line | Which lines the tests run; expect about 99% | Yes: reported, with no minimum enforced |
| Mutation testing | `cargo install cargo-mutants` | `scripts/mutants.sh`<br>It runs `cargo mutants`, passing on any options such as `-j 2`, then prints PASS or FAIL for this platform | That every small change to the code (a flipped `<`, a deleted line) makes a test fail; the exceptions, each with a reason, are in `.cargo/mutants.toml`<br>The script counts a TIMEOUT as caught: those mutants make the tests hang, and they're stopped. On macOS it lists four mutants that weaken memory erasure as not checkable there, because only `tests/memory.rs`, which runs on Linux only, can catch them<br>On Linux, the stack scrub's mutants that a normal (debug) build misses are tested again with a release build, which must catch them: only a release build leaves a copy of the key on the stack for the scrub to erase | No: a full run takes about 25 minutes, less with `-j 2` |
| Fuzzing | `rustup toolchain install nightly` (used only for fuzzing)<br>`cargo install cargo-fuzz` | `fuzz/run.sh <target> [seconds]`<br>A failing input is saved in `fuzz/artifacts/<target>/`; replay it with `cargo +nightly fuzz run <target> <file>` | Generated input for the `command_line`, `receiver` and `tree` targets, for as long as you let it (10 minutes by default): no crash, and the invariants hold | Yes: 60 seconds per target |
| Dependencies | `cargo install cargo-deny` | `cargo deny check` | Known vulnerabilities, licenses and sources of every library the receiver is built with, and that the receiver uses only the libraries the spec allows (the allowlist in `deny.toml`) | Yes |

### CI

CI runs on every push and pull request (`.github/workflows/ci.yml`). It runs the tests on Linux and on macOS, each as a debug and a release build, and also checks formatting (`cargo fmt --check`), lints (`cargo clippy`) and the docs (`cargo doc`). Coverage, fuzzing and the dependency check run on Linux only.

### Notes

**Longer runs.** The property tests, the soak test and fuzzing all take a size:

```
PROPTEST_CASES=100000 cargo test --release --test model                 # random cases per property test (default 400)
PROPTEST_CASES=100000 cargo test --release --test restart               # the same for the twin test (default 500)
PROPTEST_CASES=100000 cargo test --release --lib tree                   # the same for the tree test (default 256)
SOAK_COMMANDS=1000000 cargo test --release --test soak -- --nocapture   # commands; prints commands per second
fuzz/run.sh receiver 3600                                               # seconds of fuzzing
```

**Property tests and fuzzing.** Both use random input. A property test builds realistic command sequences from a recipe, checks a rule against every one, and when one fails, shrinks it to the smallest sequence that still fails. Fuzzing mutates raw bytes for as long as you let it, steering toward input that reaches new code.

**Throughput.** `scripts/bench.sh` sends one kind of frame at a time straight through the release binary, three runs each: small frames, the largest frames the receiver accepts (a 1,024-node tree), and the largest frames possible (the tag is checked, then the tree is refused). It reports frames per second and the time per frame. To run just one case, name it: `scripts/bench.sh small_frames`, `largest_accepted_frames` or `largest_possible_frames`. It lives in `tests/bench.rs`, which a plain `cargo test` skips, and takes about half a minute. The figures depend on the machine, so run it on an idle one.

## Layout

```
src/
  lib.rs        the library's modules, and the order of checks for a frame
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
tests/          the tests in the table above, their shared helpers in support/,
                the spec's example transcripts in transcripts/, and the benchmark in bench.rs
fuzz/           fuzz targets, seeds and dictionary (a separate crate)
demo/           the presentation demo: run.sh and the session it plays
docs/           the presentation slides (PDF)
scripts/        mutants.sh: mutation testing, with a pass or fail for this platform
                bench.sh: throughput, one kind of frame at a time
```

## Stages

The project was built in the spec's three stages, and each finished stage is tagged:

| Tag | Stage | What it adds |
|---|---|---|
| `v1-base` | Base problem | `init`, `receive` and `get_state`: authenticated frames, replay protection, timestamp correction and pairing |
| `v2-keys` | Follow-on 1 | Key rotation and revocation: version 2 frames with a key id, `add_key` and `revoke_key` |
| `v3-restart` | Follow-on 2 | `restart` and `persist_interval`: replay protection that survives a restart, within the storage write budget |

`main` builds on `v3-restart` with CI, fuzzing, mutation testing, the fixes from a security review and a code review, the demo, the soak test, tests at the size limits, work buffers reserved once and reused, the throughput benchmark, and rules for AI coding agents (`AGENTS.md`).

```
git checkout v2-keys        # look at a stage; git checkout main to come back
git diff v1-base v2-keys    # what a stage changed
```
