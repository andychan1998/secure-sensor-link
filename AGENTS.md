# AGENTS.md

Rules for AI coding agents working in this repository. README.md has the setup,
commands and layout; DESIGN.md explains the design and the reasons behind it.

## Hard rules

- Don't write or edit DESIGN.md. The project allows AI tooling everywhere
  except the writing of the design doc itself. Review comments are fine;
  replacement text is not.
- Don't add the project description (the spec) to the repository.
- No `unsafe` code. `unsafe_code = "forbid"` makes it a compile error.
- No new dependencies. The receiver may use only the JSON, hex and HMAC-SHA256
  libraries the spec allows; `deny.toml` holds the allowlist.
- Don't weaken the lints. In production code, a lint exception is
  `#[expect(lint, reason = "...")]`, never `#[allow]`.
- Changes to `.github/workflows/`, `.cargo/`, `deny.toml` or the lint settings in
  `Cargo.toml` need the owner's approval first.
- Never push. Commit only when asked.

## Before calling a change done

```
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --locked --release
cargo deny check                      # if anything about dependencies changed
```

For a change to parsing, the frame checks or the receiver's state, also run the
matching fuzz target (`fuzz/run.sh command_line|receiver|tree 600`) and mutation
testing on the change (`git diff > /tmp/change.diff`, then
`scripts/mutants.sh --in-diff /tmp/change.diff`). `tests/memory.rs` runs on Linux
only; a change to key handling or erasure needs a Linux run.

## Invariants to keep

- **Order of checks:** hex, version, layout, key status, tag, replay, timestamp,
  tree, then commit (see `src/lib.rs`). Nothing reads a frame's seq, timestamp or
  payload before its tag passes: `RawFrame` to `VerifiedFrame` is the only path.
- **A rejected frame changes nothing.** `Receiver::plan` gets memory read-only.
  Every effect happens in the commit: storage first, then memory, with the
  commit-in-progress flag set. The one exception is the key move for a frame
  refused only by the restart floor.
- **Restarts:** the floor (seq + `persist_interval`) is saved before accepting a
  seq past it, and floor writes per camera stay within the spec's budget.
- **Keys:** `Key` has no `Clone`; copies only through `Key::duplicate`, and every
  copy erases itself when dropped. Keys are decoded straight from the input line,
  and escaped key strings are refused. Key text never goes into a `String`, a log
  or a message.
- **Errors never repeat a string from the input.**
- **Bounded work and memory:** no recursion; caps on line length (256 KiB), trees
  (1,024 nodes, 64 levels) and queues (`max_pending`); the per-frame work buffers
  are reserved once at `init`, so don't allocate per frame.
- **Arithmetic:** checked everywhere; timestamps are 128-bit (`Millis`).

## Tests

- A new rule or decision gets its own test, in the matching file under `tests/`.
- A change in behavior is mirrored in the reference model in `tests/model.rs`.
- The spec's examples in `tests/transcripts/` must keep passing exactly.

## Style

- Idiomatic Rust. Comments and doc comments say why, in plain words.
- Error messages are short, specific, and don't echo input.
