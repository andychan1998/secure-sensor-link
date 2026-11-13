# Secure Sensor Link: Design

**Author:** Andy Chan \
**Date:** November 12, 2026

## Introduction

The Secure Sensor Link project is a receiver that decodes, authenticates, and time-synchronizes camera frames arriving over a hostile link. The project description, not included in this repo, contains the detailed specification. The project setup and execution instructions are in [README.md](README.md). This document focuses on discussing the following topics:

1. [Threat Model](#threat-model)
2. [Security Assurance](#security-assurance)
3. [Frame Check Order](#frame-check-order)
4. [Design Decisions](#design-decisions)
5. [Test Coverage](#test-coverage)
6. [Performance](#performance)
7. [Future Enhancements](#future-enhancements)
8. [AI Usage](#ai-usage)

## Threat Model

### The Attacker

- Can observe, drop, delay, duplicate, reorder, modify, and inject frames.
- Reaches the receiver only through a frame's bytes, which arrive hex-encoded inside a receive command. They can't break out of the JSON, add a command or see the receiver's responses since trusted processes on the node wrap frames into `receive` commands and read the responses.
- Does not know the camera keys, or at least the ones that are still active.

### Assumptions

- Cameras are trusted, but their clocks occasionally produce a bad timestamp. Sequence numbers go up by one per frame, which needs to hold true even across camera reboots.
- The command stream on stdin is trusted. Key management commands arrive over a trusted channel.
- Node memory and storage are trusted. The real hardware should make sure the keys are encrypted or in a secure element. Writes to storage are atomic, durable once a write returns, and protected against rollback.
- The camera clocks agree within `pair_window_ms`, otherwise frames are released unpaired.

### Security Goals

| ID | Goal | Description |
|---|---|---|
| S1 | Authenticity | Only accept frames with a valid tag under an active key |
| S2 | No replay | Don't accept duplicates of genuine frames, even across restarts |
| S3 | Key lifecycle | Retired and revoked keys never verify again, and key IDs only move forward |
| S4 | Key secrecy | Key material is not inadvertently leaked; defense in depth against memory later leaking (e.g. core dump) |
| S5 | Robustness | The receiver must never crash, hang, or let its memory grow without bound, whatever input it receives |
| S6 | Output integrity | Only accepted frames reach the paired output, and every timestamp is computed exactly as the spec requires, with no overflow or wraparound |
| S7 | Atomic state | A rejected or failed command keeps the receiver in a consistent state, and storage is never behind memory |
| S8 | Restart safety | A restart never lets in a frame that an unrestarted receiver would reject as a replay or under an old key, and loses at most `persist_interval` genuine frames per camera |

### Out of Scope

- Hardware-level side channels and fault injection, which need either physical access to the node (power and EM analysis, glitching, laser, EM pulse) or the attacker's own code running on it (Spectre-style speculative execution, Rowhammer).
- Confidentiality of the frame data is not a goal.
- A compromised key that's still active.

### Known Limitations

- A failed memory allocation aborts the process, although memory allocation is kept to a minimum.
- A bad first timestamp puts every later frame from that camera on a wrong timeline.
- A stolen key can push the sequence number to its maximum, which causes all of that camera's later genuine frames to get rejected even after the key is revoked. The node needs to be re-provisioned but currently there isn't a command to do it.
- A stolen key can also cause genuine frames to get corrected onto the attacker's timeline and stop pairing. A restart after revoking a key resets the timeline, but up to `persist_interval` frames per camera can be lost.
- A restart causes up to `persist_interval` frames per camera to be lost.
- A panic during storage write or an unexpected failure during memory change causes the receiver to rebuild memory from storage, the same way `restart` does, which causes up to `persist_interval` frames per camera to be lost.
- A wide pair window lets one frame fall within the window of two frames from the other camera. One dropped frame silently shifts every later pair by one period.
- Revoking a key can cause up to `max_pending` queued frames that were verified with the revoked key to be dropped.
- Revoking a key does not recall frames that were already emitted.
- Key text sits briefly in the operating system's pipe buffer.
- Decoding a key from hex isn't constant time, but the key text only arrives from a trusted channel.

## Security Assurance

### Assurance Layers

| Layer | Explanation |
|---|---|
| By construction | Use of Rust (no `unsafe`), Clippy lints, and release overflow checks for memory safety and prevention of common sources of bugs such as panicking calls, indexing, unchecked arithmetic, `as` casts, and overflow; compiler and CI reject changes that cause regression |
| By design | RawFrame limits visibility into the frame until it becomes VerifiedFrame through verification; read-only reference to the receiver's state until all checks have passed; restricted key copies that erase themselves when dropped; a Config that can only be built with valid values |
| Spec conformance | Tested against all the examples in the project description document |
| Design decisions | One test per rule and decision |
| Independent implementation | Tested against a simplified reference model over random command sequences |
| Coverage-guided fuzzing | Three targets, each asserting invariants on every input |
| Running process | Memory scan for keys and memory growth monitoring |
| Test quality | Mutation testing and coverage analysis |
| Supply chain | Only use libraries allowed by the spec, with checks for known security advisories in the dependencies, their licenses, and where they come from using cargo-deny |
| Review | Security review both by AI and human |
| CI | On every push, runs the tests in debug and release on Linux and macOS; formatting, lints, and docs; coverage; each fuzzer for 60 seconds; cargo-deny  |

### Enforcing the Security Goals

#### S1: Authenticity

Goal: Only accept frames with a valid tag under an active key.

- Tag over every byte of the frame, checked in constant time using RustCrypto's `verify_slice`.
- Key status checked before verification, so a retired or revoked key is never used to verify.
- RawFrame only becomes VerifiedFrame through verification, and the code can't read the sequence number, timestamp, or payload on a RawFrame.

Note: Keys must stay secret. The constant-time `verify_slice` is a property of RustCrypto that's not verified in this repo, but it's mainly for defense in depth as attackers currently do not have a direct way to measure timing.

#### S2: No Replay

Goal: Don't accept duplicates of genuine frames, even across restarts.

- Only accept strictly increasing sequence numbers.
- Restart floor saved before accepting.

#### S3: Key Lifecycle

Goal: Retired and revoked keys never verify again, and key IDs only move forward.

- Key status checked before frame verification, and revoked or retired keys are erased immediately.
- `add_key` refuses IDs below the current key. It also refuses a retired or revoked ID.
- A frame can only move its camera to a higher, active key.
- After a restart, a frame refused only by the restart floor still moves its camera's key forward.
- Every key status change is saved to storage before it takes effect.

Note: A stolen key that's still active is out of scope until revoked.

#### S4: Key Secrecy

Goal: Key material is not inadvertently leaked; defense in depth against memory later leaking (e.g. core dump).

- The receiver reads stdin through its own 64 KiB buffer instead of the standard buffer. It's erased as it's consumed.
- The line buffer is zeroed after every command.
- A key's hex text is decoded right from the line into the key's own memory to avoid additional copies. The key is rejected if it contains any escape sequences to avoid the JSON library creating additional copies.
- Keys erase themselves when dropped. The `hmac` library also wipes its own internal state when the working object is dropped.
- If a key is ever printed, it shows as `Key(redacted)`. Error messages never repeat a string from the input.
- After each command, 64 KiB of zeroes are written over the stack area to clear any temporary key copies on the stack left by the JSON and `hmac` libraries.

Note: The operating system's pipe buffer can still keep a temporary copy of the key text.

#### S5: Robustness

Goal: The receiver must never crash, hang, or let its memory grow without bound, whatever input it receives.

- Lint options to avoid common sources of crashing and build settings to enable overflow checks.
- Panic safety net that catches unexpected panics and returns "internal error" instead.
- Large buffers are allocated once and reused for every command. Strict caps imposed on lines, trees, and queues.
- No recursion, no threads, no locks, and every loop makes progress on bounded input. Worst case is the largest frame with a full tree that releases a full queue, which is still a fixed amount of work.

Note: Receiver can still wait on stdin and stdout, but that's expected behavior.

#### S6: Output Integrity

Goal: Only accepted frames reach the paired output, and every timestamp is computed exactly as the spec requires, with no overflow or wraparound.

- Queues only hold accepted frames, and key revocation drops queued frames with that key ID.
- Timestamp calculations use 128-bit checked arithmetic.

Note: Frames already emitted can't be recalled.

#### S7: Atomic State

Goal: A rejected or failed command keeps the receiver in a consistent state, and storage is never behind memory.

- Everything is verified first with a read-only reference to the receiver's state.
- Storage write, assumed to be atomic, is done before the change in memory.
- A panic during storage write or an unexpected failure during memory change would cause an "internal error". Before the next command, the receiver rebuilds memory from storage, the same way `restart` does.

#### S8: Restart Safety

Goal: A restart never lets in a frame that an unrestarted receiver would reject as a replay or under an old key, and loses at most `persist_interval` genuine frames per camera.

- Before accepting a frame, the receiver saves floor = seq + `persist_interval` to storage if the existing floor is smaller than the new sequence number. The floor is used after a restart to reject frames with sequence numbers at or below the floor. This strategy keeps storage writes within the spec's write budget.
- After a restart, a new frame may get rejected because its sequence number is at or below the floor. However, if the frame is otherwise valid, it can still be used to retire old keys so someone holding an old key can't get a frame accepted.

### Defense Against Attacks

| Attack | Defense |
|---|---|
| Forge or alter a frame without a key | HMAC-SHA256 over the whole frame with constant-time check |
| Replay a captured frame | Sequence number check |
| Replay after a restart | Sequence number at or below the saved floor is rejected |
| Wear out the storage by flooding frames | Frames must pass verification first, and floor writes still stay within the spec's budget |
| Reorder frames | Sequence number is part of signed data; frames at or below the last accepted sequence number are rejected as stale |
| Delay frames | Delayed frames keep their signed timestamps, so the consumer can judge their age |
| Drop frames | Bounded queues; frames released unpaired when no partner can come; with wide pairing windows, one dropped frame can silently shift every later pair by one period |
| Use a retired key captured before a rotation | Key status checked before verification; keys only move forward; after a restart, a frame refused by the floor still switches its camera to its newer key |
| Use a revoked key | Revocation is permanent and causes its queued frames to be dropped with no change to the `last_seq` and timeline |
| Send malformed frames | Strict parsing, no recursion, no panics |
| Exhaust memory or time | Large buffers allocated once and reused; strict caps on the size of lines, trees, and queues; bounded work per command |
| Force an overflow | Checked arithmetic, 128-bit timestamps, and overflow checks |
| Time the tag check | Constant-time comparison as defense in depth, since attackers currently do not have a direct way to measure timing |
| Probe error messages | Messages do not reveal sensitive information |
| Get a misplaced key echoed back | Error messages never repeat a string from the input; keys print as `Key(redacted)` |
| Leave the state half-changed | Commit in one place, with storage first then memory; after an interrupted change, the receiver rebuilds memory from storage, the same way `restart` does |
| Recover keys from memory or dumps | Keys, input buffers and the stack erased |
| Get a forged or revoked-key frame into the paired output | Only accepted frames are queued; revocation drops queued frames |
| Time SHA-256 through the cache | SHA-256 uses only additions, rotations, and XORs, with no tables indexed by secret data |

## Frame Check Order

| Step | What's Checked | Why Here |
|---|---|---|
| 1. Length of frame in hex | Valid hex with an even length of at most 2 x 65,584 | Cheap check to quickly reject oversized frames |
| 2. Version | First byte exists and it's 1 or 2 | The two versions have different header layouts |
| 3. Layout | Frame length >= header + tag; known camera; frame length == header + payload + tag | Nothing is trusted before checking the tag, so verify the minimum needed to perform the tag check |
| 4. Key status | The key ID is provisioned, not revoked, and not retired | A retired or revoked key is never even tried |
| 5. Tag | HMAC-SHA256 over everything before the tag, compared in constant time | Major trust boundary; the frame only becomes a VerifiedFrame after the tag check passes |
| 6. Sequence number | `seq` above the last accepted one; after a restart, also above the restart floor | Forged frames are reported as authentication failures rather than stale or replayed |
| 7. Timestamp | Not negative | Cheap check for spec conformance |
| 8. Tree | Valid encoding with at most 1,024 nodes and 64 levels | The most complex parser runs last, and only on authenticated data |
| 9. Accept | Correct the timestamp if needed, plan the pairing, and finally commit to storage and memory | Final step that actually changes storage and memory states |

Considerations:

- The key status (step 4) is checked before the tag (step 5). Revoked and retired keys are erased, so their tags can't be checked. The trade-off is that anyone who sees responses learns a key's status, as specified in the project description document's example ("cam1 key 0 is retired").
- Sequence number check (step 6) is put after the tag check (step 5). A forged frame is reported as an authentication failure rather than stale or replayed, so whatever reads the responses can detect attackers injecting frames. The trade-off is that rejecting invalid sequence numbers still costs a tag check, but it doesn't really cost anything since an attacker can pick a fresh sequence number to force a tag check anyway.
- Step 6 special case: For a frame below the restart floor, steps 7 and 8 still run. A valid frame that's below the restart floor still moves its camera to a newer key. The frame is still reported as stale either way.

## Design Decisions

### Questions Left to the Implementer

#### Tree Limits

Question: Do you accept trees beyond these limits (1,024 nodes, 64 levels)? Why or why not?

Decision: Reject trees with over 1,024 nodes or 64 levels.

Rationale:
- This gives a bounded worst case still allowed by the spec, at the cost of less flexibility in accepting bigger trees.
- The limits are named constants, so changing them is a one-line change. We can even increase them preemptively if there's a high chance for them to increase in the near future.

#### Valid Tag but Invalid Payload

Question: A frame with a valid tag but an invalid payload is rejected. Should it still count for replay protection?

Decision: Frame is rejected without counting for replay protection.

Rationale:
- This approach avoids breaking the spec's sequence number rules after a restart, which specify that only accepted frames count.
- It also fits the plan-then-commit paradigm cleanly, at the cost that a replay of the bad frame reaches the tree decoder again.
- Invalid payload is an error case, so the design should not optimize for it.

#### Wide Pair Window

Question: What should happen if `pair_window_ms` is wide enough that one frame could be within the window of two frames from the other camera?

Decision: If a frame can potentially pair with more than one frame, then pair it with the oldest first.

Rationale:
- This agrees better with the spec's pairing rules and removes the need for look-ahead complications.
- If 2 x `pair_window_ms` >= `period_ms` - `max_jitter_ms`, one dropped frame silently shifts every later pair by one period, but below that it can't happen.

#### `add_key` with a Provisioned, Revoked or Lower ID

Question: What happens if `add_key` is called with a `key_id` that is already provisioned (or revoked) for that camera, or that is lower than the camera's current key?

Decision:
- Revoked, below the current key ID or same ID with different bytes result in an error.
- Same ID with same bytes succeeds with no change.

Rationale:
- Do not allow operations that could revive a revoked or retired key.
- Do not allow changing an existing key.
- Adding the same key with the same bytes is allowed for idempotent operations (e.g. a power cut loses the reply to an `add_key`).

#### Queued Frames When Their Key Is Revoked

Question: What happens to frames waiting in a queue when the key that authenticated them is revoked?

Decision:
- Dropped without being emitted, but `last_seq` and the timeline stay as they are.
- Frames under a retired key stay.

Rationale:
- Remove possibly forged frames, at the cost of up to `max_pending` queued frames lost.
- Retroactively changing `last_seq` and the timeline goes against the spec's rule on carrying on sequence numbers and timestamp correction across key changes.
- Rolling back `last_seq` could let replays of already-reported frames in.

### Other Questions That Came Up During Implementation

- After a restart, the spec allows dropping only up to `persist_interval` frames past the last accepted frame. It also caps floor writes per camera to 1 + (`S_max` - `S_min`) / `persist_interval`, where `S_max` is the highest sequence number ever accepted and `S_min` is the lowest sequence number ever accepted. The design handles these requirements by saving `floor` = `seq` + `persist_interval` before accepting past it, then writing nothing until a sequence number passes the floor. After a restart, frames with sequence numbers at or below the floor are rejected.
- A frame rejected only by the restart floor but otherwise valid still moves its camera to its newer key, while still reported as stale. This is an exception to the common rule that a rejected frame changes nothing, but it retires an old key faster so someone holding an old key can't get a frame accepted.

## Test Coverage

- The tests achieve 99.33% line coverage. Only three lines are never run, and none of them are real gaps.
- Mutation testing with 300 mutants, 220 caught and the remaining 80 not viable because they can't compile.
- Five property tests (3 in `model.rs`, 1 in `restart.rs` and 1 in `tree.rs`) of 100,000 cases each, all passing.
- Three fuzzing targets (`tree`, `command_line`, `receiver`) for 10 minutes per target, with no failures.
- Soak test of 300,000 commands, with memory staying flat at 4 MB on macOS.

### Run in CI

| Category | Command | Coverage |
|---|---|---|
| Unit tests | `cargo test --lib` | Each module's unit tests |
| Spec examples | `cargo test --test transcripts` | The spec's three worked examples and the demo session |
| Rules and decisions | `cargo test --test rules` | Order of checks, tree limits, valid tag but invalid payload, wide pair window, queue limits, arithmetic at the extremes, command and input rules, and JSON escapes |
| Key rotation and revocation | `cargo test --test keys` | Key IDs and frame versions, retiring keys, `add_key`, `revoke_key`, and dropping queued frames |
| Restarts | `cargo test --test restart` | Restart floor, `persist_interval`, key changes surviving a restart, key rotation under the floor, writes within the budget, and twin property test |
| Reference model | `cargo test --test model` | Random command sequences against a separate, plain model of the spec; random lines never cause an internal error and random frame bytes are rejected cleanly |
| Safety net | `cargo test --test safety_net` | After a panic mid-commit, receiver rebuilds memory from storage, the same way a `restart` does |
| End-to-end | `cargo test --test cli` | End-to-end test cases over stdin and stdout |
| Memory scan (Linux-only) | `cargo test --test memory`, plus `--release` to also catch a missing stack scrub | No copies of retired or revoked keys, key text or any form HMAC derives from them in the memory |
| Soak | `cargo test --test soak` | Correct response to mixed traffic |
| Fuzzing | `fuzz/run.sh <target> 60`, where the target is `tree`, `command_line`, or `receiver` | 60 seconds of fuzzing per target |
| Coverage | `cargo llvm-cov --summary-only` | Runs `cargo test` and reports coverage |
| Dependencies | `cargo deny check` | Known vulnerabilities, licenses, sources, and the spec's allowlist |

### Run on Request

| Category | Command | Coverage |
|---|---|---|
| Throughput benchmark | `scripts/bench.sh` | Frames per second through the release binary |
| Mutation testing | `scripts/mutants.sh -j 2` | Checks that the tests can notice small code changes |
| Longer fuzzing | `fuzz/run.sh <target> [seconds]` (10 minutes by default) | The same three targets as CI for the specified duration |
| More property test cases | `PROPTEST_CASES=100000 cargo test --release --test model` (or `--test restart`, `--lib tree`) |  The same five properties with more random cases |
| Soak stress run | `SOAK_COMMANDS=300000 cargo test --release --test soak -- --nocapture` | The same soak test with more commands |
| Detailed coverage | `cargo llvm-cov --html --open` and `cargo +nightly llvm-cov --branch --summary-only` | Line-by-line coverage report and branch coverage |

## Performance

Here's the throughput collected on a MacBook Pro with Apple M1 Pro chip and 16 GB of memory. As a comparison, the spec's worst case is two cameras at 1 ms, which is 2,000 frames per second.

| Frames | Size | Frames per second | &micro;s per frame | Command |
|---|---|---|---|---|
| Small (one-node tree) | 55 bytes | 41,000 - 43,000 | 23 - 24 | `scripts/bench.sh small_frames` |
| Largest accepted (1,024-node tree) | 6,193 bytes | 11,000 - 15,000 | 68 - 89 | `scripts/bench.sh largest_accepted_frames` |
| Largest possible (tag checked, tree refused) | 65,583 bytes | 2,200 - 3,100 | 320 - 450 | `scripts/bench.sh largest_possible_frames` |

Memory usage (measured with `SOAK_COMMANDS=300000 cargo test --release --test soak -- --nocapture`) is about 4 MB resident on Mac, flat over 300,000 commands. Peak heap is 656 KiB at `max_pending` 1,024 (measured with valgrind massif on Linux), most of it reserved once at startup or `init`.

## Future Enhancements

- At the spec's minimum `period_ms` of 1, the 32-bit sequence number runs out in about 49.7 days (6.8 years at the project document's example period of 50 ms). Once the maximum is reached, no more frames can be accepted from that camera. One possible solution is to create a new frame version that supports 64-bit sequence numbers.
- A stolen key could push the sequence number to the maximum, and currently there's no way to re-provision the receiver. This problem can be overcome by changing the protocol to allow sequence numbering per key instead. Another potential solution is to add a re-provisioning command that resets a camera's state.
- Currently, the spec allows `pair_window_ms` up to `period_ms` - 1. Restrict the pairing window size such that 2 x `pair_window_ms` < `period_ms` - `max_jitter_ms` to remove ambiguity that can happen when one frame can pair with multiple frames from the other camera.
- If we were to deploy this in real-life scenarios, there would be additional requirements that are important, such as defending against attackers with physical access to the node, a freshness check of camera time against the node's clock, recovering a camera whose counter restarts, and counting or alerting on authentication failures.

## AI Usage

Claude was used to write the code, tests, scripts, README.md, AGENTS.md, CLAUDE.md and presentation. I made or approved all the design decisions and reviewed everything Claude produced. This design document was written manually, with AI used only for grammar, research and feedback.
