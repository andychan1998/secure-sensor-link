//! Secure Sensor Link: a receiver that decodes, authenticates and
//! time-synchronizes camera frames arriving over a hostile link.
//!
//! Commands arrive as newline-delimited JSON on stdin and each gets one JSON line
//! on stdout; see [`protocol::run`]. A frame passes through the checks in this
//! order, and nothing changes until every check passes:
//!
//! 1. hex, then 2. version, then 3. layout (camera, exact length) — the only
//!    reads before the tag, just enough to pick the key and find the tag;
//! 4. key status (with key rotation);
//! 5. the HMAC-SHA256 tag, compared in constant time;
//! 6. replay (seq above the last accepted);
//! 7. timestamp not negative;
//! 8. the tree, within its size limits;
//! 9. commit: timestamp correction, queues and pairing.

// Tests may use plain arithmetic and string slicing on fixed test data; the
// production code is still checked in the normal (non-test) build.
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::string_slice,
        clippy::unnecessary_wraps,
        clippy::cast_possible_truncation
    )
)]

pub mod camera;
pub mod config;
pub mod frame;
pub mod key;
pub mod protocol;
pub mod receiver;
pub mod sync;
pub mod timeline;
pub mod tree;
