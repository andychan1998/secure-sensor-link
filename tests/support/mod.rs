//! Helpers shared by the integration tests: signed frame building, command lines
//! and a session that returns parsed responses.

#![allow(
    dead_code,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    unreachable_pub
)]

use hmac::{Hmac, KeyInit, Mac};
use secure_sensor_link::protocol::Session;
use serde_json::{Value, json};
use sha2::Sha256;

/// The spec's example keys.
pub const KEY1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
pub const KEY2: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// The key hex for a camera number (1 or 2).
pub fn key_for(camera: u8) -> &'static str {
    if camera == 2 { KEY2 } else { KEY1 }
}

/// A frame, built field by field so tests can make any of them wrong. Version 1
/// by default; [`Frame::v2`] switches to version 2 with a key id.
#[derive(Clone, Debug)]
pub struct Frame {
    pub version: u8,
    pub camera: u8,
    /// Written only in version 2 frames.
    pub key_id: u8,
    pub seq: u32,
    pub timestamp: i64,
    pub payload: Vec<u8>,
    /// Overrides the `payload_len` field; `None` means the real length.
    pub payload_len: Option<u16>,
    pub key: String,
}

impl Frame {
    /// A valid frame from `camera` (1 or 2) carrying the empty tree.
    pub fn new(camera: u8, seq: u32, timestamp: i64) -> Self {
        Self {
            version: 1,
            camera,
            key_id: 0,
            seq,
            timestamp,
            payload: EMPTY_TREE.to_vec(),
            payload_len: None,
            key: key_for(camera).to_owned(),
        }
    }

    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    /// A version 2 frame using `key_id`, signed with `key`.
    pub fn v2(mut self, key_id: u8, key: &str) -> Self {
        self.version = 2;
        self.key_id = key_id;
        key.clone_into(&mut self.key);
        self
    }

    pub fn key(mut self, key: &str) -> Self {
        key.clone_into(&mut self.key);
        self
    }

    /// The header and payload: the bytes the tag covers.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let payload_len = self
            .payload_len
            .unwrap_or_else(|| u16::try_from(self.payload.len()).unwrap());
        let mut bytes = vec![self.version, self.camera];
        if self.version == 2 {
            bytes.push(self.key_id);
        }
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// The complete frame: signed bytes plus a valid tag for `key`.
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = self.signed_bytes();
        let key = hex::decode(&self.key).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
        mac.update(&bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        bytes
    }

    pub fn hex(&self) -> String {
        hex::encode(self.bytes())
    }
}

/// The empty tree.
pub const EMPTY_TREE: [u8; 1] = [0x00];

/// A tree with one node holding `value`.
pub fn leaf(value: i32) -> Vec<u8> {
    let mut bytes = vec![0x01];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes.extend_from_slice(&[0x00, 0x00]);
    bytes
}

/// An `init` line with the spec's keys.
pub fn init_line(period: u64, jitter: u64, window: u64, max_pending: u64) -> String {
    json!({
        "command": "init",
        "parameters": {
            "period_ms": period,
            "max_jitter_ms": jitter,
            "pair_window_ms": window,
            "max_pending": max_pending,
            "keys": {"cam1": KEY1, "cam2": KEY2},
        }
    })
    .to_string()
}

pub fn receive_line(frame_hex: &str) -> String {
    json!({"command": "receive", "parameters": {"frame": frame_hex}}).to_string()
}

pub const GET_STATE: &str = r#"{"command":"get_state","parameters":{}}"#;

pub fn add_key_line(camera: &str, key_id: u64, key: &str) -> String {
    json!({"command": "add_key", "parameters": {"camera": camera, "key_id": key_id, "key": key}})
        .to_string()
}

pub fn revoke_key_line(camera: &str, key_id: u64) -> String {
    json!({"command": "revoke_key", "parameters": {"camera": camera, "key_id": key_id}}).to_string()
}

/// A session that hands back each response as JSON.
#[derive(Default)]
pub struct Harness {
    session: Session,
}

impl Harness {
    /// A session already initialized with the spec's example configuration.
    pub fn spec_config() -> Self {
        let mut harness = Self::default();
        harness.ok(&init_line(50, 5, 20, 4));
        harness
    }

    pub fn send(&mut self, line: &str) -> Value {
        serde_json::to_value(self.session.handle_line(line.as_bytes())).unwrap()
    }

    /// Sends a line and returns its payload, failing the test on an error.
    pub fn ok(&mut self, line: &str) -> Value {
        let response = self.send(line);
        assert_eq!(response["status"], "ok", "{line} -> {response}");
        response["payload"].clone()
    }

    /// Sends a line and returns its error message, failing the test on success.
    pub fn error(&mut self, line: &str) -> String {
        let response = self.send(line);
        assert_eq!(response["status"], "error", "{line} -> {response}");
        response["payload"]["message"].as_str().unwrap().to_owned()
    }

    pub fn state(&mut self) -> Value {
        self.ok(GET_STATE)
    }
}
