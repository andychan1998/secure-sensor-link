//! Correctly signed frames in any order, mixed with forgeries, key commands and
//! restarts, straight into the receiver. Random bytes almost never carry a
//! valid tag, so this target signs its frames to reach everything past
//! authentication: replay, timestamps, trees, pairing, keys and restarts.
//!
//! After every step it checks:
//! - nothing reaches an internal error or halts the receiver;
//! - no seq is ever accepted twice from a camera, across any restarts;
//! - a revoked key never gets a frame accepted;
//! - once a camera has a frame accepted on a key, it never gets one accepted
//!   on a lower key;
//! - queues never hold more than `max_pending` frames;
//!
//! and at the end, that storage writes stayed within the spec's budget.

#![no_main]

use std::collections::BTreeSet;

use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use secure_sensor_link::camera::{Camera, PerCamera};
use secure_sensor_link::config::{Config, ConfigInput};
use secure_sensor_link::key::{Key, KeyId};
use secure_sensor_link::receiver::Receiver;
use secure_sensor_link::storage::MemoryStore;
use sha2::Sha256;

#[derive(Arbitrary, Debug)]
struct Input {
    period_ms: u16,
    max_jitter_ms: u16,
    pair_window_ms: u16,
    max_pending: u8,
    persist_interval: u32,
    ops: Vec<Op>,
}

#[derive(Arbitrary, Debug)]
enum Op {
    Frame(FrameOp),
    AddKey { cam2: bool, key_id: u8 },
    Revoke { cam2: bool, key_id: u8 },
    Restart,
}

#[derive(Arbitrary, Debug)]
struct FrameOp {
    cam2: bool,
    /// Version 1 frames always use key 0.
    version_2: bool,
    key_id: u8,
    seq: u32,
    timestamp: i64,
    payload: Payload,
    /// Signed with a key that isn't the camera's.
    forged: bool,
}

#[derive(Arbitrary, Debug)]
enum Payload {
    Empty,
    Leaf(i32),
    Raw(Vec<u8>),
}

/// The bytes of camera `cam` (0 or 1)'s key `id`.
fn key_bytes(cam: u8, id: u8) -> [u8; 32] {
    let mut key = [0x5a; 32];
    key[0] = cam;
    key[1] = id;
    key
}

fn key(cam: u8, id: u8) -> Key {
    Key::from_hex(&hex::encode(key_bytes(cam, id))).expect("64 hex characters")
}

fn frame_hex(op: &FrameOp) -> String {
    let cam = u8::from(op.cam2);
    let key_id = if op.version_2 { op.key_id } else { 0 };
    let mut payload = match &op.payload {
        Payload::Empty => vec![0x00],
        Payload::Leaf(value) => {
            let mut leaf = vec![0x01];
            leaf.extend_from_slice(&value.to_be_bytes());
            leaf.extend_from_slice(&[0x00, 0x00]);
            leaf
        }
        Payload::Raw(bytes) => bytes.clone(),
    };
    payload.truncate(usize::from(u16::MAX));
    let mut frame = vec![if op.version_2 { 0x02 } else { 0x01 }, cam + 1];
    if op.version_2 {
        frame.push(key_id);
    }
    frame.extend_from_slice(&op.seq.to_be_bytes());
    frame.extend_from_slice(&op.timestamp.to_be_bytes());
    let len = u16::try_from(payload.len()).expect("truncated above");
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut signing_key = key_bytes(cam, key_id);
    if op.forged {
        signing_key[31] ^= 1;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key).expect("any key length");
    mac.update(&frame);
    frame.extend_from_slice(&mac.finalize().into_bytes());
    hex::encode(frame)
}

/// What the harness knows about one camera, independently of the receiver.
#[derive(Default)]
struct Seen {
    /// Every seq accepted, across restarts.
    accepted: BTreeSet<u32>,
    /// The highest key id an accepted frame used.
    highest_key: Option<u8>,
    revoked: BTreeSet<u8>,
}

fuzz_target!(|input: Input| {
    let period_ms = u64::from(input.period_ms % 60_000) + 1;
    let config = Config::new(ConfigInput {
        period_ms,
        max_jitter_ms: u64::from(input.max_jitter_ms) % period_ms,
        pair_window_ms: u64::from(input.pair_window_ms) % period_ms,
        max_pending: u64::from(input.max_pending % 8) + 1,
        persist_interval: Some(u64::from(input.persist_interval.max(1))),
    })
    .expect("values in range");
    let mut receiver = Receiver::new(
        config,
        PerCamera::new(key(0, 0), key(1, 0)),
        MemoryStore::default(),
    )
    .expect("memory storage never fails");
    let mut seen = [Seen::default(), Seen::default()];

    for op in &input.ops {
        match op {
            Op::Frame(frame) => {
                let result = receiver.receive(&frame_hex(frame));
                let cam = &mut seen[usize::from(frame.cam2)];
                match result {
                    Err(error) => assert_ne!(error.to_string(), "internal error"),
                    Ok(accepted) => {
                        let key_id = accepted.key_id.0;
                        assert!(!frame.forged, "a forged frame was accepted");
                        assert!(
                            cam.accepted.last().is_none_or(|&last| accepted.seq > last),
                            "seq {} accepted after {:?}",
                            accepted.seq,
                            cam.accepted.last()
                        );
                        assert!(!cam.revoked.contains(&key_id), "revoked key {key_id} used");
                        assert!(
                            cam.highest_key.is_none_or(|highest| key_id >= highest),
                            "key {key_id} accepted after key {:?}",
                            cam.highest_key
                        );
                        cam.accepted.insert(accepted.seq);
                        cam.highest_key = Some(key_id);
                    }
                }
            }
            Op::AddKey { cam2, key_id } => {
                let camera = if *cam2 { Camera::Cam2 } else { Camera::Cam1 };
                if let Err(error) =
                    receiver.add_key(camera, KeyId(*key_id), key(u8::from(*cam2), *key_id))
                {
                    assert_ne!(error.to_string(), "internal error");
                }
            }
            Op::Revoke { cam2, key_id } => {
                let camera = if *cam2 { Camera::Cam2 } else { Camera::Cam1 };
                match receiver.revoke_key(camera, KeyId(*key_id)) {
                    Ok(()) => {
                        seen[usize::from(*cam2)].revoked.insert(*key_id);
                    }
                    Err(error) => assert_ne!(error.to_string(), "internal error"),
                }
            }
            Op::Restart => receiver.restart().expect("storage was written at init"),
        }
        assert!(!receiver.is_halted());
        let state = receiver.state();
        for camera in Camera::ALL {
            assert!(state.cameras.get(camera).pending.len() <= config.max_pending());
        }
    }

    let interval = u64::from(config.persist_interval());
    for (cam, camera) in Camera::ALL.into_iter().enumerate() {
        let writes = *receiver.store().writes().floors.get(camera);
        let budget = match (seen[cam].accepted.first(), seen[cam].accepted.last()) {
            (Some(&min), Some(&max)) => 1 + u64::from(max - min) / interval,
            _ => 0,
        };
        assert!(
            writes <= budget,
            "{camera:?}: {writes} floor writes, budget {budget}"
        );
    }
});
