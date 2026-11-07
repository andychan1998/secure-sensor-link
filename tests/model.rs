//! Random tests against a reference model.
//!
//! The model below is a deliberately plain, separate implementation of the
//! spec's rules (keys, replay, restarts, timestamp correction, pairing) with
//! none of the receiver's structure. Random command sequences go to both, and after every
//! command the response and the full state must agree. Along the way this
//! checks that a rejected frame changes nothing, queues never exceed
//! `max_pending`, and every accepted frame ends up paired, unpaired or pending.
//!
//! A second test throws arbitrary bytes at the protocol: every line must get
//! exactly one response, and none may be an internal error (which would mean a
//! caught panic).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::string_slice
)]

mod support;

use std::collections::{BTreeMap, VecDeque};

use proptest::prelude::*;
use serde_json::{Value, json};
use support::{
    Frame, Harness, KEY1, KEY2, RESTART, add_key_line, init_line, leaf, receive_line,
    revoke_key_line,
};

// ---- The reference model ----

#[derive(Clone, Debug)]
struct ModelConfig {
    period: i128,
    jitter: i128,
    window: i128,
    max_pending: usize,
    interval: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Status {
    Active,
    Retired,
    Revoked,
}

#[derive(Clone, Debug)]
struct ModelKey {
    hex: String,
    status: Status,
}

#[derive(Clone, Debug)]
struct Model {
    last: [Option<(u32, i128)>; 2],
    /// Waiting frames: seq, corrected timestamp, key id.
    queues: [VecDeque<(u32, i128, u8)>; 2],
    keys: [BTreeMap<u8, ModelKey>; 2],
    current: [Option<u8>; 2],
    /// The replay floor in storage, and the one loaded at the last restart.
    saved: [Option<u64>; 2],
    loaded: [Option<u64>; 2],
}

/// A key that is never provisioned for any camera or key id.
const WRONG_KEY: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// The key the tests provision for `cam` (0 or 1) under `id`; `alt` gives a
/// different key for the same id.
fn key_hex(cam: usize, id: u8, alt: bool) -> String {
    if id == 0 && !alt {
        return if cam == 0 { KEY1 } else { KEY2 }.to_owned();
    }
    let byte = u8::try_from(cam).unwrap() * 64 + id * 2 + u8::from(alt) + 1;
    format!("{byte:02x}").repeat(32)
}

impl Default for Model {
    fn default() -> Self {
        let initial = |cam| {
            BTreeMap::from([(
                0,
                ModelKey {
                    hex: key_hex(cam, 0, false),
                    status: Status::Active,
                },
            )])
        };
        Self {
            last: [None, None],
            queues: [VecDeque::new(), VecDeque::new()],
            keys: [initial(0), initial(1)],
            current: [None, None],
            saved: [None, None],
            loaded: [None, None],
        }
    }
}

/// What the model expects a frame to produce.
#[derive(Debug, PartialEq)]
struct Outcome {
    timestamp: i128,
    corrected: bool,
    records: Vec<Value>,
}

impl Model {
    /// The spec's rules, written as directly as possible. `cam` is 0 or 1.
    #[allow(clippy::too_many_arguments)]
    fn receive(
        &mut self,
        cfg: &ModelConfig,
        cam: usize,
        key_id: u8,
        seq: u32,
        raw: i64,
        tag_ok: bool,
        tree_ok: bool,
    ) -> Option<Outcome> {
        match self.keys[cam].get(&key_id) {
            Some(ModelKey {
                status: Status::Active,
                ..
            }) => {}
            _ => return None,
        }
        if !tag_ok {
            return None;
        }
        if let Some((last_seq, _)) = self.last[cam]
            && seq <= last_seq
        {
            return None;
        }
        let valid = raw >= 0 && tree_ok;
        if self.loaded[cam].is_some_and(|floor| u64::from(seq) <= floor) {
            // Maybe a replay from before the restart: rejected, but a frame
            // that would otherwise be accepted still moves the camera's key.
            if valid {
                self.use_key(cam, key_id);
            }
            return None;
        }
        if !valid {
            return None;
        }
        if self.saved[cam].is_none_or(|floor| u64::from(seq) > floor) {
            self.saved[cam] = Some(u64::from(seq) + cfg.interval);
        }
        let raw = i128::from(raw);
        let (timestamp, corrected) = match self.last[cam] {
            None => (raw, false),
            Some((s, t)) => {
                let expected = t + i128::from(seq - s) * cfg.period;
                if (raw - expected).abs() > cfg.jitter {
                    (expected, true)
                } else {
                    (raw, false)
                }
            }
        };
        self.last[cam] = Some((seq, timestamp));
        self.use_key(cam, key_id);
        self.queues[cam].push_back((seq, timestamp, key_id));

        let mut records = Vec::new();
        let record = |ts: i128, c1: Option<u32>, c2: Option<u32>| json!({"timestamp": ts, "cam1": c1, "cam2": c2});
        while !self.queues[0].is_empty() && !self.queues[1].is_empty() {
            let (s1, t1, _) = self.queues[0][0];
            let (s2, t2, _) = self.queues[1][0];
            if (t1 - t2).abs() <= cfg.window {
                self.queues[0].pop_front();
                self.queues[1].pop_front();
                records.push(record((t1 + t2).div_euclid(2), Some(s1), Some(s2)));
            } else if t1 < t2 {
                self.queues[0].pop_front();
                records.push(record(t1, Some(s1), None));
            } else {
                self.queues[1].pop_front();
                records.push(record(t2, None, Some(s2)));
            }
        }
        for c in 0..2 {
            if self.queues[c].len() > cfg.max_pending {
                let (s, t, _) = self.queues[c].pop_front().unwrap();
                records.push(if c == 0 {
                    record(t, Some(s), None)
                } else {
                    record(t, None, Some(s))
                });
            }
        }
        Some(Outcome {
            timestamp,
            corrected,
            records,
        })
    }

    fn use_key(&mut self, cam: usize, key_id: u8) {
        if self.current[cam].is_none_or(|current| key_id > current) {
            self.current[cam] = Some(key_id);
            for (_, key) in self.keys[cam].range_mut(..key_id) {
                if key.status == Status::Active {
                    key.status = Status::Retired;
                }
            }
        }
    }

    /// Power loss: only keys and floors survive.
    fn restart(&mut self) {
        self.last = [None, None];
        self.queues = [VecDeque::new(), VecDeque::new()];
        self.loaded = self.saved;
    }

    /// Q4: `add_key`. Returns whether it succeeds.
    fn add_key(&mut self, cam: usize, id: u8, hex: &str) -> bool {
        if let Some(key) = self.keys[cam].get(&id) {
            return key.status == Status::Active && key.hex == hex;
        }
        if self.current[cam].is_some_and(|current| id < current) {
            return false;
        }
        self.keys[cam].insert(
            id,
            ModelKey {
                hex: hex.to_owned(),
                status: Status::Active,
            },
        );
        true
    }

    /// `revoke_key`, with Q5: queued frames that used the key are dropped.
    fn revoke_key(&mut self, cam: usize, id: u8) -> bool {
        let Some(key) = self.keys[cam].get_mut(&id) else {
            return false;
        };
        key.status = Status::Revoked;
        self.queues[cam].retain(|(_, _, k)| *k != id);
        true
    }

    fn state(&self) -> Value {
        let camera = |c: usize| {
            let keys: Vec<Value> = self.keys[c]
                .iter()
                .map(|(id, key)| {
                    let status = match key.status {
                        Status::Active => "active",
                        Status::Retired => "retired",
                        Status::Revoked => "revoked",
                    };
                    json!({"key_id": id, "status": status})
                })
                .collect();
            json!({
                "last_seq": self.last[c].map(|(s, _)| s),
                "last_timestamp": self.last[c].map(|(_, t)| t),
                "pending": self.queues[c].iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
                "keys": keys,
            })
        };
        json!({"cameras": {"cam1": camera(0), "cam2": camera(1)}})
    }
}

// ---- Random commands ----

#[derive(Clone, Debug)]
enum Kind {
    Valid,
    Forged,
    WrongKey,
    BadTree,
    NegativeTimestamp,
}

#[derive(Clone, Debug)]
enum Op {
    Frame {
        cam: usize,
        key_id: u8,
        /// For key 0: send it as a version 1 frame.
        version_1: bool,
        /// Seq relative to the camera's last generated seq: may repeat or go back.
        seq_step: i64,
        /// Timestamp relative to the expected one.
        offset: i64,
        glitch: bool,
        kind: Kind,
        value: i32,
    },
    AddKey {
        cam: usize,
        key_id: u8,
        alt: bool,
    },
    Revoke {
        cam: usize,
        key_id: u8,
    },
    GetState,
    Restart,
}

fn op() -> impl Strategy<Value = Op> {
    let kind = prop_oneof![
        8 => Just(Kind::Valid),
        1 => Just(Kind::Forged),
        1 => Just(Kind::WrongKey),
        1 => Just(Kind::BadTree),
        1 => Just(Kind::NegativeTimestamp),
    ];
    let frame = (
        (0usize..2, 0u8..4, any::<bool>()),
        -2i64..5,
        -8i64..9,
        prop::bool::weighted(0.1),
        kind,
        any::<i32>(),
    )
        .prop_map(
            |((cam, key_id, version_1), seq_step, offset, glitch, kind, value)| Op::Frame {
                cam,
                key_id,
                version_1,
                seq_step,
                offset,
                glitch,
                kind,
                value,
            },
        );
    let add_key = (0usize..2, 0u8..4, prop::bool::weighted(0.2))
        .prop_map(|(cam, key_id, alt)| Op::AddKey { cam, key_id, alt });
    let revoke = (0usize..2, 0u8..4).prop_map(|(cam, key_id)| Op::Revoke { cam, key_id });
    prop_oneof![
        30 => frame,
        3 => add_key,
        1 => revoke,
        2 => Just(Op::GetState),
        1 => Just(Op::Restart),
    ]
}

fn config() -> impl Strategy<Value = (u64, u64, u64, u64)> {
    (1u64..120).prop_flat_map(|period| (Just(period), 0..period, 0..period, 1u64..7))
}

fn interval() -> impl Strategy<Value = u64> {
    prop_oneof![1u64..6, Just(100), Just(4_294_967_295)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn receiver_matches_the_reference_model(
        (period, jitter, window, max_pending) in config(),
        interval in interval(),
        start in 0i64..1_000_000,
        ops in prop::collection::vec(op(), 1..80),
    ) {
        let cfg = ModelConfig {
            period: i128::from(period),
            jitter: i128::from(jitter),
            window: i128::from(window),
            max_pending: usize::try_from(max_pending).unwrap(),
            interval,
        };
        let mut harness = Harness::default();
        let mut init: Value =
            serde_json::from_str(&init_line(period, jitter, window, max_pending)).unwrap();
        init["parameters"]["persist_interval"] = json!(interval);
        harness.ok(&init.to_string());
        let mut model = Model::default();
        // The last seq and the next "true" camera time each camera generated.
        let mut generated: [(i64, i64); 2] = [(0, start), (0, start + 3)];

        for op in ops {
            let before = harness.state();
            match op {
                Op::GetState => {
                    prop_assert_eq!(&before, &model.state());
                }
                Op::Restart => {
                    model.restart();
                    prop_assert_eq!(&harness.ok(RESTART), &model.state());
                }
                Op::AddKey { cam, key_id, alt } => {
                    let hex = key_hex(cam, key_id, alt);
                    let name = if cam == 0 { "cam1" } else { "cam2" };
                    let response = harness.send(&add_key_line(name, u64::from(key_id), &hex));
                    let expected = if model.add_key(cam, key_id, &hex) { "ok" } else { "error" };
                    prop_assert_eq!(&response["status"], expected, "{}", response);
                    prop_assert_eq!(&harness.state(), &model.state());
                }
                Op::Revoke { cam, key_id } => {
                    let name = if cam == 0 { "cam1" } else { "cam2" };
                    let response = harness.send(&revoke_key_line(name, u64::from(key_id)));
                    let expected = if model.revoke_key(cam, key_id) { "ok" } else { "error" };
                    prop_assert_eq!(&response["status"], expected, "{}", response);
                    prop_assert_eq!(&harness.state(), &model.state());
                }
                Op::Frame { cam, key_id, version_1, seq_step, offset, glitch, kind, value } => {
                    let (last_seq, clock) = generated[cam];
                    let seq = u32::try_from((last_seq + seq_step).clamp(0, i64::from(u32::MAX))).unwrap();
                    let steps = i64::from(seq) - last_seq;
                    let true_time = clock + steps * i64::try_from(period).unwrap();
                    let mut timestamp = if glitch { true_time + 10_000 } else { true_time + offset };
                    if matches!(kind, Kind::NegativeTimestamp) {
                        timestamp = -1 - i64::from(value.unsigned_abs());
                    }
                    let timestamp = if matches!(kind, Kind::NegativeTimestamp) { timestamp } else { timestamp.max(0) };
                    if matches!(kind, Kind::Valid) && seq > u32::try_from(last_seq).unwrap() {
                        generated[cam] = (i64::from(seq), true_time);
                    }

                    let camera = u8::try_from(cam + 1).unwrap();
                    // Sign with the key the model knows for this id (even if it's
                    // retired or revoked: an attacker may hold an old key).
                    let signing = model.keys[cam]
                        .get(&key_id)
                        .map_or_else(|| key_hex(cam, key_id, true), |key| key.hex.clone());
                    let mut frame = Frame::new(camera, seq, timestamp).payload(leaf(value));
                    if !(key_id == 0 && version_1) {
                        frame = frame.v2(key_id, &signing);
                    }
                    match kind {
                        Kind::BadTree => frame = frame.payload(vec![0x01, 0x00]),
                        Kind::WrongKey => frame = frame.key(WRONG_KEY),
                        _ => {}
                    }
                    let mut bytes = frame.bytes();
                    if matches!(kind, Kind::Forged) {
                        let last = bytes.len() - 1;
                        bytes[last] ^= 0x80;
                    }
                    let tag_ok = !matches!(kind, Kind::Forged | Kind::WrongKey);
                    let tree_ok = !matches!(kind, Kind::BadTree);

                    let response = harness.send(&receive_line(&hex::encode(&bytes)));
                    let expected =
                        model.receive(&cfg, cam, key_id, seq, timestamp, tag_ok, tree_ok);
                    match expected {
                        None => {
                            prop_assert_eq!(&response["status"], "error", "{}", response);
                            // A rejected frame changes nothing, except that one
                            // rejected only by the restart floor still moves the
                            // camera's key, as the model does too.
                            prop_assert_eq!(&harness.state(), &model.state());
                            if model.loaded[cam].is_none() {
                                prop_assert_eq!(&harness.state(), &before);
                            }
                        }
                        Some(outcome) => {
                            prop_assert_eq!(&response["status"], "ok", "{}", response);
                            let got = &response["payload"];
                            prop_assert_eq!(&got["frame"]["seq"], &json!(seq));
                            prop_assert_eq!(&got["frame"]["key_id"], &json!(key_id));
                            prop_assert_eq!(&got["frame"]["timestamp"], &json!(outcome.timestamp));
                            prop_assert_eq!(&got["frame"]["corrected"], &json!(outcome.corrected));
                            prop_assert_eq!(&got["frame"]["tree"], &json!([value]));
                            prop_assert_eq!(&got["synced"], &json!(outcome.records));
                        }
                    }
                    let state = harness.state();
                    prop_assert_eq!(&state, &model.state());
                    for cam_name in ["cam1", "cam2"] {
                        let pending = state["cameras"][cam_name]["pending"].as_array().unwrap();
                        prop_assert!(pending.len() <= cfg.max_pending);
                    }
                }
            }
        }
    }

    #[test]
    fn arbitrary_lines_never_cause_an_internal_error(
        lines in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..200), 1..20),
        initialize in any::<bool>(),
    ) {
        let mut input = Vec::new();
        if initialize {
            input.extend_from_slice(init_line(50, 5, 20, 4).as_bytes());
            input.push(b'\n');
        }
        let mut expected_lines = usize::from(initialize);
        for line in &lines {
            let clean: Vec<u8> = line.iter().copied().filter(|b| *b != b'\n').collect();
            input.extend_from_slice(&clean);
            input.push(b'\n');
            expected_lines += 1;
        }
        let mut output = Vec::new();
        secure_sensor_link::protocol::run(input.as_slice(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        prop_assert_eq!(text.lines().count(), expected_lines);
        for line in text.lines() {
            let response: Value = serde_json::from_str(line).unwrap();
            prop_assert_ne!(&response["payload"]["message"], "internal error");
        }
    }

    #[test]
    fn arbitrary_frame_bytes_are_rejected_cleanly(
        bytes in prop::collection::vec(any::<u8>(), 0..300),
        version_and_camera in prop::option::of((0u8..4, 0u8..4)),
    ) {
        let mut bytes = bytes;
        if let Some((version, camera)) = version_and_camera
            && bytes.len() >= 2
        {
            bytes[0] = version;
            bytes[1] = camera;
        }
        let mut harness = Harness::spec_config();
        let message = harness.error(&receive_line(&hex::encode(&bytes)));
        prop_assert!(
            message.starts_with("malformed frame") || message.starts_with("authentication failed"),
            "{}", message
        );
    }
}
