//! Restarts and persistent replay protection (follow-on 2).
//!
//! The property test at the end runs two receivers side by side on the same
//! traffic, restarting only one of them, and checks the spec's restart rules
//! against the twin that never restarts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]

mod support;

use std::collections::BTreeSet;

use proptest::prelude::*;
use secure_sensor_link::camera::{Camera, PerCamera};
use secure_sensor_link::config::{Config, ConfigInput};
use secure_sensor_link::key::{Key, KeyId};
use secure_sensor_link::keyring::KeyStatus;
use secure_sensor_link::receiver::Receiver;
use secure_sensor_link::storage::MemoryStore;
use serde_json::{Value, json};
use support::{
    Frame, Harness, KEY1, KEY2, RESTART, add_key_line, init_line, init_line_with_interval,
    receive_line, revoke_key_line,
};

// ---- Rules, one per test, through the real protocol ----

fn accept(h: &mut Harness, frame: &Frame) -> Value {
    h.ok(&receive_line(&frame.hex()))
}

fn reject(h: &mut Harness, frame: &Frame) -> String {
    h.error(&receive_line(&frame.hex()))
}

/// A cam1 frame with the spec's spacing: timestamp 1000 + 50 per seq.
fn cam1(seq: u32) -> Frame {
    Frame::new(1, seq, 1000 + i64::from(seq) * 50)
}

/// Distinct test keys for cam1, one per id.
fn key(id: u8) -> String {
    format!("{:02x}", id ^ 0x80).repeat(32)
}

fn cam1_keys(h: &mut Harness) -> Value {
    h.state()["cameras"]["cam1"]["keys"].clone()
}

fn entry(id: u8, status: &str) -> Value {
    json!({"key_id": id, "status": status})
}

fn spec_with_interval(interval: u64) -> Harness {
    let mut h = Harness::default();
    h.ok(&init_line_with_interval(interval));
    h
}

#[test]
fn restart_needs_init_and_takes_no_parameters() {
    let mut h = Harness::default();
    assert_eq!(
        h.error(RESTART),
        "not initialized: the first command must be init"
    );
    let mut h = Harness::spec_config();
    assert!(
        h.error(r#"{"command":"restart","parameters":{"now":true}}"#)
            .starts_with("invalid command: unknown field `now`")
    );
    assert_eq!(
        h.error(r#"{"command":"restart","parameters":[]}"#),
        "invalid command: expected a JSON object"
    );
}

#[test]
fn init_is_still_rejected_after_a_restart() {
    let mut h = Harness::spec_config();
    h.ok(RESTART);
    assert_eq!(h.error(&init_line(50, 5, 20, 4)), "already initialized");
}

#[test]
fn a_restart_keeps_only_keys_and_returns_the_new_state() {
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1));
    accept(&mut h, &Frame::new(2, 1, 1003));
    accept(&mut h, &cam1(2));
    h.ok(&add_key_line("cam2", 1, &key(1)));
    let keys_before = h.state()["cameras"]["cam2"]["keys"].clone();
    let state = h.ok(RESTART);
    for camera in ["cam1", "cam2"] {
        let camera_state = &state["cameras"][camera];
        assert_eq!(camera_state["last_seq"], Value::Null);
        assert_eq!(camera_state["last_timestamp"], Value::Null);
        assert_eq!(camera_state["pending"], json!([]));
    }
    assert_eq!(state["cameras"]["cam2"]["keys"], keys_before);
    assert_eq!(state, h.state());
}

#[test]
fn frames_up_to_the_saved_floor_are_rejected_after_a_restart() {
    // persist_interval defaults to 100: accepting seq 1 saved the floor 101.
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1));
    accept(&mut h, &cam1(50));
    h.ok(RESTART);
    for seq in [0, 1, 50, 51, 101] {
        assert_eq!(
            reject(&mut h, &cam1(seq)),
            format!("stale or replayed frame: cam1 seq {seq}")
        );
    }
    accept(&mut h, &cam1(102));
    // From then on, the usual rule: above the last accepted seq.
    assert_eq!(
        reject(&mut h, &cam1(102)),
        "stale or replayed frame: cam1 seq 102"
    );
    accept(&mut h, &cam1(103));
}

#[test]
fn the_floor_moves_up_as_seqs_pass_it() {
    let mut h = spec_with_interval(10);
    accept(&mut h, &cam1(1)); // floor 11
    accept(&mut h, &cam1(11)); // still covered
    accept(&mut h, &cam1(12)); // floor 22
    h.ok(RESTART);
    reject(&mut h, &cam1(22));
    accept(&mut h, &cam1(23)); // floor 33
    h.ok(RESTART);
    // Replay protection holds across any number of restarts.
    for seq in [1, 12, 23, 33] {
        reject(&mut h, &cam1(seq));
    }
    accept(&mut h, &cam1(34));
}

#[test]
fn every_frame_more_than_persist_interval_past_the_last_is_accepted() {
    let mut h = spec_with_interval(5);
    accept(&mut h, &cam1(3)); // floor 8
    accept(&mut h, &cam1(8)); // S = 8, so S + 5 = 13
    h.ok(RESTART);
    reject(&mut h, &cam1(8));
    // Required from 14; accepted from 9, the first seq above the floor.
    accept(&mut h, &cam1(9));
}

#[test]
fn persist_interval_1_rejects_only_one_seq_past_the_last() {
    let mut h = spec_with_interval(1);
    accept(&mut h, &cam1(5)); // floor 6
    h.ok(RESTART);
    reject(&mut h, &cam1(6));
    accept(&mut h, &cam1(7));
}

#[test]
fn with_the_largest_persist_interval_a_camera_is_never_accepted_after_a_restart() {
    // A known limitation of the budget: one write must cover every seq.
    let mut h = spec_with_interval(4_294_967_295);
    accept(&mut h, &cam1(0));
    accept(&mut h, &cam1(1));
    h.ok(RESTART);
    assert_eq!(
        reject(&mut h, &cam1(u32::MAX)),
        "stale or replayed frame: cam1 seq 4294967295"
    );
}

#[test]
fn a_camera_with_nothing_accepted_has_no_floor() {
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(9));
    h.ok(RESTART);
    accept(&mut h, &Frame::new(2, 0, 1000));
}

#[test]
fn the_timeline_starts_over_after_a_restart() {
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1));
    h.ok(RESTART);
    // Without the restart this would be corrected to 1000 + 199 * 50.
    let first = accept(&mut h, &Frame::new(1, 200, 5_000_000));
    assert_eq!(first["frame"]["timestamp"], 5_000_000);
    assert_eq!(first["frame"]["corrected"], false);
    // Later frames are corrected against the new first frame.
    let next = accept(&mut h, &Frame::new(1, 201, 9));
    assert_eq!(next["frame"]["timestamp"], 5_000_050);
    assert_eq!(next["frame"]["corrected"], true);
}

#[test]
fn queued_frames_are_dropped_without_being_emitted() {
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1));
    assert_eq!(h.state()["cameras"]["cam1"]["pending"], json!([1]));
    assert_eq!(h.ok(RESTART)["cameras"]["cam1"]["pending"], json!([]));
    // cam2's frame 1 would have paired with cam1's; now it waits alone.
    let response = accept(&mut h, &Frame::new(2, 1, 1003));
    assert_eq!(response["synced"], json!([]));
    assert_eq!(h.state()["cameras"]["cam2"]["pending"], json!([1]));
}

#[test]
fn key_changes_survive_a_restart() {
    let mut h = Harness::spec_config();
    h.ok(&add_key_line("cam1", 1, &key(1)));
    h.ok(&add_key_line("cam1", 3, &key(3)));
    h.ok(&add_key_line("cam1", 5, &key(5)));
    accept(&mut h, &cam1(1).v2(3, &key(3))); // retires keys 0 and 1
    h.ok(&revoke_key_line("cam1", 5));
    let before = cam1_keys(&mut h);
    h.ok(RESTART);
    assert_eq!(cam1_keys(&mut h), before);
    assert_eq!(
        before,
        json!([
            entry(0, "retired"),
            entry(1, "retired"),
            entry(3, "active"),
            entry(5, "revoked"),
        ])
    );
    assert_eq!(reject(&mut h, &cam1(200)), "cam1 key 0 is retired");
    assert_eq!(
        reject(&mut h, &cam1(200).v2(5, &key(5))),
        "cam1 key 5 is revoked"
    );
    // The camera's current key survived too.
    assert_eq!(
        h.error(&add_key_line("cam1", 2, &key(2))),
        "cam1 key 2 would be retired at once: cam1 already uses key 3"
    );
    accept(&mut h, &cam1(200).v2(3, &key(3)));
}

#[test]
fn a_key_rotation_seen_below_the_floor_still_retires_the_old_key() {
    // Without the restart, cam1's seq 2 under key 1 would be accepted and
    // would retire key 0. After the restart it is rejected (it might be a
    // replay), but it still moves cam1 to key 1, so an attacker holding key 0
    // gets nothing in.
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1)); // floor 101
    h.ok(&add_key_line("cam1", 1, &key(1)));
    h.ok(RESTART);
    assert_eq!(
        reject(&mut h, &cam1(2).v2(1, &key(1))),
        "stale or replayed frame: cam1 seq 2"
    );
    assert_eq!(
        cam1_keys(&mut h),
        json!([entry(0, "retired"), entry(1, "active")])
    );
    assert_eq!(reject(&mut h, &cam1(102)), "cam1 key 0 is retired");
    accept(&mut h, &cam1(102).v2(1, &key(1)));
}

#[test]
fn a_frame_below_the_floor_moves_no_key_unless_it_is_otherwise_valid() {
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1));
    h.ok(&add_key_line("cam1", 1, &key(1)));
    h.ok(RESTART);
    let before = h.state();
    let bad_tree = cam1(2).v2(1, &key(1)).payload(vec![0x07]);
    let negative = Frame::new(1, 3, -1).v2(1, &key(1));
    let forged = cam1(4).v2(1, &key(9));
    // Reported as stale, like any frame at or below the floor...
    assert_eq!(
        reject(&mut h, &bad_tree),
        "stale or replayed frame: cam1 seq 2"
    );
    assert_eq!(
        reject(&mut h, &negative),
        "stale or replayed frame: cam1 seq 3"
    );
    // ...except a forgery, which fails the tag first.
    assert_eq!(reject(&mut h, &forged), "authentication failed for cam1");
    // None of them moved cam1 to key 1.
    assert_eq!(h.state(), before);
}

#[test]
fn a_frame_below_the_floor_on_the_current_key_changes_nothing() {
    let mut h = Harness::spec_config();
    accept(&mut h, &cam1(1));
    h.ok(RESTART);
    let before = h.state();
    reject(&mut h, &cam1(2));
    assert_eq!(h.state(), before);
}

#[test]
fn persist_interval_must_be_a_whole_number_in_range() {
    let line = |value: &str| {
        let mut init: Value = serde_json::from_str(&init_line(50, 5, 20, 4)).unwrap();
        init["parameters"]["persist_interval"] = serde_json::from_str(value).unwrap();
        init.to_string()
    };
    let mut h = Harness::default();
    assert_eq!(
        h.error(&line("0")),
        "persist_interval must be from 1 to 4294967295, got 0"
    );
    assert_eq!(
        h.error(&line("4294967296")),
        "persist_interval must be from 1 to 4294967295, got 4294967296"
    );
    for bad in ["null", "\"100\"", "1.5", "true", "-1"] {
        assert!(
            h.error(&line(bad)).starts_with("invalid command: invalid "),
            "{bad}"
        );
    }
    // Each failed init can be retried.
    h.ok(&line("4294967295"));
}

// ---- Storage writes, through the library ----

#[test]
fn a_floor_is_written_once_every_persist_interval_plus_one_seqs() {
    let mut r = receiver(10);
    for seq in 0..=1000 {
        r.receive(&cam1(seq).hex()).unwrap();
    }
    // Floors 10, 21, 32, ..., 1000: written at seq 0, 11, 22, ..., 990. The
    // budget is 1 + (1000 - 0) / 10 = 101.
    assert_eq!(*r.store().writes().floors.get(Camera::Cam1), 91);
    assert_eq!(*r.store().writes().floors.get(Camera::Cam2), 0);
}

#[test]
fn restarts_stay_within_the_write_budget() {
    let mut r = receiver(10);
    let mut accepted = Vec::new();
    for seq in 0..=1000 {
        if r.receive(&cam1(seq).hex()).is_ok() {
            accepted.push(seq);
        }
        if seq % 97 == 0 {
            r.restart().unwrap();
        }
    }
    let (min, max) = (accepted[0], accepted[accepted.len() - 1]);
    let writes = *r.store().writes().floors.get(Camera::Cam1);
    assert!(writes <= 1 + u64::from(max - min) / 10, "{writes} writes");
    // Each restart rejects at most persist_interval seqs.
    assert!(
        accepted.len() >= 1001 - 11 * 11,
        "{} accepted",
        accepted.len()
    );
}

#[test]
fn key_events_are_written_at_once_and_nothing_else_is() {
    let mut r = receiver(100);
    let keys = |r: &Receiver<MemoryStore>| *r.store().writes().keys.get(Camera::Cam1);
    assert_eq!(keys(&r), 1, "init");
    assert_eq!(r.store().writes().config, 1);
    r.receive(&cam1(1).hex()).unwrap();
    assert_eq!(keys(&r), 1, "a frame on the key cam1 started on");
    r.add_key(Camera::Cam1, KeyId(1), Key::from_hex(&key(1)).unwrap())
        .unwrap();
    assert_eq!(keys(&r), 2);
    r.add_key(Camera::Cam1, KeyId(1), Key::from_hex(&key(1)).unwrap())
        .unwrap();
    assert_eq!(keys(&r), 2, "re-adding the same key");
    r.receive(&cam1(2).v2(1, &key(1)).hex()).unwrap();
    assert_eq!(keys(&r), 3, "cam1 moved to key 1");
    r.receive(&cam1(3).v2(1, &key(1)).hex()).unwrap();
    assert_eq!(keys(&r), 3);
    r.revoke_key(Camera::Cam1, KeyId(0)).unwrap();
    r.revoke_key(Camera::Cam1, KeyId(0)).unwrap();
    assert_eq!(keys(&r), 4, "one revocation");
    r.restart().unwrap();
    assert_eq!(keys(&r), 4, "a restart only reads");
    assert_eq!(r.store().writes().config, 1);
}

// ---- Property: a restarted receiver against a twin that never restarts ----

/// A key the attacker never has.
const WRONG_KEY: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Key `id` of camera `cam` (0 or 1). Key 0 is the spec's.
fn key_hex(cam: usize, id: u8) -> String {
    if id == 0 {
        return if cam == 0 { KEY1 } else { KEY2 }.to_owned();
    }
    format!("{:02x}", u8::try_from(cam).unwrap() * 100 + id).repeat(32)
}

fn camera(cam: usize) -> Camera {
    if cam == 0 { Camera::Cam1 } else { Camera::Cam2 }
}

/// A frame signed with key `id` (version 1 for key 0).
fn frame(cam: usize, id: u8, seq: u32, key: &str) -> String {
    let wire = u8::try_from(cam + 1).unwrap();
    let timestamp = 1000 + i64::from(seq) * 50;
    let frame = Frame::new(wire, seq, timestamp);
    let frame = if id == 0 {
        frame.key(key)
    } else {
        frame.v2(id, key)
    };
    frame.hex()
}

#[derive(Clone, Debug)]
enum Op {
    /// The camera sends its next frame, `gap` seqs on (the rest are lost).
    Next { cam: usize, gap: u32 },
    /// The operator provisions the camera's next key, and the camera moves
    /// to it for its following frames.
    Rotate { cam: usize },
    /// An attacker replays one of the camera's earlier frames.
    Replay { cam: usize, pick: usize },
    /// An attacker holding a key the receivers have retired or revoked sends a
    /// frame with a fresh seq. (An attacker holding a key that is still
    /// active can inject frames whether or not there is a restart, so that
    /// case says nothing about restarts.)
    OldKey { cam: usize, jump: u32 },
    /// An attacker without any key forges a frame.
    Forge { cam: usize, jump: u32 },
    /// The operator revokes a key the camera has moved past.
    RevokeOld { cam: usize },
    /// Power loss: only the first receiver restarts.
    Restart,
}

fn op() -> impl Strategy<Value = Op> {
    let cam = 0usize..2;
    prop_oneof![
        12 => (cam.clone(), 1u32..4).prop_map(|(cam, gap)| Op::Next { cam, gap }),
        2 => cam.clone().prop_map(|cam| Op::Rotate { cam }),
        3 => (cam.clone(), any::<usize>()).prop_map(|(cam, pick)| Op::Replay { cam, pick }),
        3 => (cam.clone(), 0u32..300).prop_map(|(cam, jump)| Op::OldKey { cam, jump }),
        1 => (cam.clone(), 0u32..300).prop_map(|(cam, jump)| Op::Forge { cam, jump }),
        1 => cam.prop_map(|cam| Op::RevokeOld { cam }),
        2 => Just(Op::Restart),
    ]
}

/// A camera as the attacker and the operator see it.
#[derive(Debug, Default)]
struct CameraModel {
    next_seq: u32,
    key: u8,
    /// Every genuine frame sent: seq, key id.
    sent: Vec<(u32, u8)>,
}

/// What the restarted receiver has accepted, for the spec's rules.
#[derive(Debug, Default)]
struct Accepted {
    all: BTreeSet<u32>,
    /// The highest seq accepted before the latest restart.
    before_restart: Option<u32>,
    /// The highest seq accepted since the latest restart.
    since_restart: Option<u32>,
}

fn receiver(interval: u32) -> Receiver<MemoryStore> {
    let config = Config::new(ConfigInput {
        period_ms: 50,
        max_jitter_ms: 5,
        pair_window_ms: 20,
        max_pending: 4,
        persist_interval: Some(u64::from(interval)),
    })
    .unwrap();
    let keys = PerCamera::new(Key::from_hex(KEY1).unwrap(), Key::from_hex(KEY2).unwrap());
    Receiver::new(config, keys, MemoryStore::default()).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn a_restart_never_lets_in_what_the_twin_rejects(
        interval in prop_oneof![Just(1u32), Just(2), Just(3), Just(5), Just(10), Just(100)],
        starts in (0u32..5, 0u32..5),
        ops in prop::collection::vec(op(), 1..120),
    ) {
        let mut restarted = receiver(interval);
        let mut twin = receiver(interval);
        let mut cams = [CameraModel::default(), CameraModel::default()];
        cams[0].next_seq = starts.0;
        cams[1].next_seq = starts.1;
        let mut accepted = [Accepted::default(), Accepted::default()];

        for op in ops {
            // (camera, frame hex, is it the camera's own new frame?)
            let delivery = match op {
                Op::Restart => {
                    restarted.restart().unwrap();
                    for a in &mut accepted {
                        a.before_restart = a.before_restart.max(a.since_restart);
                        a.since_restart = None;
                    }
                    None
                }
                Op::Rotate { cam } => {
                    let model = &mut cams[cam];
                    if model.key < 200 {
                        let id = model.key + 1;
                        for r in [&mut restarted, &mut twin] {
                            let key = Key::from_hex(&key_hex(cam, id)).unwrap();
                            r.add_key(camera(cam), KeyId(id), key).unwrap();
                        }
                        model.key = id;
                    }
                    None
                }
                Op::RevokeOld { cam } => {
                    let model = &cams[cam];
                    if model.key > 0 {
                        let id = KeyId(model.key - 1);
                        restarted.revoke_key(camera(cam), id).unwrap();
                        twin.revoke_key(camera(cam), id).unwrap();
                    }
                    None
                }
                Op::Next { cam, gap } => {
                    let model = &mut cams[cam];
                    let seq = model.next_seq;
                    model.next_seq = seq.saturating_add(gap);
                    model.sent.push((seq, model.key));
                    Some((cam, frame(cam, model.key, seq, &key_hex(cam, model.key)), true, seq))
                }
                Op::Replay { cam, pick } => {
                    let model = &cams[cam];
                    if model.sent.is_empty() {
                        None
                    } else {
                        let (seq, id) = model.sent[pick % model.sent.len()];
                        Some((cam, frame(cam, id, seq, &key_hex(cam, id)), false, seq))
                    }
                }
                Op::OldKey { cam, jump } => {
                    // The highest key the twin no longer accepts, if any.
                    let state = twin.state();
                    let inactive = state
                        .cameras
                        .get(camera(cam))
                        .keys
                        .iter()
                        .rev()
                        .find(|entry| entry.status != KeyStatus::Active)
                        .map(|entry| entry.key_id.0);
                    inactive.map(|id| {
                        let seq = cams[cam].next_seq.saturating_add(jump);
                        (cam, frame(cam, id, seq, &key_hex(cam, id)), false, seq)
                    })
                }
                Op::Forge { cam, jump } => {
                    let seq = cams[cam].next_seq.saturating_add(jump);
                    Some((cam, frame(cam, 0, seq, WRONG_KEY), false, seq))
                }
            };
            let Some((cam, hex, genuine_new, seq)) = delivery else {
                continue;
            };
            let got = restarted.receive(&hex).is_ok();
            let twin_got = twin.receive(&hex).is_ok();
            let a = &mut accepted[cam];

            // No seq is ever accepted twice, across any number of restarts.
            if got {
                prop_assert!(a.all.iter().all(|&s| s < seq), "seq {} accepted again", seq);
                a.all.insert(seq);
            }
            // Rule 1: a restart never lets in a replay, forgery or old-key
            // frame that the twin rejects.
            if got && !genuine_new {
                prop_assert!(twin_got, "restart let in an attacker frame: {:?}", (cam, seq));
            }
            // Rule 2: after a restart, the camera's own new frame is accepted
            // once its seq is more than persist_interval above the highest seq
            // accepted before the restart (and above anything accepted since).
            if genuine_new {
                let past_floor = a
                    .before_restart
                    .is_none_or(|s| u64::from(seq) > u64::from(s) + u64::from(interval));
                let past_last = a.since_restart.is_none_or(|s| seq > s);
                if past_floor && past_last {
                    prop_assert!(got, "restart blocked a required frame: {:?}", (cam, seq));
                }
            }
            if got {
                a.since_restart = Some(seq);
            }
        }

        // The write budget, per camera.
        for (cam, a) in accepted.iter().enumerate() {
            let writes = *restarted.store().writes().floors.get(camera(cam));
            if let (Some(&min), Some(&max)) = (a.all.first(), a.all.last()) {
                let budget = 1 + u64::from(max - min) / u64::from(interval);
                prop_assert!(writes <= budget, "{} floor writes, budget {}", writes, budget);
            } else {
                prop_assert_eq!(writes, 0);
            }
        }
    }
}
