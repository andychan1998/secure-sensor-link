//! Key rotation and revocation (follow-on 1), one rule per test, through the
//! real protocol.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]

mod support;

use serde_json::{Value, json};
use support::{Frame, Harness, KEY1, add_key_line, leaf, receive_line, revoke_key_line};

/// Distinct test keys, one per id; never the spec's camera keys.
fn key(id: u8) -> String {
    format!("{:02x}", id ^ 0x80).repeat(32)
}

/// A version 2 cam1 frame signed with [`key`]`(id)`.
fn cam1(id: u8, seq: u32, timestamp: i64) -> Frame {
    Frame::new(1, seq, timestamp).v2(id, &key(id))
}

fn add(h: &mut Harness, camera: &str, id: u64, hex: &str) -> Value {
    h.ok(&add_key_line(camera, id, hex))
}

fn add_error(h: &mut Harness, camera: &str, id: u64, hex: &str) -> String {
    let before = h.state();
    let message = h.error(&add_key_line(camera, id, hex));
    assert_eq!(h.state(), before, "a rejected add_key changed the state");
    message
}

fn revoke(h: &mut Harness, camera: &str, id: u64) -> Value {
    h.ok(&revoke_key_line(camera, id))
}

fn accept(h: &mut Harness, frame: &Frame) -> Value {
    h.ok(&receive_line(&frame.hex()))
}

fn reject(h: &mut Harness, frame: &Frame) -> String {
    let before = h.state();
    let message = h.error(&receive_line(&frame.hex()));
    assert_eq!(h.state(), before, "a rejected frame changed the state");
    message
}

fn keys(h: &mut Harness, camera: &str) -> Value {
    h.state()["cameras"][camera]["keys"].clone()
}

fn entry(id: u8, status: &str) -> Value {
    json!({"key_id": id, "status": status})
}

// ---- Frames and key ids ----

#[test]
fn version_1_frames_use_key_0_and_match_version_2_frames_on_key_0() {
    let mut h = Harness::spec_config();
    let v1 = accept(&mut h, &Frame::new(1, 1, 1000));
    assert_eq!(v1["frame"]["key_id"], 0);
    let v2 = accept(&mut h, &Frame::new(1, 2, 1050).v2(0, KEY1));
    assert_eq!(v2["frame"]["key_id"], 0);
    assert_eq!(keys(&mut h, "cam1"), json!([entry(0, "active")]));
}

#[test]
fn a_frame_under_an_unknown_key_id_is_rejected() {
    let mut h = Harness::spec_config();
    assert_eq!(
        reject(&mut h, &cam1(9, 1, 1000)),
        "cam1 key 9 is not provisioned"
    );
}

#[test]
fn key_ids_are_per_camera() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    let frame = Frame::new(2, 1, 1000).v2(1, &key(1));
    assert_eq!(reject(&mut h, &frame), "cam2 key 1 is not provisioned");
    assert_eq!(keys(&mut h, "cam2"), json!([entry(0, "active")]));
}

#[test]
fn the_highest_key_id_works() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 255, &key(255));
    let frame = Frame::new(1, 1, 1000).v2(255, &key(255));
    assert_eq!(accept(&mut h, &frame)["frame"]["key_id"], 255);
}

#[test]
fn an_added_key_does_not_retire_older_keys_until_a_frame_uses_it() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    assert_eq!(
        keys(&mut h, "cam1"),
        json!([entry(0, "active"), entry(1, "active")])
    );
    // The camera may still be sending on key 0 while the new key rolls out.
    accept(&mut h, &Frame::new(1, 1, 1000));
    accept(&mut h, &cam1(1, 2, 1050));
    assert_eq!(
        keys(&mut h, "cam1"),
        json!([entry(0, "retired"), entry(1, "active")])
    );
    assert_eq!(
        reject(&mut h, &Frame::new(1, 3, 1100)),
        "cam1 key 0 is retired"
    );
    assert_eq!(
        reject(&mut h, &Frame::new(1, 3, 1100).v2(0, KEY1)),
        "cam1 key 0 is retired"
    );
}

#[test]
fn using_a_key_retires_every_lower_key() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    add(&mut h, "cam1", 2, &key(2));
    add(&mut h, "cam1", 4, &key(4));
    accept(&mut h, &cam1(2, 1, 1000));
    assert_eq!(
        keys(&mut h, "cam1"),
        json!([
            entry(0, "retired"),
            entry(1, "retired"),
            entry(2, "active"),
            entry(4, "active"),
        ])
    );
    assert_eq!(reject(&mut h, &cam1(1, 2, 1050)), "cam1 key 1 is retired");
    accept(&mut h, &cam1(4, 2, 1050));
    assert_eq!(
        keys(&mut h, "cam1"),
        json!([
            entry(0, "retired"),
            entry(1, "retired"),
            entry(2, "retired"),
            entry(4, "active"),
        ])
    );
}

#[test]
fn a_forged_frame_on_a_new_key_retires_nothing() {
    // Only an accepted frame moves the camera to a key, so an attacker can't
    // retire the keys a camera is still using by claiming a higher key id.
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    let forged = Frame::new(1, 1, 1000).v2(1, &key(7));
    assert_eq!(reject(&mut h, &forged), "authentication failed for cam1");
    accept(&mut h, &Frame::new(1, 1, 1000));
}

#[test]
fn a_rejected_frame_on_a_new_key_retires_nothing() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    accept(&mut h, &Frame::new(1, 5, 1000));
    assert_eq!(
        reject(&mut h, &cam1(1, 5, 1050)),
        "stale or replayed frame: cam1 seq 5"
    );
    assert_eq!(
        reject(&mut h, &cam1(1, 6, -1)),
        "malformed frame: negative timestamp -1"
    );
    assert_eq!(
        reject(&mut h, &cam1(1, 6, 1050).payload(vec![0x07])),
        "malformed frame: tree has byte 0x07 at payload offset 0 where 0x00 or 0x01 was expected"
    );
    accept(&mut h, &Frame::new(1, 6, 1050));
}

#[test]
fn key_status_is_checked_before_the_tag() {
    // A frame under a retired or revoked key is reported as such even when its
    // tag is wrong, so the error never depends on guessing the tag.
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    accept(&mut h, &cam1(1, 1, 1000));
    let forged = Frame::new(1, 2, 1050).key(&key(9));
    assert_eq!(reject(&mut h, &forged), "cam1 key 0 is retired");
    revoke(&mut h, "cam1", 1);
    assert_eq!(
        reject(&mut h, &cam1(1, 2, 1050).key(&key(9))),
        "cam1 key 1 is revoked"
    );
}

#[test]
fn seq_and_timeline_carry_across_key_changes() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    accept(&mut h, &Frame::new(1, 5, 1000));
    // A new key is not a new stream: replay protection and the timeline continue.
    assert_eq!(
        reject(&mut h, &cam1(1, 5, 1050)),
        "stale or replayed frame: cam1 seq 5"
    );
    let jumped = accept(&mut h, &cam1(1, 6, 9999));
    assert_eq!(jumped["frame"]["timestamp"], 1050);
    assert_eq!(jumped["frame"]["corrected"], true);
}

#[test]
fn the_payload_decodes_the_same_in_both_versions() {
    let mut h = Harness::spec_config();
    let v1 = accept(&mut h, &Frame::new(1, 1, 1000).payload(leaf(42)));
    add(&mut h, "cam1", 1, &key(1));
    let v2 = accept(&mut h, &cam1(1, 2, 1050).payload(leaf(42)));
    assert_eq!(v1["frame"]["tree"], json!([42]));
    assert_eq!(v2["frame"]["tree"], json!([42]));
}

// ---- add_key ----

#[test]
fn add_key_returns_the_state_with_keys_sorted() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 5, &key(5));
    let state = add(&mut h, "cam1", 2, &key(2));
    assert_eq!(
        state["cameras"]["cam1"]["keys"],
        json!([entry(0, "active"), entry(2, "active"), entry(5, "active")])
    );
    assert_eq!(state, h.state());
}

#[test]
fn re_adding_the_same_key_is_a_no_op() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    let before = h.state();
    add(&mut h, "cam1", 1, &key(1));
    add(&mut h, "cam1", 0, KEY1);
    // Hex case doesn't matter: the bytes are compared.
    add(&mut h, "cam1", 1, &key(1).to_uppercase());
    assert_eq!(h.state(), before);
}

#[test]
fn re_adding_an_id_with_different_bytes_is_rejected() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    assert_eq!(
        add_error(&mut h, "cam1", 1, &key(2)),
        "cam1 key 1 is already provisioned with a different key"
    );
    assert_eq!(
        add_error(&mut h, "cam2", 0, KEY1),
        "cam2 key 0 is already provisioned with a different key"
    );
    // The original key still works.
    accept(&mut h, &cam1(1, 1, 1000));
}

#[test]
fn a_revoked_id_cannot_be_added_back() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 3, &key(3));
    revoke(&mut h, "cam1", 3);
    assert_eq!(
        add_error(&mut h, "cam1", 3, &key(3)),
        "cam1 key 3 is revoked"
    );
    assert_eq!(
        add_error(&mut h, "cam1", 3, &key(4)),
        "cam1 key 3 is revoked"
    );
}

#[test]
fn a_retired_id_cannot_be_added_back() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    accept(&mut h, &cam1(1, 1, 1000));
    assert_eq!(add_error(&mut h, "cam1", 0, KEY1), "cam1 key 0 is retired");
}

#[test]
fn a_key_below_the_one_in_use_is_rejected() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 3, &key(3));
    accept(&mut h, &cam1(3, 1, 1000));
    assert_eq!(
        add_error(&mut h, "cam1", 2, &key(2)),
        "cam1 key 2 would be retired at once: cam1 already uses key 3"
    );
    // Above the current key is fine.
    add(&mut h, "cam1", 4, &key(4));
}

#[test]
fn a_key_below_an_unused_key_is_accepted() {
    // Only the key in use matters, not the highest provisioned one.
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 5, &key(5));
    add(&mut h, "cam1", 2, &key(2));
    accept(&mut h, &cam1(2, 1, 1000));
}

#[test]
fn add_key_parameters_are_checked() {
    let mut h = Harness::spec_config();
    let before = h.state();
    assert_eq!(
        h.error(&add_key_line("cam1", 256, &key(1))),
        "key_id must be from 0 to 255, got 256"
    );
    assert_eq!(
        h.error(&add_key_line("cam3", 1, &key(1))),
        "camera must be cam1 or cam2"
    );
    assert_eq!(
        h.error(&add_key_line("CAM1", 1, &key(1))),
        "camera must be cam1 or cam2"
    );
    assert_eq!(
        h.error(&add_key_line("cam1", 1, &"ab".repeat(31))),
        "key must be 64 hex characters (a 32-byte key), got 62"
    );
    assert_eq!(
        h.error(&add_key_line("cam1", 1, &key(1).replace('8', "z"))),
        "key must contain only hex characters"
    );
    assert!(
        h.error(r#"{"command":"add_key","parameters":{"camera":"cam1","key_id":1}}"#)
            .starts_with("invalid command: missing field `key`")
    );
    assert!(
        h.error(&format!(
            r#"{{"command":"add_key","parameters":{{"camera":"cam1","key_id":1,"key":"{}","extra":1}}}}"#,
            key(1)
        ))
        .starts_with("invalid command: unknown field `extra`")
    );
    assert!(
        h.error(&format!(
            r#"{{"command":"add_key","parameters":{{"camera":"cam1","key_id":-1,"key":"{}"}}}}"#,
            key(1)
        ))
        .starts_with("invalid command: invalid value")
    );
    assert_eq!(h.state(), before);
}

#[test]
fn a_bad_key_is_never_echoed() {
    let mut h = Harness::spec_config();
    let secret = format!("{}g", "7".repeat(63));
    let response = h.send(&add_key_line("cam1", 1, &secret));
    assert_eq!(response["status"], "error");
    assert!(!response.to_string().contains("777"), "{response}");
}

#[test]
fn key_commands_need_init_first() {
    let mut h = Harness::default();
    let not_initialized = "not initialized: the first command must be init";
    assert_eq!(h.error(&add_key_line("cam1", 1, &key(1))), not_initialized);
    assert_eq!(h.error(&revoke_key_line("cam1", 0)), not_initialized);
}

// ---- revoke_key ----

#[test]
fn revoking_an_unknown_key_is_rejected() {
    let mut h = Harness::spec_config();
    let before = h.state();
    assert_eq!(
        h.error(&revoke_key_line("cam2", 7)),
        "cam2 key 7 is not provisioned"
    );
    assert_eq!(
        h.error(&revoke_key_line("cam2", 300)),
        "key_id must be from 0 to 255, got 300"
    );
    assert_eq!(
        h.error(&revoke_key_line("cam0", 0)),
        "camera must be cam1 or cam2"
    );
    assert_eq!(h.state(), before);
}

#[test]
fn revoking_twice_is_a_no_op() {
    let mut h = Harness::spec_config();
    let first = revoke(&mut h, "cam1", 0);
    let second = revoke(&mut h, "cam1", 0);
    assert_eq!(first, second);
    assert_eq!(
        first["cameras"]["cam1"]["keys"],
        json!([entry(0, "revoked")])
    );
}

#[test]
fn revoking_the_key_in_use_stops_the_camera_until_it_is_re_keyed() {
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(1, 5, 1000));
    revoke(&mut h, "cam1", 0);
    assert_eq!(
        reject(&mut h, &Frame::new(1, 6, 1050)),
        "cam1 key 0 is revoked"
    );
    add(&mut h, "cam1", 1, &key(1));
    // The replay floor survives the revocation.
    assert_eq!(
        reject(&mut h, &cam1(1, 5, 1050)),
        "stale or replayed frame: cam1 seq 5"
    );
    accept(&mut h, &cam1(1, 6, 1050));
    assert_eq!(
        keys(&mut h, "cam1"),
        json!([entry(0, "revoked"), entry(1, "active")])
    );
}

#[test]
fn a_retired_key_can_be_revoked() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    accept(&mut h, &cam1(1, 1, 1000));
    let state = revoke(&mut h, "cam1", 0);
    assert_eq!(
        state["cameras"]["cam1"]["keys"],
        json!([entry(0, "revoked"), entry(1, "active")])
    );
    assert_eq!(add_error(&mut h, "cam1", 0, KEY1), "cam1 key 0 is revoked");
}

#[test]
fn revoking_an_unused_key_leaves_the_key_in_use_alone() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    revoke(&mut h, "cam1", 1);
    accept(&mut h, &Frame::new(1, 1, 1000));
    assert_eq!(
        keys(&mut h, "cam1"),
        json!([entry(0, "active"), entry(1, "revoked")])
    );
}

#[test]
fn revoking_drops_only_that_keys_waiting_frames() {
    let mut h = Harness::spec_config();
    add(&mut h, "cam1", 1, &key(1));
    accept(&mut h, &Frame::new(1, 1, 1000));
    accept(&mut h, &Frame::new(1, 2, 1050));
    accept(&mut h, &cam1(1, 3, 1100));
    let state = revoke(&mut h, "cam1", 0);
    let cam1_state = &state["cameras"]["cam1"];
    assert_eq!(cam1_state["pending"], json!([3]));
    // Dropping waiting frames doesn't reopen their sequence numbers.
    assert_eq!(cam1_state["last_seq"], 3);
    assert_eq!(cam1_state["last_timestamp"], 1100);
    assert_eq!(
        reject(&mut h, &cam1(1, 2, 1050)),
        "stale or replayed frame: cam1 seq 2"
    );
    // The other camera is untouched.
    assert_eq!(state["cameras"]["cam2"], h.state()["cameras"]["cam2"]);
}

#[test]
fn a_dropped_frame_is_never_paired() {
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(1, 1, 1000));
    revoke(&mut h, "cam1", 0);
    let response = accept(&mut h, &Frame::new(2, 1, 1002));
    assert_eq!(response["synced"], json!([]));
    assert_eq!(h.state()["cameras"]["cam2"]["pending"], json!([1]));
}
