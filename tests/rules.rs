//! The receiver's rules and design decisions, one test each, through the real
//! protocol.

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
use support::{
    Frame, GET_STATE, Harness, KEY1, KEY2, add_key_line, init_line, leaf, receive_line,
    revoke_key_line,
};

fn receive(harness: &mut Harness, frame: &Frame) -> Value {
    harness.send(&receive_line(&frame.hex()))
}

fn accept(harness: &mut Harness, frame: &Frame) -> Value {
    harness.ok(&receive_line(&frame.hex()))
}

fn reject(harness: &mut Harness, frame: &Frame) -> String {
    let before = harness.state();
    let message = harness.error(&receive_line(&frame.hex()));
    assert_eq!(
        harness.state(),
        before,
        "a rejected frame changed the state"
    );
    message
}

// ---- Order of checks ----

#[test]
fn a_forged_frame_with_an_old_seq_reports_authentication_failure() {
    // The tag is checked before replay, so a forgery is never reported as a replay.
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(1, 5, 1000));
    let forged = Frame::new(1, 3, 900).key(KEY2);
    assert_eq!(reject(&mut h, &forged), "authentication failed for cam1");
}

#[test]
fn a_stale_frame_is_reported_as_stale_even_with_a_bad_timestamp_or_tree() {
    // Replay is checked before the timestamp and the tree.
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(1, 5, 1000));
    let stale_negative = Frame::new(1, 5, -1);
    assert_eq!(
        reject(&mut h, &stale_negative),
        "stale or replayed frame: cam1 seq 5"
    );
    let stale_bad_tree = Frame::new(1, 4, 1000).payload(vec![0x07]);
    assert_eq!(
        reject(&mut h, &stale_bad_tree),
        "stale or replayed frame: cam1 seq 4"
    );
}

#[test]
fn a_negative_timestamp_is_malformed() {
    let mut h = Harness::spec_config();
    assert_eq!(
        reject(&mut h, &Frame::new(2, 1, -5)),
        "malformed frame: negative timestamp -5"
    );
    assert_eq!(
        reject(&mut h, &Frame::new(2, 1, i64::MIN)),
        format!("malformed frame: negative timestamp {}", i64::MIN)
    );
}

#[test]
fn layout_errors_name_the_problem() {
    let mut h = Harness::spec_config();
    let mut version_3 = Frame::new(1, 1, 1000);
    version_3.version = 3;
    assert_eq!(
        reject(&mut h, &version_3),
        "malformed frame: unsupported version 3"
    );
    let mut camera_3 = Frame::new(1, 1, 1000);
    camera_3.camera = 3;
    assert_eq!(
        reject(&mut h, &camera_3),
        "malformed frame: unknown camera 0x03"
    );
    let mut wrong_len = Frame::new(1, 1, 1000);
    wrong_len.payload_len = Some(2);
    assert_eq!(
        reject(&mut h, &wrong_len),
        "malformed frame: payload_len 2 implies a 50-byte frame, got 49 bytes"
    );
    let message = h.error(&receive_line("0101"));
    assert_eq!(
        message,
        "malformed frame: 2 bytes is shorter than the 48-byte minimum"
    );
    assert_eq!(
        h.error(&receive_line("abc")),
        "malformed frame: odd number of hex characters (3)"
    );
    assert_eq!(h.error(&receive_line("")), "malformed frame: empty frame");
    assert_eq!(
        h.error(&receive_line("zz")),
        "malformed frame: not valid hex"
    );
}

#[test]
fn the_other_cameras_key_fails_authentication() {
    let mut h = Harness::spec_config();
    assert_eq!(
        reject(&mut h, &Frame::new(1, 1, 1000).key(KEY2)),
        "authentication failed for cam1"
    );
    assert_eq!(
        reject(&mut h, &Frame::new(2, 1, 1000).key(KEY1)),
        "authentication failed for cam2"
    );
}

// ---- Q2: a valid tag with an invalid payload doesn't count ----

#[test]
fn a_frame_rejected_for_its_payload_does_not_use_up_its_seq() {
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(1, 1, 1000));
    let bad = Frame::new(1, 3, 1100).payload(vec![0x02]);
    assert!(reject(&mut h, &bad).starts_with("malformed frame: tree has byte 0x02"));
    // Seq 3 wasn't accepted, so a late seq 2 and then a good seq 3 still are.
    accept(&mut h, &Frame::new(1, 2, 1050));
    accept(&mut h, &Frame::new(1, 3, 1100).payload(leaf(9)));
}

// ---- Q1: tree limits ----

/// A chain of `n` nodes, each the right child of the one before.
fn right_chain(n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..n {
        bytes.extend(leaf(i32::try_from(i).unwrap())[..5].iter());
        bytes.push(0x00);
    }
    bytes.push(0x00);
    bytes
}

#[test]
fn trees_at_the_depth_limit_pass_and_deeper_ones_are_rejected() {
    let mut h = Harness::spec_config();
    let ok = accept(&mut h, &Frame::new(1, 1, 1000).payload(right_chain(64)));
    assert_eq!(ok["frame"]["tree"].as_array().unwrap().len(), 64 * 2 - 1);
    assert_eq!(
        reject(&mut h, &Frame::new(1, 2, 1050).payload(right_chain(65))),
        "malformed frame: tree is deeper than 64 levels"
    );
}

// ---- Q3: a pair window wide enough to match two frames ----

#[test]
fn a_wide_window_pairs_the_two_oldest_frames_not_the_closest() {
    // With a 30 ms window and a 50 ms period, cam2's frame at 1030 is within the
    // window of both cam1 frames, and closer to 1050. Step 1 compares the oldest
    // frame in each queue, so it pairs with 1000.
    let mut h = Harness::default();
    h.ok(&init_line(50, 5, 30, 4));
    accept(&mut h, &Frame::new(1, 1, 1000));
    accept(&mut h, &Frame::new(1, 2, 1050));
    let response = accept(&mut h, &Frame::new(2, 1, 1030));
    assert_eq!(
        response["synced"],
        json!([{"timestamp": 1015, "cam1": 1, "cam2": 1}])
    );
    assert_eq!(h.state()["cameras"]["cam1"]["pending"], json!([2]));
}

#[test]
fn with_a_wide_window_one_lost_frame_can_shift_every_later_pair() {
    // The cost of following step 1, recorded with the decision: when the window
    // reaches period_ms - max_jitter_ms, a lost frame makes each later frame pair
    // with the other camera's frame from one period earlier. Configuration
    // avoids it by keeping 2 * pair_window_ms below period_ms - max_jitter_ms.
    let mut h = Harness::default();
    h.ok(&init_line(50, 5, 45, 4));
    // cam1's seq 1 is lost; cam2 runs 5 ms behind.
    accept(&mut h, &Frame::new(2, 1, 1005));
    let second = accept(&mut h, &Frame::new(1, 2, 1050));
    assert_eq!(
        second["synced"],
        json!([{"timestamp": 1027, "cam1": 2, "cam2": 1}])
    );
    accept(&mut h, &Frame::new(2, 2, 1055));
    let third = accept(&mut h, &Frame::new(1, 3, 1100));
    assert_eq!(
        third["synced"],
        json!([{"timestamp": 1077, "cam1": 3, "cam2": 2}])
    );
}

// ---- Arithmetic at the extremes ----

#[test]
fn corrected_timestamps_beyond_64_bits_are_exact() {
    let mut h = Harness::default();
    h.ok(&init_line(60_000, 0, 0, 4));
    accept(&mut h, &Frame::new(1, 0, i64::MAX));
    let ok = accept(&mut h, &Frame::new(1, u32::MAX, 0));
    assert_eq!(
        ok["frame"]["timestamp"],
        json!(9_223_629_734_892_475_807_u64)
    );
    assert_eq!(ok["frame"]["corrected"], json!(true));
}

#[test]
fn after_the_largest_seq_nothing_more_is_accepted() {
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(2, u32::MAX, 1000));
    assert_eq!(
        reject(&mut h, &Frame::new(2, u32::MAX, 1050)),
        format!("stale or replayed frame: cam2 seq {}", u32::MAX)
    );
}

#[test]
fn the_first_frame_may_have_seq_zero_and_any_timestamp() {
    let mut h = Harness::spec_config();
    let ok = accept(&mut h, &Frame::new(1, 0, 0));
    assert_eq!(ok["frame"]["timestamp"], json!(0));
    let ok = accept(&mut h, &Frame::new(2, 7, i64::MAX));
    assert_eq!(ok["frame"]["timestamp"], json!(i64::MAX));
}

// ---- Commands and input rules ----

#[test]
fn commands_before_init_and_a_second_init_are_errors() {
    let mut h = Harness::default();
    assert!(h.error(GET_STATE).starts_with("not initialized"));
    assert!(
        h.error(&receive_line(&Frame::new(1, 1, 1000).hex()))
            .starts_with("not initialized")
    );
    h.ok(&init_line(50, 5, 20, 4));
    assert_eq!(h.error(&init_line(50, 5, 20, 4)), "already initialized");
}

#[test]
fn a_failed_init_changes_nothing_and_can_be_retried() {
    let mut h = Harness::default();
    assert_eq!(
        h.error(&init_line(50, 50, 20, 4)),
        "max_jitter_ms must be from 0 to 49, got 50"
    );
    assert!(h.error(GET_STATE).starts_with("not initialized"));
    h.ok(&init_line(50, 5, 20, 4));
}

#[test]
fn key_errors_never_repeat_the_key() {
    let mut h = Harness::default();
    let short = &KEY1[..63];
    let line = json!({"command": "init", "parameters": {
        "period_ms": 50, "max_jitter_ms": 5, "pair_window_ms": 20, "max_pending": 4,
        "keys": {"cam1": short, "cam2": KEY2}}})
    .to_string();
    let message = h.error(&line);
    assert_eq!(
        message,
        "keys.cam1 must be 64 hex characters (a 32-byte key), got 63"
    );
    assert!(!message.contains(&KEY1[..16]));

    let not_hex = format!("{}zz", &KEY2[..62]);
    let line = json!({"command": "init", "parameters": {
        "period_ms": 50, "max_jitter_ms": 5, "pair_window_ms": 20, "max_pending": 4,
        "keys": {"cam1": KEY1, "cam2": not_hex}}})
    .to_string();
    let message = h.error(&line);
    assert_eq!(message, "keys.cam2 must contain only hex characters");
}

#[test]
fn strict_parsing_rejects_anything_unexpected() {
    let mut h = Harness::spec_config();
    let bad_lines = [
        // Unknown fields, at the top level and in parameters.
        r#"{"command":"get_state","parameters":{},"extra":1}"#,
        r#"{"command":"get_state","parameters":{"extra":1}}"#,
        // parameters is required, and must be an object.
        r#"{"command":"get_state"}"#,
        r#"{"command":"get_state","parameters":[]}"#,
        // Duplicate keys.
        r#"{"command":"get_state","command":"get_state","parameters":{}}"#,
        // The command must be a known string.
        r#"{"command":"GET_STATE","parameters":{}}"#,
        r#"{"command":7,"parameters":{}}"#,
        // Not an object, or not JSON.
        r#"["get_state"]"#,
        "",
        "get_state",
    ];
    for line in bad_lines {
        let response = h.send(line);
        assert_eq!(response["status"], "error", "{line} -> {response}");
    }
    // serde would accept arrays in place of these objects; strict parsing doesn't.
    let mut fresh = Harness::default();
    let array_params = format!(
        r#"{{"command":"init","parameters":[50,5,20,4,{{"cam1":"{KEY1}","cam2":"{KEY2}"}}]}}"#
    );
    assert_eq!(
        fresh.error(&array_params),
        "invalid command: expected a JSON object"
    );
    let array_keys = format!(
        r#"{{"command":"init","parameters":{{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"keys":["{KEY1}","{KEY2}"]}}}}"#
    );
    assert_eq!(
        fresh.error(&array_keys),
        "invalid command: expected a JSON object"
    );
}

#[test]
fn field_order_does_not_matter() {
    let mut h = Harness::spec_config();
    h.ok(r#"{"parameters":{},"command":"get_state"}"#);
    let frame = Frame::new(1, 1, 1000).hex();
    h.ok(&format!(
        r#"{{"parameters":{{"frame":"{frame}"}},"command":"receive"}}"#
    ));
}

#[test]
fn numbers_must_be_whole_and_in_range() {
    let mut h = Harness::default();
    for bad in [
        r#""50""#,
        "50.0",
        "5e1",
        "true",
        "-1",
        "null",
        "18446744073709551616",
    ] {
        let line = format!(
            r#"{{"command":"init","parameters":{{"period_ms":{bad},"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"keys":{{"cam1":"{KEY1}","cam2":"{KEY2}"}}}}}}"#
        );
        let message = h.error(&line);
        assert!(message.starts_with("invalid command"), "{bad}: {message}");
    }
    h.ok(&init_line(50, 5, 20, 4));
}

#[test]
fn uppercase_hex_is_accepted() {
    let mut h = Harness::spec_config();
    accept(&mut h, &Frame::new(1, 1, 1000));
    let upper = Frame::new(1, 2, 1050).hex().to_uppercase();
    h.ok(&receive_line(&upper));
}

#[test]
fn a_rejected_frame_is_reported_once_and_the_receiver_carries_on() {
    let mut h = Harness::spec_config();
    for _ in 0..3 {
        assert_eq!(
            reject(&mut h, &Frame::new(1, 1, 1000).key(KEY2)),
            "authentication failed for cam1"
        );
    }
    assert_eq!(
        receive(&mut h, &Frame::new(1, 1, 1000))["status"],
        json!("ok")
    );
}

// ---- What error messages may repeat, and JSON escapes ----

/// Key-shaped text that must never come back in a response.
const SECRET: &str = "5ec2e7ababababababababababababababababababababababababababababab";

#[test]
fn the_secret_is_key_sized() {
    assert_eq!(SECRET.len(), 64);
}

fn assert_not_echoed(response: &Value, line: &str) {
    let text = response.to_string();
    assert_eq!(response["status"], "error", "{line}\n{text}");
    assert!(
        !text.contains("5ec2e7") && !text.contains("abababab"),
        "echoed the value: {line}\n{text}"
    );
}

/// `line` with the JSON value at `path` replaced by `value`.
fn with_value(line: &str, path: &[&str], value: Value) -> String {
    let mut json: Value = serde_json::from_str(line).unwrap();
    let mut target = &mut json;
    for key in path {
        target = &mut target[*key];
    }
    *target = value;
    json.to_string()
}

#[test]
fn no_value_from_the_input_is_ever_repeated() {
    let backslash = char::from(0x5c_u8);
    let escaped_secret = format!("{backslash}u0035{}", &SECRET[1..]);
    let secret = || Value::String(SECRET.to_owned());
    let init = init_line(50, 5, 20, 4);
    let add_key = add_key_line("cam1", 1, KEY2);
    let revoke_key = revoke_key_line("cam1", 0);

    // Lines a fresh receiver sees: init's parameters.
    let mut fresh = vec![format!("\"{SECRET}\"")];
    for field in [
        "period_ms",
        "max_jitter_ms",
        "pair_window_ms",
        "max_pending",
        "persist_interval",
        "keys",
    ] {
        fresh.push(with_value(&init, &["parameters", field], secret()));
    }
    for camera in ["cam1", "cam2"] {
        let long = Value::String(format!("{SECRET}00"));
        fresh.push(with_value(&init, &["parameters", "keys", camera], long));
        let escaped = with_value(&init, &["parameters", "keys", camera], json!("ESCAPED"));
        fresh.push(escaped.replace("ESCAPED", &escaped_secret));
    }
    for line in &fresh {
        let mut h = Harness::default();
        assert_not_echoed(&h.send(line), line);
    }

    // Lines an initialized receiver sees.
    let mut later = vec![
        json!({"command": SECRET, "parameters": {}}).to_string(),
        json!({"command": "get_state", "parameters": SECRET}).to_string(),
        with_value(
            &receive_line(SECRET),
            &[],
            json!({"command": "receive", "parameters": {"frame": SECRET}}),
        ),
        with_value(&add_key, &["parameters", "camera"], secret()),
        with_value(&add_key, &["parameters", "key_id"], secret()),
        with_value(
            &add_key,
            &["parameters", "key"],
            Value::String(format!("{SECRET}00")),
        ),
        with_value(&revoke_key, &["parameters", "camera"], secret()),
        with_value(&revoke_key, &["parameters", "key_id"], secret()),
    ];
    let escaped = with_value(&add_key, &["parameters", "key"], json!("ESCAPED"));
    later.push(escaped.replace("ESCAPED", &escaped_secret));
    let mut h = Harness::spec_config();
    for line in &later {
        assert_not_echoed(&h.send(line), line);
    }
}

#[test]
fn json_escapes_are_accepted_except_in_keys() {
    let backslash = char::from(0x5c_u8);
    let mut h = Harness::spec_config();
    // A command name, camera names and a frame, each with an escape.
    h.ok(&format!(
        r#"{{"command":"get{backslash}u005fstate","parameters":{{}}}}"#
    ));
    let frame = Frame::new(1, 1, 1000).hex();
    let escaped_frame = format!("{backslash}u00{:x}{}", frame.as_bytes()[0], &frame[1..]);
    let accepted = h.ok(&format!(
        r#"{{"command":"receive","parameters":{{"frame":"{escaped_frame}"}}}}"#
    ));
    assert_eq!(accepted["frame"]["seq"], 1);
    h.ok(&format!(
        r#"{{"command":"add_key","parameters":{{"camera":"cam{backslash}u0031","key_id":1,"key":"{KEY2}"}}}}"#
    ));
    h.ok(&format!(
        r#"{{"command":"revoke_key","parameters":{{"camera":"cam{backslash}u0031","key_id":1}}}}"#
    ));
    // A key with an escape is refused, and nothing changes.
    let before = h.state();
    let escaped_key = format!("{backslash}u0030{}", &KEY1[1..]);
    assert!(
        h.error(&format!(
            r#"{{"command":"add_key","parameters":{{"camera":"cam1","key_id":2,"key":"{escaped_key}"}}}}"#
        ))
        .starts_with("invalid command: keys must be plain strings of hex, without escape sequences")
    );
    assert_eq!(h.state(), before);
    let mut fresh = Harness::default();
    let init = init_line(50, 5, 20, 4).replacen(&KEY1[..1], &format!("{backslash}u0030"), 1);
    assert!(fresh.error(&init).contains("without escape sequences"));
}
