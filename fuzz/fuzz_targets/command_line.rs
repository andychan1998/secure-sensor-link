//! Any input lines, after a valid `init`, through the whole protocol: every
//! line gets one well-formed response with a short message, and nothing
//! reaches an internal error or halts the receiver.
//!
//! Run with the seeds and the dictionary, so the fuzzer starts from real
//! commands and knows the protocol's words (see the README).

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_sensor_link::protocol::Session;

const INIT: &str = r#"{"command":"init","parameters":{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"persist_interval":3,"keys":{"cam1":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","cam2":"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"}}}"#;

/// Error messages stay this short whatever the input (the longest is a JSON
/// error capped at 200 characters plus a prefix).
const MAX_MESSAGE_LEN: usize = 256;

fuzz_target!(|data: &[u8]| {
    let mut session = Session::default();
    let init = respond(&mut session, INIT.as_bytes());
    assert_eq!(init["status"], "ok");
    for line in data.split(|&byte| byte == b'\n') {
        respond(&mut session, line);
    }
});

fn respond(session: &mut Session, line: &[u8]) -> serde_json::Value {
    let response =
        serde_json::to_value(session.handle_line(line)).expect("responses always serialize");
    let status = response["status"].as_str();
    assert!(matches!(status, Some("ok" | "error")), "{response}");
    if let Some(message) = response["payload"]["message"].as_str() {
        assert_ne!(
            message,
            "internal error",
            "after {:?}",
            String::from_utf8_lossy(line)
        );
        assert!(!message.starts_with("receiver halted"), "{message}");
        assert!(message.len() <= MAX_MESSAGE_LEN, "{message}");
    }
    response
}
