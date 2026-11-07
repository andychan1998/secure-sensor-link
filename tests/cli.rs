//! Runs the real binary end to end over stdin and stdout.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use std::io::Write;
use std::process::{Command, Stdio};

use support::{Frame, GET_STATE, init_line, receive_line};

/// Runs the receiver binary on `input` and returns its stdout lines.
fn run(input: &[u8]) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secure-sensor-link"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "exit status {}", output.status);
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn processes_commands_in_order_with_one_line_each() {
    let input = format!(
        "{}\n{}\nnot json\n{}\n",
        init_line(50, 5, 20, 4),
        receive_line(&Frame::new(1, 1, 1000).hex()),
        GET_STATE
    );
    let responses = run(input.as_bytes());
    assert_eq!(responses.len(), 4);
    assert_eq!(responses[1]["payload"]["frame"]["seq"], 1);
    assert_eq!(responses[2]["status"], "error");
    assert_eq!(
        responses[3]["payload"]["cameras"]["cam1"]["pending"],
        serde_json::json!([1])
    );
}

#[test]
fn a_last_line_without_a_newline_is_still_processed() {
    let responses = run(GET_STATE.as_bytes());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["status"], "error");
}

#[test]
fn a_huge_line_without_a_newline_gets_one_error() {
    let input = vec![b'a'; 3 * 1024 * 1024];
    let responses = run(&input);
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0]["payload"]["message"],
        "input line exceeds 262144 bytes"
    );
}

#[test]
fn empty_input_exits_cleanly_with_no_output() {
    assert!(run(b"").is_empty());
}
