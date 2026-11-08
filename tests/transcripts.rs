//! Runs every transcript under `tests/transcripts/`, and the demo session in
//! `demo/session.txt`, through the real protocol.
//!
//! A transcript is plain text. `> ` starts a command line; the next line is its
//! expected response: `< ` for an exact match (as JSON, so field order and
//! spacing don't matter) or `<~ ` for a partial match (every field given must
//! match; fields left out are ignored). `#` lines and blank lines are comments.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::path::{Path, PathBuf};

use secure_sensor_link::protocol;
use serde_json::Value;

#[derive(Debug)]
struct Step {
    line_number: usize,
    command: String,
    expected: Value,
    partial: bool,
}

fn parse(path: &Path) -> Vec<Step> {
    let text = fs::read_to_string(path).unwrap();
    let mut steps = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let place = format!("{}:{line_number}", path.display());
        if let Some(command) = line.strip_prefix("> ") {
            assert!(pending.is_none(), "{place}: command without a response");
            pending = Some((line_number, command.to_owned()));
        } else if let Some((partial, expected)) = line
            .strip_prefix("<~ ")
            .map(|e| (true, e))
            .or_else(|| line.strip_prefix("< ").map(|e| (false, e)))
        {
            let (command_line, command) = pending.take().unwrap_or_else(|| {
                panic!("{place}: response without a command");
            });
            steps.push(Step {
                line_number: command_line,
                command,
                expected: serde_json::from_str(expected)
                    .unwrap_or_else(|e| panic!("{place}: bad expected JSON: {e}")),
                partial,
            });
        } else {
            assert!(
                line.trim().is_empty() || line.starts_with('#'),
                "{place}: unrecognized line"
            );
        }
    }
    assert!(
        pending.is_none(),
        "{}: last command has no response",
        path.display()
    );
    steps
}

/// Every field in `expected` matches `actual`; arrays must match exactly.
fn matches_partially(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(want), Value::Object(got)) => want
            .iter()
            .all(|(k, v)| got.get(k).is_some_and(|g| matches_partially(v, g))),
        _ => expected == actual,
    }
}

fn run_transcript(path: &Path) {
    let steps = parse(path);
    assert!(!steps.is_empty(), "{}: no steps", path.display());
    let mut input = String::new();
    for step in &steps {
        input.push_str(&step.command);
        input.push('\n');
    }
    let mut output = Vec::new();
    protocol::run(input.as_bytes(), &mut output).unwrap();
    let responses: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        responses.len(),
        steps.len(),
        "{}: one response per command",
        path.display()
    );
    for (step, actual) in steps.iter().zip(&responses) {
        let ok = if step.partial {
            matches_partially(&step.expected, actual)
        } else {
            &step.expected == actual
        };
        assert!(
            ok,
            "{}:{}\n  command:  {}\n  expected: {}\n  actual:   {}",
            path.display(),
            step.line_number,
            step.command,
            step.expected,
            actual
        );
    }
}

fn transcripts(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            transcripts(&path, found);
        } else if path.extension().is_some_and(|e| e == "txt") {
            found.push(path);
        }
    }
}

#[test]
fn all_transcripts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    transcripts(&root.join("tests/transcripts"), &mut found);
    found.sort();
    found.push(root.join("demo/session.txt"));
    assert!(!found.is_empty());
    for path in &found {
        run_transcript(path);
    }
}
