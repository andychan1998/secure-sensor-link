//! Throughput, one kind of frame at a time, straight through the release binary.
//! A plain `cargo test` skips it; run it with
//!
//! ```text
//! scripts/bench.sh
//! ```
//!
//! which runs `cargo test --release --test bench -- --ignored --nocapture`.
//!
//! Each case sends `init`, then a stream of one kind of frame, alternating
//! between the cameras so that accepted frames pair, three times:
//!
//! - small frames: a one-node tree, every frame accepted and paired;
//! - largest accepted frames: a 1,024-node tree, the most the receiver accepts,
//!   every frame accepted and paired;
//! - largest possible frames: 65,535 bytes of payload, so the tag is checked
//!   and then the tree is refused, the most work any frame can cause.
//!
//! It reports frames per second and the time per frame for each run. The time
//! covers writing every line, the receiver's work and reading every response.
//! The figures depend on the machine: use a release build on an idle machine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod support;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use support::{Frame, complete_tree, init_line, largest_payload, leaf, receive_line};

/// Runs of each case.
const RUNS: usize = 3;

/// One kind of frame to measure.
struct Case {
    name: &'static str,
    payload: Vec<u8>,
    frames: u32,
    /// Whether the receiver accepts these frames (or refuses every one).
    accepted: bool,
}

/// Stops the receiver if a run fails partway.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            self.0.kill().ok();
            self.0.wait().ok();
        }
    }
}

/// `init`, then the case's frames, alternating between the cameras: each
/// cam2 frame is 2 ms after its cam1 partner, well within the pair window.
/// Also returns the size in bytes of one frame.
fn input(case: &Case) -> (Vec<u8>, usize) {
    let mut input = init_line(50, 5, 20, 16).into_bytes();
    input.push(b'\n');
    let mut frame_len = 0;
    for n in 0..case.frames {
        let camera = u8::try_from(n % 2).unwrap() + 1;
        let seq = n / 2 + 1;
        let timestamp = 1_000 + i64::from(seq) * 50 + if camera == 2 { 2 } else { 0 };
        let frame = Frame::new(camera, seq, timestamp).payload(case.payload.clone());
        frame_len = frame.bytes().len();
        input.extend_from_slice(receive_line(&frame.hex()).as_bytes());
        input.push(b'\n');
    }
    (input, frame_len)
}

/// Sends `input` through the binary and reads every response. Returns the
/// time taken, the number of responses and how many of them were ok.
fn run(input: &[u8]) -> (Duration, u32, u32) {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_secure-sensor-link"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let mut stdin = child.0.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.0.stdout.take().unwrap());

    let start = Instant::now();
    let (responses, ok) = thread::scope(|scope| {
        scope.spawn(move || {
            stdin.write_all(input).unwrap();
            // Dropping stdin ends the input, so the receiver exits.
        });
        let mut line = Vec::new();
        let (mut responses, mut ok) = (0, 0);
        loop {
            line.clear();
            if stdout.read_until(b'\n', &mut line).unwrap() == 0 {
                break (responses, ok);
            }
            responses += 1;
            if line.starts_with(br#"{"status":"ok""#) {
                ok += 1;
            }
        }
    });
    let elapsed = start.elapsed();
    assert!(child.0.wait().unwrap().success());
    (elapsed, responses, ok)
}

#[test]
#[ignore = "a benchmark: run it with scripts/bench.sh"]
#[expect(
    clippy::print_stderr,
    reason = "the figures are the benchmark's report"
)]
fn throughput_for_each_kind_of_frame() {
    let cases = [
        Case {
            name: "small frames (one-node tree)",
            payload: leaf(7),
            frames: 300_000,
            accepted: true,
        },
        Case {
            name: "largest accepted frames (1,024-node tree)",
            payload: complete_tree(1_024),
            frames: 10_000,
            accepted: true,
        },
        Case {
            name: "largest possible frames (tag checked, tree refused)",
            payload: largest_payload(),
            frames: 2_000,
            accepted: false,
        },
    ];
    for case in &cases {
        let (input, frame_len) = input(case);
        eprintln!(
            "{}: {frame_len} bytes each, {} frames",
            case.name, case.frames
        );
        for _ in 0..RUNS {
            let (elapsed, responses, ok) = run(&input);
            assert_eq!(responses, case.frames + 1, "one response per line");
            let expected_ok = if case.accepted { case.frames + 1 } else { 1 };
            assert_eq!(ok, expected_ok, "{}: unexpected refusals", case.name);
            let seconds = elapsed.as_secs_f64();
            eprintln!(
                "  {:.0} frames per second, {:.1} µs per frame ({:.2} s)",
                f64::from(case.frames) / seconds,
                seconds * 1e6 / f64::from(case.frames),
                seconds,
            );
        }
    }
}
