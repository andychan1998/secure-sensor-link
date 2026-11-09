//! A long run through the real binary. It sends a stream of commands mixing
//! valid frames from both cameras, full-size trees, the largest frame there can
//! be, lost frames, forgeries, replays, lines that aren't JSON, state queries,
//! key rotations, revocations and restarts, and checks that:
//!
//! - every command gets a response of the expected kind, never an internal
//!   error, and within 10 seconds, so the receiver never hangs;
//! - the receiver's memory stops growing once it has warmed up;
//!
//! and it reports how many commands per second went through.
//!
//! The default size keeps `cargo test` quick. For a stress run, set the number
//! of commands:
//!
//! ```text
//! SOAK_COMMANDS=1000000 cargo test --release --test soak -- --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use support::{
    Frame, GET_STATE, RESTART, add_key_line, complete_tree, init_line_with_interval, key_for,
    largest_payload, leaf, receive_line, revoke_key_line,
};

/// Commands sent when `SOAK_COMMANDS` isn't set: fewer in debug builds, which
/// are about 30 times slower.
const DEFAULT_COMMANDS: u32 = if cfg!(debug_assertions) {
    5_000
} else {
    50_000
};
/// The longest the receiver may take to answer one command.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// How much the receiver's memory may grow after warming up.
const GROWTH_LIMIT_KIB: u64 = 2 * 1024;
/// The most memory the receiver may use at any point.
const PEAK_LIMIT_KIB: u64 = 64 * 1024;

/// The spec's example period, as configured by `init_line_with_interval`.
const PERIOD_MS: i64 = 50;
const PERSIST_INTERVAL: u32 = 10;
/// Rotations stop well before a camera runs out of its 256 key ids.
const LAST_KEY_ID: u8 = 250;

/// What a command's response must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Ok,
    Error,
}

/// A small deterministic random number generator (xorshift), so every run
/// sends the same stream and a failure can be reproduced.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// A distinct key for each camera and key id.
fn key_hex(camera: u8, key_id: u8) -> String {
    if key_id == 0 {
        key_for(camera).to_owned()
    } else {
        format!("{camera:02x}{key_id:02x}").repeat(16)
    }
}

/// One camera's side of the stream.
struct Camera {
    number: u8,
    name: &'static str,
    /// The key the camera signs with.
    key_id: u8,
    /// The last seq sent in a valid frame.
    seq: u32,
    /// The last valid frame sent, for replaying.
    last: Option<String>,
}

impl Camera {
    const fn new(number: u8, name: &'static str) -> Self {
        Self {
            number,
            name,
            key_id: 0,
            seq: 0,
            last: None,
        }
    }

    /// The camera's next frame. Now and then a seq is skipped, as if lost.
    fn next_frame(&mut self, payload: Vec<u8>, rng: &mut Rng) -> Frame {
        self.seq += if rng.below(20) == 0 { 2 } else { 1 };
        self.frame(self.seq, payload, rng)
    }

    /// A frame with `seq` carrying `payload`, signed with the camera's key.
    fn frame(&self, seq: u32, payload: Vec<u8>, rng: &mut Rng) -> Frame {
        let jitter = i64::try_from(rng.below(5)).unwrap();
        let timestamp = 1_000 + i64::from(seq) * PERIOD_MS + jitter;
        let frame = Frame::new(self.number, seq, timestamp).payload(payload);
        if self.key_id == 0 {
            frame
        } else {
            frame.v2(self.key_id, &key_hex(self.number, self.key_id))
        }
    }
}

/// A one-node tree with a random value.
fn small_tree(rng: &mut Rng) -> Vec<u8> {
    leaf(i32::try_from(rng.below(1_000)).unwrap())
}

/// Commands on their way to the receiver, each announced to the checker first.
struct Stream<W: Write> {
    out: BufWriter<W>,
    expect: mpsc::Sender<Expect>,
    sent: u32,
}

impl<W: Write> Stream<W> {
    fn send(&mut self, line: &str, kind: Expect) {
        self.expect.send(kind).unwrap();
        writeln!(self.out, "{line}").unwrap();
        self.sent += 1;
    }
}

/// Writes about `count` commands to `out`, sending what each response must be
/// to `expect` just before writing the command.
fn write_stream(count: u32, out: impl Write, expect: mpsc::Sender<Expect>) {
    let mut stream = Stream {
        out: BufWriter::new(out),
        expect,
        sent: 0,
    };
    let mut rng = Rng(0x5eed_cafe_f00d_d00d);
    let mut cameras = [Camera::new(1, "cam1"), Camera::new(2, "cam2")];
    let full_tree = complete_tree(1_024);
    let largest = largest_payload();

    stream.send(
        &init_line_with_interval(u64::from(PERSIST_INTERVAL)),
        Expect::Ok,
    );
    while stream.sent < count {
        let camera = &mut cameras[usize::from(rng.below(2) == 1)];
        match rng.below(100) {
            // A replay of the camera's last valid frame.
            70..=74 if camera.last.is_some() => {
                stream.send(&receive_line(camera.last.as_ref().unwrap()), Expect::Error);
            }
            // A forgery: the next frame with one bit of its tag flipped.
            75..=79 => {
                let payload = small_tree(&mut rng);
                let mut hex = camera.frame(camera.seq + 1, payload, &mut rng).hex();
                let last = if hex.ends_with('0') { "1" } else { "0" };
                hex.replace_range(hex.len() - 1.., last);
                stream.send(&receive_line(&hex), Expect::Error);
            }
            80..=82 => stream.send("not json", Expect::Error),
            83..=84 => stream.send(GET_STATE, Expect::Ok),
            // A key rotation: the camera's next frames use the new key.
            85..=89 if camera.key_id < LAST_KEY_ID => {
                camera.key_id += 1;
                let key = key_hex(camera.number, camera.key_id);
                stream.send(
                    &add_key_line(camera.name, u64::from(camera.key_id), &key),
                    Expect::Ok,
                );
            }
            // A revocation, then a new key so the camera can carry on.
            90..=91 if camera.key_id < LAST_KEY_ID => {
                stream.send(
                    &revoke_key_line(camera.name, u64::from(camera.key_id)),
                    Expect::Ok,
                );
                camera.key_id += 1;
                let key = key_hex(camera.number, camera.key_id);
                stream.send(
                    &add_key_line(camera.name, u64::from(camera.key_id), &key),
                    Expect::Ok,
                );
            }
            // A restart. Seqs up to the saved floor are now rejected, so each
            // camera skips past it.
            92 => {
                stream.send(RESTART, Expect::Ok);
                for camera in &mut cameras {
                    camera.seq += PERSIST_INTERVAL;
                }
            }
            // A full-size tree: the largest frame the receiver accepts.
            93..=95 => {
                let hex = camera.next_frame(full_tree.clone(), &mut rng).hex();
                stream.send(&receive_line(&hex), Expect::Ok);
                camera.last = Some(hex);
            }
            // The largest frame there can be: its tag checks out, then its tree
            // is refused, which doesn't use up its seq.
            96 => {
                let hex = camera
                    .frame(camera.seq + 1, largest.clone(), &mut rng)
                    .hex();
                stream.send(&receive_line(&hex), Expect::Error);
            }
            _ => {
                let payload = small_tree(&mut rng);
                let hex = camera.next_frame(payload, &mut rng).hex();
                stream.send(&receive_line(&hex), Expect::Ok);
                camera.last = Some(hex);
            }
        }
    }
    stream.out.flush().unwrap();
}

/// The receiver under test. If the test fails part-way, the receiver is
/// killed, so one that hangs doesn't outlive the test.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            self.0.kill().ok();
            self.0.wait().ok();
        }
    }
}

/// The resident memory of process `pid` in KiB, from `ps`, which reports it the
/// same way on Linux and macOS.
fn resident_kib(pid: u32) -> u64 {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
#[expect(
    clippy::print_stderr,
    reason = "the throughput and memory figures are the run's report"
)]
fn a_long_mixed_stream_gets_every_response_without_memory_growth() {
    let count: u32 = std::env::var("SOAK_COMMANDS").map_or(DEFAULT_COMMANDS, |value| {
        value.parse().expect("SOAK_COMMANDS must be a whole number")
    });
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_secure-sensor-link"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let stdin = child.0.stdin.take().unwrap();
    let stdout = child.0.stdout.take().unwrap();

    let start = Instant::now();
    let (expect_tx, expect_rx) = mpsc::channel();
    let writer = thread::spawn(move || write_stream(count, stdin, expect_tx));
    let (line_tx, line_rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });

    let warm_up = count / 5;
    let sample_every = (count / 50).max(1);
    let mut responses: u32 = 0;
    let mut errors: u32 = 0;
    let mut baseline = None;
    let mut peak: u64 = 0;
    for expected in expect_rx {
        let line = line_rx
            .recv_timeout(RESPONSE_TIMEOUT)
            .unwrap_or_else(|_| panic!("no response to command {responses} within 10 s"));
        let response: Value = serde_json::from_str(&line).unwrap();
        let message = response["payload"]["message"].as_str().unwrap_or("");
        assert!(
            !message.contains("internal error"),
            "command {responses}: {line}"
        );
        let kind = if response["status"] == "ok" {
            Expect::Ok
        } else {
            Expect::Error
        };
        assert_eq!(kind, expected, "command {responses}: {line}");
        responses += 1;
        errors += u32::from(kind == Expect::Error);

        if responses.is_multiple_of(sample_every) {
            let resident = resident_kib(pid);
            peak = peak.max(resident);
            if baseline.is_none() && responses >= warm_up {
                baseline = Some(resident);
            }
            if let Some(baseline) = baseline {
                assert!(
                    resident <= baseline + GROWTH_LIMIT_KIB,
                    "memory grew from {baseline} KiB after warming up to {resident} KiB \
                     by command {responses}"
                );
            }
        }
    }
    let elapsed = start.elapsed();
    writer.join().unwrap();
    assert!(child.0.wait().unwrap().success());
    assert!(peak <= PEAK_LIMIT_KIB, "memory peaked at {peak} KiB");

    eprintln!(
        "soak: {responses} commands ({errors} rightly refused) in {:.1} s ({:.0} per \
         second); memory {} KiB after warming up, peak {peak} KiB",
        elapsed.as_secs_f64(),
        f64::from(responses) / elapsed.as_secs_f64(),
        baseline.unwrap_or(peak),
    );
}
