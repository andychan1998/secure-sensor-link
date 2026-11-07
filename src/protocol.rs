//! The command protocol: newline-delimited JSON in, one JSON line out per line.
//!
//! Input is read under strict rules:
//!
//! - A line longer than [`MAX_LINE_LEN`] bytes gets one error, and the rest of it
//!   is read and thrown away without being stored, so memory stays bounded.
//! - Every line gets exactly one response, including blank lines.
//! - Unknown fields and duplicate keys are rejected, `parameters` is required,
//!   and numbers must be whole and in range.
//! - Hex strings (frames and keys) are read in place from the input line, never
//!   copied, and error messages never repeat key text.
//!
//! The line buffer is wiped after every command, since it may hold key text.
//! Each command runs under a panic safety net: a bug produces an "internal error"
//! response instead of ending the process.

use std::fmt;
use std::io::{self, BufRead, ErrorKind, Write};
use std::panic::{self, AssertUnwindSafe};

use hmac::digest::zeroize::Zeroize;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::camera::{Camera, PerCamera};
use crate::config::{Config, ConfigError, ConfigInput};
use crate::key::{Key, KeyError};
use crate::receiver::{Accepted, ReceiveError, Receiver, State};
use crate::sync::SyncRecord;
use crate::timeline::Millis;

/// Longest accepted input line, in bytes. The largest valid command (a
/// `receive` with a maximum-size frame) is about 131 KB.
pub const MAX_LINE_LEN: usize = 256 * 1024;

/// Reads commands from `input` until it ends, writing one response line each.
///
/// # Errors
///
/// Returns an error only if reading input or writing output fails.
pub fn run<R: BufRead, W: Write>(mut input: R, mut output: W) -> io::Result<()> {
    let mut session = Session::default();
    let mut line = Vec::new();
    loop {
        let response = match read_line(&mut input, &mut line)? {
            Line::End => return Ok(()),
            Line::TooLong => Response::error(&CommandError::LineTooLong),
            Line::Complete => session.handle_line(&line),
        };
        // The line may hold key text: erase it before reading the next one.
        line.zeroize();
        write_response(&mut output, &response)?;
    }
}

/// The receiver, before and after `init`.
#[derive(Debug, Default)]
pub struct Session {
    receiver: Option<Receiver>,
}

impl Session {
    /// Handles one input line, under the panic safety net.
    pub fn handle_line(&mut self, line: &[u8]) -> Response {
        // A panic in planning leaves the state untouched, so carrying on is
        // safe. A panic during a commit is detected by the receiver itself,
        // which then refuses frames.
        panic::catch_unwind(AssertUnwindSafe(|| match self.execute(line) {
            Ok(payload) => Response::Ok(payload),
            Err(error) => Response::error(&error),
        }))
        .unwrap_or_else(|_| Response::error(&CommandError::Internal))
    }

    fn execute(&mut self, line: &[u8]) -> Result<Payload, CommandError> {
        let envelope: Envelope<'_> = serde_json::from_slice(line).map_err(CommandError::invalid)?;
        let parameters = envelope.parameters;
        match envelope.command {
            "init" => self.init(&parse(parameters)?),
            "receive" => {
                let params: ReceiveParams<'_> = parse(parameters)?;
                let accepted = self.receiver_mut()?.receive(params.frame.0)?;
                Ok(Payload::Received(Received::from(accepted)))
            }
            "get_state" => {
                let NoParams {} = parse(parameters)?;
                Ok(Payload::State(self.receiver()?.state()))
            }
            other => Err(CommandError::UnknownCommand(abbreviate(other))),
        }
    }

    fn init(&mut self, params: &InitParams<'_>) -> Result<Payload, CommandError> {
        if self.receiver.is_some() {
            return Err(CommandError::AlreadyInitialized);
        }
        let config = Config::new(ConfigInput {
            period_ms: params.period_ms,
            max_jitter_ms: params.max_jitter_ms,
            pair_window_ms: params.pair_window_ms,
            max_pending: params.max_pending,
        })?;
        let keys: KeysParam<'_> = parse(params.keys)?;
        let keys = PerCamera::new(
            decode_key(Camera::Cam1, keys.cam1)?,
            decode_key(Camera::Cam2, keys.cam2)?,
        );
        let receiver = Receiver::new(config, keys);
        let state = receiver.state();
        self.receiver = Some(receiver);
        Ok(Payload::State(state))
    }

    fn receiver(&self) -> Result<&Receiver, CommandError> {
        self.receiver.as_ref().ok_or(CommandError::NotInitialized)
    }

    fn receiver_mut(&mut self) -> Result<&mut Receiver, CommandError> {
        self.receiver.as_mut().ok_or(CommandError::NotInitialized)
    }
}

fn decode_key(camera: Camera, text: HexText<'_>) -> Result<Key, CommandError> {
    Key::from_hex(text.0).map_err(|error| CommandError::Key { camera, error })
}

/// Parses a JSON object into `T`. serde would also accept an array for a struct
/// (`[50, 5, ...]`); strict parsing allows only an object.
fn parse<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Result<T, CommandError> {
    let text = raw.get();
    if !text.trim_start().starts_with('{') {
        return Err(CommandError::NotAnObject);
    }
    serde_json::from_str(text).map_err(CommandError::invalid)
}

/// The first 32 characters of attacker-chosen text, for error messages.
fn abbreviate(text: &str) -> String {
    const LIMIT: usize = 32;
    let mut short: String = text.chars().take(LIMIT).collect();
    if short.len() < text.len() {
        short.push_str("...");
    }
    short
}

// ---- Input lines ----

enum Line {
    Complete,
    TooLong,
    End,
}

/// Reads one line into `buf` (without the newline), storing at most
/// [`MAX_LINE_LEN`] bytes. A longer line is consumed to its end and reported as
/// [`Line::TooLong`].
fn read_line<R: BufRead>(input: &mut R, buf: &mut Vec<u8>) -> io::Result<Line> {
    buf.clear();
    let mut read_any = false;
    let mut too_long = false;
    loop {
        let available = match input.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            return Ok(if too_long {
                Line::TooLong
            } else if read_any {
                Line::Complete
            } else {
                Line::End
            });
        }
        read_any = true;
        let newline = available.iter().position(|&byte| byte == b'\n');
        let chunk_len = newline.unwrap_or(available.len());
        let chunk = available.get(..chunk_len).unwrap_or_default();
        if !too_long {
            if buf.len().saturating_add(chunk.len()) > MAX_LINE_LEN {
                too_long = true;
                buf.zeroize();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let consumed = if newline.is_some() {
            chunk_len.saturating_add(1)
        } else {
            chunk_len
        };
        input.consume(consumed);
        if newline.is_some() {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Complete
            });
        }
    }
}

fn write_response<W: Write>(output: &mut W, response: &Response) -> io::Result<()> {
    if serde_json::to_writer(&mut *output, response).is_err() {
        // Can't happen for these types; still, keep one line per command.
        output.write_all(br#"{"status":"error","payload":{"message":"internal error"}}"#)?;
    }
    output.write_all(b"\n")?;
    output.flush()
}

// ---- Commands ----

/// The outer shape of every command. `parameters` is kept as raw JSON so the
/// command can be read first whatever the field order.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    command: &'a str,
    #[serde(borrow)]
    parameters: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitParams<'a> {
    period_ms: u64,
    max_jitter_ms: u64,
    pair_window_ms: u64,
    max_pending: u64,
    /// Kept raw so it can be checked to be an object before it's parsed.
    #[serde(borrow)]
    keys: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysParam<'a> {
    #[serde(borrow)]
    cam1: HexText<'a>,
    #[serde(borrow)]
    cam2: HexText<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveParams<'a> {
    #[serde(borrow)]
    frame: HexText<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

/// A hex string read in place from the input line.
///
/// Strings containing JSON escape sequences are rejected rather than copied,
/// and the error never repeats the string, which may be a key.
#[derive(Clone, Copy)]
struct HexText<'a>(&'a str);

impl<'de: 'a, 'a> Deserialize<'de> for HexText<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HexVisitor;

        impl<'de> Visitor<'de> for HexVisitor {
            type Value = &'de str;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hex string")
            }

            fn visit_borrowed_str<E: de::Error>(self, text: &'de str) -> Result<Self::Value, E> {
                Ok(text)
            }

            fn visit_str<E: de::Error>(self, _text: &str) -> Result<Self::Value, E> {
                Err(E::custom("hex strings may not contain escape sequences"))
            }
        }

        deserializer.deserialize_str(HexVisitor).map(HexText)
    }
}

// ---- Responses ----

/// One response line.
#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "payload", rename_all = "lowercase")]
pub enum Response {
    Ok(Payload),
    Error(ErrorPayload),
}

impl Response {
    fn error(error: &CommandError) -> Self {
        Self::Error(ErrorPayload {
            message: error.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Payload {
    State(State),
    Received(Received),
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    message: String,
}

/// The payload of a successful `receive`.
#[derive(Debug, Serialize)]
pub struct Received {
    frame: FrameView,
    synced: Vec<SyncRecord>,
}

#[derive(Debug, Serialize)]
struct FrameView {
    camera: Camera,
    seq: u32,
    timestamp: Millis,
    corrected: bool,
    tree: Vec<Option<i32>>,
}

impl From<Accepted> for Received {
    fn from(accepted: Accepted) -> Self {
        Self {
            frame: FrameView {
                camera: accepted.camera,
                seq: accepted.seq,
                timestamp: accepted.timestamp,
                corrected: accepted.corrected,
                tree: accepted.tree,
            },
            synced: accepted.synced,
        }
    }
}

// ---- Errors ----

/// Why a command failed. Messages never contain key material.
#[derive(Debug)]
enum CommandError {
    LineTooLong,
    Invalid(String),
    NotAnObject,
    UnknownCommand(String),
    NotInitialized,
    AlreadyInitialized,
    Config(ConfigError),
    Key { camera: Camera, error: KeyError },
    Receive(ReceiveError),
    Internal,
}

impl CommandError {
    #[allow(clippy::needless_pass_by_value)]
    fn invalid(error: serde_json::Error) -> Self {
        Self::Invalid(error.to_string())
    }
}

impl From<ConfigError> for CommandError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<ReceiveError> for CommandError {
    fn from(error: ReceiveError) -> Self {
        Self::Receive(error)
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong => write!(f, "input line exceeds {MAX_LINE_LEN} bytes"),
            Self::Invalid(detail) => write!(f, "invalid command: {detail}"),
            Self::NotAnObject => f.write_str("invalid command: expected a JSON object"),
            Self::UnknownCommand(name) => write!(f, "unknown command {name:?}"),
            Self::NotInitialized => f.write_str("not initialized: the first command must be init"),
            Self::AlreadyInitialized => f.write_str("already initialized"),
            Self::Config(error) => error.fmt(f),
            Self::Key { camera, error } => write!(f, "keys.{camera} {error}"),
            Self::Receive(error) => error.fmt(f),
            Self::Internal => f.write_str("internal error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_lines(input: &[u8]) -> Vec<serde_json::Value> {
        let mut output = Vec::new();
        run(input, &mut output).unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn message(response: &serde_json::Value) -> &str {
        assert_eq!(response["status"], "error", "{response}");
        response["payload"]["message"].as_str().unwrap()
    }

    #[test]
    fn every_line_gets_exactly_one_response() {
        let responses = run_lines(b"\n\n{}\r\nnot json");
        assert_eq!(responses.len(), 4);
        for response in &responses {
            assert!(message(response).starts_with("invalid command"));
        }
    }

    #[test]
    fn no_input_means_no_output() {
        assert!(run_lines(b"").is_empty());
    }

    #[test]
    fn an_overlong_line_gets_one_error_and_the_next_line_still_works() {
        let mut input = vec![b'x'; MAX_LINE_LEN + 1];
        input.extend_from_slice(b"\n{\"command\":\"get_state\",\"parameters\":{}}\n");
        let responses = run_lines(&input);
        assert_eq!(responses.len(), 2);
        assert_eq!(message(&responses[0]), "input line exceeds 262144 bytes");
        assert!(message(&responses[1]).starts_with("not initialized"));
    }

    #[test]
    fn a_line_at_the_limit_is_read_in_full() {
        let mut input = br#"{"command":"get_state","parameters":{}}"#.to_vec();
        input.resize(MAX_LINE_LEN, b' ');
        let responses = run_lines(&input);
        assert!(message(&responses[0]).starts_with("not initialized"));
    }

    #[test]
    fn hex_text_with_escapes_is_rejected_without_echoing_it() {
        // The frame is the JSON escape for "0" twice (backslash written as a byte
        // so no tool or editor turns it into a literal "0").
        let backslash = char::from(0x5c_u8);
        let line = format!(
            r#"{{"command":"receive","parameters":{{"frame":"{backslash}u0030{backslash}u0030"}}}}"#
        );
        assert!(line.contains("u0030"));
        let responses = run_lines(line.as_bytes());
        let text = message(&responses[0]);
        assert!(text.contains("escape sequences"), "{text}");
        assert!(!text.contains("0030"), "{text}");
    }

    /// Input that fails once with `kind`, then yields `data`.
    struct Flaky {
        failure: Option<ErrorKind>,
        data: io::Cursor<Vec<u8>>,
    }

    impl io::Read for Flaky {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            io::Read::read(&mut self.data, buf)
        }
    }

    impl BufRead for Flaky {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            match self.failure.take() {
                Some(kind) => Err(io::Error::from(kind)),
                None => self.data.fill_buf(),
            }
        }

        fn consume(&mut self, amount: usize) {
            self.data.consume(amount);
        }
    }

    fn flaky(kind: ErrorKind) -> Flaky {
        Flaky {
            failure: Some(kind),
            data: io::Cursor::new(b"{}\n".to_vec()),
        }
    }

    #[test]
    fn an_interrupted_read_is_retried() {
        let mut output = Vec::new();
        run(flaky(ErrorKind::Interrupted), &mut output).unwrap();
        assert_eq!(String::from_utf8(output).unwrap().lines().count(), 1);
    }

    #[test]
    fn other_read_errors_end_the_run() {
        let mut output = Vec::new();
        let error = run(flaky(ErrorKind::BrokenPipe), &mut output).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert!(output.is_empty());
    }

    #[test]
    fn a_non_string_frame_names_what_was_expected() {
        let mut session = Session::default();
        let response = serde_json::to_value(
            session.handle_line(br#"{"command":"receive","parameters":{"frame":5}}"#),
        )
        .unwrap();
        let text = response["payload"]["message"].as_str().unwrap();
        assert!(text.contains("expected a hex string"), "{text}");
    }

    #[test]
    fn abbreviates_long_names() {
        assert_eq!(abbreviate("short"), "short");
        let long = "x".repeat(100);
        assert_eq!(abbreviate(&long), format!("{}...", "x".repeat(32)));
    }
}
