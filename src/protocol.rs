//! The command protocol: newline-delimited JSON in, one JSON line out per line.
//!
//! Input is read under strict rules:
//!
//! - A line longer than [`MAX_LINE_LEN`] bytes gets one error, and the rest of it
//!   is read and thrown away without being stored, so memory stays bounded.
//! - Every line gets exactly one response, including blank lines.
//! - Unknown fields and duplicate keys are rejected, `parameters` is required,
//!   and numbers must be whole and in range.
//! - Keys are read in place from the input line and never copied. A key
//!   written with a JSON escape sequence is refused before the JSON library
//!   decodes it, since the decoded copy would sit in a buffer nothing erases.
//!   Every other string may use escapes.
//! - Error messages never repeat a string from the input, which might be a key
//!   in the wrong place, not even an unknown field's name. They may repeat a
//!   number or a boolean (no key is one).
//!
//! The line buffer is wiped after every command, since it may hold key text.
//! Each command runs under a panic safety net: a bug produces an "internal error"
//! response instead of ending the process.

use std::borrow::Cow;
use std::fmt;
use std::io::{self, BufRead, ErrorKind, Write};
use std::panic::{self, AssertUnwindSafe};

use hmac::digest::zeroize::Zeroize;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::camera::{Camera, PerCamera};
use crate::config::{Config, ConfigError, ConfigInput};
use crate::key::{Key, KeyError, KeyId};
use crate::receiver::{Accepted, KeyCommandError, ReceiveError, Receiver, State};
use crate::storage::{MemoryStore, Storage, StorageError};
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
    let mut session: Session = Session::default();
    let mut line = Vec::new();
    let mut reply = Vec::with_capacity(RESPONSE_CAPACITY);
    loop {
        let response = match read_line(&mut input, &mut line)? {
            Line::End => return Ok(()),
            Line::TooLong => Response::error(&CommandError::LineTooLong),
            Line::Complete => session.handle_line(&line),
        };
        // The line may hold key text: erase it, and whatever the command left
        // on the stack, before reading the next one.
        erase(&mut line);
        scrub_stack();
        write_response(&mut output, &mut reply, &response)?;
    }
}

/// The receiver, before and after `init`. `init` creates its storage, by
/// default the simulated non-volatile store; `restart` rebuilds the receiver
/// from that storage alone.
#[derive(Debug)]
pub struct Session<S = MemoryStore> {
    receiver: Option<Receiver<S>>,
}

impl<S> Default for Session<S> {
    fn default() -> Self {
        Self { receiver: None }
    }
}

impl<S: Storage + Default> Session<S> {
    /// Handles one input line, under the panic safety net. A `receive`
    /// response borrows the frame's tree and records from the receiver, so it
    /// must be written before the next line is handled.
    pub fn handle_line(&mut self, line: &[u8]) -> Response<'_> {
        // A panic in planning leaves the state untouched, so carrying on is
        // safe. A panic during a commit is detected by the receiver itself,
        // which rebuilds its memory from storage before the next command.
        panic::catch_unwind(AssertUnwindSafe(move || {
            // Moving the session in makes this closure run only once, which
            // lets the response it returns borrow from the session.
            let session = self;
            match session.execute(line) {
                Ok(payload) => Response::Ok(payload),
                Err(error) => Response::error(&error),
            }
        }))
        .unwrap_or_else(|_| Response::error(&CommandError::Internal))
    }

    fn execute(&mut self, line: &[u8]) -> Result<Payload<'_>, CommandError> {
        // serde would quote a top-level string in its error.
        if line
            .trim_ascii_start()
            .first()
            .is_some_and(|&byte| byte != b'{')
        {
            return Err(CommandError::NotAnObject);
        }
        let envelope: Envelope<'_> = serde_json::from_slice(line).map_err(CommandError::invalid)?;
        let parameters = envelope.parameters;
        match envelope.command.as_ref() {
            "init" => self.init(&parse(parameters)?),
            "receive" => {
                let params: ReceiveParams<'_> = parse(parameters)?;
                let accepted = self.receiver_mut()?.receive(&params.frame)?;
                Ok(Payload::Received(Received::from(accepted)))
            }
            "get_state" => {
                let NoParams {} = parse(parameters)?;
                let receiver = self.receiver_mut()?;
                // Report rebuilt memory after an interrupted commit. If storage
                // can't be read, report memory as it is, for diagnosis.
                receiver.recover();
                Ok(Payload::State(receiver.state()))
            }
            "add_key" => {
                let params: AddKeyParams<'_> = parse(parameters)?;
                let camera = camera(&params.camera)?;
                let key_id = key_id(params.key_id)?;
                let key = Key::from_hex(params.key.0).map_err(CommandError::KeyText)?;
                let receiver = self.receiver_mut()?;
                receiver.add_key(camera, key_id, key)?;
                Ok(Payload::State(receiver.state()))
            }
            "revoke_key" => {
                let params: RevokeKeyParams<'_> = parse(parameters)?;
                let camera = camera(&params.camera)?;
                let key_id = key_id(params.key_id)?;
                let receiver = self.receiver_mut()?;
                receiver.revoke_key(camera, key_id)?;
                Ok(Payload::State(receiver.state()))
            }
            "restart" => {
                let NoParams {} = parse(parameters)?;
                let receiver = self.receiver_mut()?;
                receiver.restart().map_err(CommandError::Restart)?;
                Ok(Payload::State(receiver.state()))
            }
            _ => Err(CommandError::UnknownCommand),
        }
    }

    fn init(&mut self, params: &InitParams<'_>) -> Result<Payload<'static>, CommandError> {
        if self.receiver.is_some() {
            return Err(CommandError::AlreadyInitialized);
        }
        let config = Config::new(ConfigInput {
            period_ms: params.period_ms,
            max_jitter_ms: params.max_jitter_ms,
            pair_window_ms: params.pair_window_ms,
            max_pending: params.max_pending,
            persist_interval: params.persist_interval,
        })?;
        let keys: KeysParam<'_> = parse(params.keys)?;
        let keys = PerCamera::new(
            decode_key(Camera::Cam1, keys.cam1)?,
            decode_key(Camera::Cam2, keys.cam2)?,
        );
        let receiver = Receiver::new(config, keys, S::default()).map_err(CommandError::Init)?;
        let state = receiver.state();
        self.receiver = Some(receiver);
        Ok(Payload::State(state))
    }

    fn receiver_mut(&mut self) -> Result<&mut Receiver<S>, CommandError> {
        self.receiver.as_mut().ok_or(CommandError::NotInitialized)
    }
}

fn camera(name: &str) -> Result<Camera, CommandError> {
    Camera::ALL
        .into_iter()
        .find(|camera| camera.name() == name)
        .ok_or(CommandError::UnknownCamera)
}

fn key_id(value: u64) -> Result<KeyId, CommandError> {
    u8::try_from(value)
        .map(KeyId)
        .map_err(|_| CommandError::KeyIdOutOfRange(value))
}

fn decode_key(camera: Camera, text: KeyText<'_>) -> Result<Key, CommandError> {
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

/// Deserializes a whole number. Asked for a number directly, `serde_json` would
/// quote a string it found instead, and that string might be a key in the
/// wrong field; this says only that it was a string.
fn whole_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    struct WholeNumber;

    impl Visitor<'_> for WholeNumber {
        type Value = u64;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a whole number")
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<u64, E> {
            Ok(value)
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<u64, E> {
            // Only negative numbers arrive here; a whole number, but out of range.
            Err(E::invalid_value(de::Unexpected::Signed(value), &self))
        }

        fn visit_str<E: de::Error>(self, _text: &str) -> Result<u64, E> {
            Err(E::invalid_type(de::Unexpected::Other("a string"), &self))
        }
    }

    deserializer.deserialize_any(WholeNumber)
}

/// Like [`whole_number`], for a field that may be left out but, when present,
/// must hold a number: `null` is an error rather than a silent default.
fn optional_whole_number<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    whole_number(deserializer).map(Some)
}

/// serde's message for an unknown field quotes the field's name, which comes
/// from the input and could be a key typed in the wrong place. Removes the
/// name and keeps what serde adds after it: the fields it expected, and where
/// in the line. Any other message is returned as it is.
fn without_field_name(message: String) -> String {
    let Some(rest) = message.strip_prefix("unknown field `") else {
        return message;
    };
    // The name ends where serde's own text starts. The name may contain that
    // text too, but nothing after the last match comes from the input.
    let end = ["`, expected ", "`, there are no fields"]
        .iter()
        .filter_map(|marker| rest.rfind(marker))
        .max();
    match end
        .and_then(|end| rest.get(end..))
        .and_then(|after| after.strip_prefix('`'))
    {
        Some(after) => format!("unknown field{after}"),
        None => "unknown field".to_owned(),
    }
}

/// How much of the stack [`scrub_stack`] overwrites: more than any command
/// uses, since nothing in a command recurses deeply (the JSON library limits
/// nesting, and the tree decoder doesn't recurse).
const STACK_SCRUB_LEN: usize = 64 * 1024;

/// Overwrites the stack where the command just handled ran, erasing the
/// temporaries it left there: pieces of the input line copied out while the
/// JSON library scanned it, and key-derived blocks the HMAC library set up.
/// This function's own frame takes the place of the command's frames, and
/// `zeroize` writes the zeros with volatile writes the compiler can't remove.
#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    reason = "the array is meant to lie on the stack, over the command's old frames"
)]
fn scrub_stack() {
    let mut area = [0_u8; STACK_SCRUB_LEN];
    area.zeroize();
    std::hint::black_box(&area);
}

// ---- Input lines ----

/// Erases `buf`'s bytes, then empties it. (The `zeroize` crate, as built
/// here, erases a `Vec`'s bytes but keeps its length, so this spells out both
/// steps.)
fn erase(buf: &mut Vec<u8>) {
    buf.as_mut_slice().zeroize();
    buf.clear();
}

enum Line {
    Complete,
    TooLong,
    End,
}

/// Reads one line into `buf` (without the newline), storing at most
/// [`MAX_LINE_LEN`] bytes. A longer line is consumed to its end and reported as
/// [`Line::TooLong`].
///
/// `buf` is given room for the longest line before anything is read into it,
/// so it never grows: growing would move the line to new memory and leave the
/// old copy, which may hold key text, behind unerased.
fn read_line<R: BufRead>(input: &mut R, buf: &mut Vec<u8>) -> io::Result<Line> {
    erase(buf);
    buf.reserve_exact(MAX_LINE_LEN);
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
                erase(buf);
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

/// Room reserved for one response line, so building one never allocates. The
/// largest response is about 83 KB: a frame whose tree has the longest level
/// order, releasing 1,024 waiting frames, all with the longest numbers (the
/// test that builds it checks it fits). Every other response is smaller.
pub const RESPONSE_CAPACITY: usize = 128 * 1024;

/// Writes one response line. The whole line is built first, in `reply`, and
/// written at once, so a failed write never leaves part of a response
/// followed by another.
fn write_response<W: Write>(
    output: &mut W,
    reply: &mut Vec<u8>,
    response: &Response<'_>,
) -> io::Result<()> {
    reply.clear();
    // Serializing these types can't fail; still, keep one line per command.
    if serde_json::to_writer(&mut *reply, response).is_err() {
        reply.clear();
        reply.extend_from_slice(br#"{"status":"error","payload":{"message":"internal error"}}"#);
    }
    reply.push(b'\n');
    output.write_all(reply)?;
    output.flush()
}

// ---- Commands ----

/// The outer shape of every command. `parameters` is kept as raw JSON so the
/// command can be read first whatever the field order.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    /// Borrowed from the line unless it uses escapes.
    #[serde(borrow)]
    command: Cow<'a, str>,
    #[serde(borrow)]
    parameters: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InitParams<'a> {
    #[serde(deserialize_with = "whole_number")]
    period_ms: u64,
    #[serde(deserialize_with = "whole_number")]
    max_jitter_ms: u64,
    #[serde(deserialize_with = "whole_number")]
    pair_window_ms: u64,
    #[serde(deserialize_with = "whole_number")]
    max_pending: u64,
    /// Optional; when present it must be a number (`null` is rejected).
    #[serde(default, deserialize_with = "optional_whole_number")]
    persist_interval: Option<u64>,
    /// Kept raw so it can be checked to be an object before it's parsed.
    #[serde(borrow)]
    keys: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysParam<'a> {
    #[serde(borrow)]
    cam1: KeyText<'a>,
    #[serde(borrow)]
    cam2: KeyText<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveParams<'a> {
    /// Frames aren't secret, so they may use escapes like any string.
    #[serde(borrow)]
    frame: Cow<'a, str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddKeyParams<'a> {
    #[serde(borrow)]
    camera: Cow<'a, str>,
    #[serde(deserialize_with = "whole_number")]
    key_id: u64,
    #[serde(borrow)]
    key: KeyText<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeKeyParams<'a> {
    #[serde(borrow)]
    camera: Cow<'a, str>,
    #[serde(deserialize_with = "whole_number")]
    key_id: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

/// A key's text, read in place from the input line.
///
/// It's taken as raw JSON, so the JSON library never decodes it: a decoded
/// copy would sit in the library's own buffer, which nothing erases. It must
/// be a plain JSON string with no escape sequences; anything else is refused,
/// and the error never repeats it.
#[derive(Clone, Copy)]
struct KeyText<'a>(&'a str);

impl<'de: 'a, 'a> Deserialize<'de> for KeyText<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <&RawValue>::deserialize(deserializer)?;
        raw.get()
            .strip_prefix('"')
            .and_then(|text| text.strip_suffix('"'))
            .filter(|text| !text.contains('\\'))
            .map(KeyText)
            .ok_or_else(|| {
                de::Error::custom("keys must be plain strings of hex, without escape sequences")
            })
    }
}

// ---- Responses ----

/// One response line.
#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "payload", rename_all = "lowercase")]
pub enum Response<'a> {
    Ok(Payload<'a>),
    Error(ErrorPayload),
}

impl Response<'_> {
    fn error(error: &CommandError) -> Self {
        Self::Error(ErrorPayload {
            message: error.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Payload<'a> {
    State(State),
    Received(Received<'a>),
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    message: String,
}

/// The payload of a successful `receive`.
#[derive(Debug, Serialize)]
pub struct Received<'a> {
    frame: FrameView<'a>,
    synced: &'a [SyncRecord],
}

#[derive(Debug, Serialize)]
struct FrameView<'a> {
    camera: Camera,
    key_id: KeyId,
    seq: u32,
    timestamp: Millis,
    corrected: bool,
    tree: &'a [Option<i32>],
}

impl<'a> From<Accepted<'a>> for Received<'a> {
    fn from(accepted: Accepted<'a>) -> Self {
        Self {
            frame: FrameView {
                camera: accepted.camera,
                key_id: accepted.key_id,
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
    UnknownCommand,
    NotInitialized,
    AlreadyInitialized,
    Config(ConfigError),
    Key { camera: Camera, error: KeyError },
    KeyText(KeyError),
    UnknownCamera,
    KeyIdOutOfRange(u64),
    Receive(ReceiveError),
    KeyCommand(KeyCommandError),
    Init(StorageError),
    Restart(StorageError),
    Internal,
}

impl CommandError {
    /// A JSON parse error. Its message never quotes a string from the input:
    /// an unknown field's name is removed ([`without_field_name`]), keys are
    /// refused by [`KeyText`], strings in number fields by [`whole_number`],
    /// and a line or `parameters` that isn't an object is refused before serde
    /// sees it.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "called as `map_err(CommandError::invalid)`, which hands over the error by value"
    )]
    fn invalid(error: serde_json::Error) -> Self {
        Self::Invalid(without_field_name(error.to_string()))
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

impl From<KeyCommandError> for CommandError {
    fn from(error: KeyCommandError) -> Self {
        Self::KeyCommand(error)
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LineTooLong => write!(f, "input line exceeds {MAX_LINE_LEN} bytes"),
            Self::Invalid(detail) => write!(f, "invalid command: {detail}"),
            Self::NotAnObject => f.write_str("invalid command: expected a JSON object"),
            Self::UnknownCommand => f.write_str("unknown command"),
            Self::NotInitialized => f.write_str("not initialized: the first command must be init"),
            Self::AlreadyInitialized => f.write_str("already initialized"),
            Self::Config(error) => error.fmt(f),
            Self::Key { camera, error } => write!(f, "keys.{camera} {error}"),
            Self::KeyText(error) => write!(f, "key {error}"),
            Self::UnknownCamera => f.write_str("camera must be cam1 or cam2"),
            Self::KeyIdOutOfRange(value) => {
                write!(f, "key_id must be from 0 to 255, got {value}")
            }
            Self::Receive(error) => error.fmt(f),
            Self::KeyCommand(error) => error.fmt(f),
            Self::Init(error) => write!(f, "{error}: not initialized"),
            Self::Restart(error) => write!(f, "{error}: restart failed"),
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
    fn an_overlong_line_is_never_held_in_memory() {
        let input = [vec![b'a'; MAX_LINE_LEN * 4], b"\n{}\n".to_vec()].concat();
        // In one chunk, and in chunks the size of stdin's own buffer.
        for chunk in [input.len(), 8 * 1024] {
            let mut reader = io::BufReader::with_capacity(chunk, input.as_slice());
            let mut buf = Vec::new();
            assert!(matches!(
                read_line(&mut reader, &mut buf).unwrap(),
                Line::TooLong
            ));
            assert!(
                buf.is_empty(),
                "kept {} bytes of an overlong line",
                buf.len()
            );
            let capacity = buf.capacity();
            assert!((MAX_LINE_LEN..2 * MAX_LINE_LEN).contains(&capacity));
            // The next line goes into the same memory: the buffer never grows.
            assert!(matches!(
                read_line(&mut reader, &mut buf).unwrap(),
                Line::Complete
            ));
            assert_eq!(buf, b"{}");
            assert_eq!(buf.capacity(), capacity);
        }
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
    fn a_key_with_an_escape_is_refused_without_echoing_it() {
        // A key starting with the JSON escape for "5" (backslash written as a
        // byte so no tool or editor turns it into a literal "5").
        let backslash = char::from(0x5c_u8);
        let key = format!("{backslash}u0035ec2e7{}", "ab".repeat(29));
        let line = format!(
            r#"{{"command":"add_key","parameters":{{"camera":"cam1","key_id":1,"key":"{key}"}}}}"#
        );
        let responses = run_lines(line.as_bytes());
        let text = message(&responses[0]);
        assert!(text.contains("without escape sequences"), "{text}");
        assert!(!text.contains("ec2e7") && !text.contains("abab"), "{text}");
        // So is a key that isn't a string at all.
        let not_a_string =
            br#"{"command":"add_key","parameters":{"camera":"cam1","key_id":1,"key":5}}"#;
        let text = message(&run_lines(not_a_string)[0]).to_owned();
        assert!(text.contains("keys must be plain strings of hex"), "{text}");
    }

    /// A reader that fails once with its error, then reports end of input.
    struct FailOnce(Option<ErrorKind>);

    impl io::Read for FailOnce {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            match self.0.take() {
                Some(kind) => Err(io::Error::from(kind)),
                None => Ok(0),
            }
        }
    }

    /// Input whose first read fails with `kind`, then yields one line.
    fn flaky(kind: ErrorKind) -> impl BufRead {
        io::BufReader::new(io::Read::chain(
            FailOnce(Some(kind)),
            io::Cursor::new(b"{}\n".to_vec()),
        ))
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
        let mut session: Session = Session::default();
        let response = serde_json::to_value(
            session.handle_line(br#"{"command":"receive","parameters":{"frame":5}}"#),
        )
        .unwrap();
        let text = response["payload"]["message"].as_str().unwrap();
        assert!(text.contains("expected a string"), "{text}");
    }

    #[test]
    fn a_number_given_as_a_string_is_not_quoted() {
        let line = br#"{"command":"revoke_key","parameters":{"camera":"cam1","key_id":"300"}}"#;
        let text = message(&run_lines(line)[0]).to_owned();
        assert!(
            text.starts_with("invalid command: invalid type: a string, expected a whole number"),
            "{text}"
        );
    }

    #[test]
    fn removes_an_unknown_field_name_and_keeps_the_rest() {
        let strip = |message: &str| without_field_name(message.to_owned());
        assert_eq!(
            strip(
                "unknown field `q`, expected one of `camera`, `key_id`, `key` at line 1 column 42"
            ),
            "unknown field, expected one of `camera`, `key_id`, `key` at line 1 column 42"
        );
        assert_eq!(
            strip("unknown field `q`, expected `cam1` or `cam2` at line 1 column 17"),
            "unknown field, expected `cam1` or `cam2` at line 1 column 17"
        );
        assert_eq!(
            strip("unknown field `q`, there are no fields at line 1 column 19"),
            "unknown field, there are no fields at line 1 column 19"
        );
        // A name that contains serde's own text: the real text is the last.
        assert_eq!(
            strip("unknown field `a`, expected b`, there are no fields at line 1 column 9"),
            "unknown field, there are no fields at line 1 column 9"
        );
        assert_eq!(
            strip(
                "unknown field `a`, there are no fields`, expected `x` or `y` at line 1 column 9"
            ),
            "unknown field, expected `x` or `y` at line 1 column 9"
        );
        // A shape serde doesn't produce: nothing after the name is kept.
        assert_eq!(strip("unknown field `secret"), "unknown field");
        // Other messages name only the code's own fields, and pass through.
        assert_eq!(
            strip("duplicate field `command` at line 1 column 48"),
            "duplicate field `command` at line 1 column 48"
        );
    }

    #[test]
    fn json_errors_never_name_an_unknown_field() {
        let mut session: Session = Session::default();
        let long = "y".repeat(10_000);
        let unknown_field = format!(r#"{{"command":"get_state","parameters":{{}},"{long}":1}}"#);
        let unknown_parameter = format!(r#"{{"command":"get_state","parameters":{{"{long}":1}}}}"#);
        for line in [unknown_field, unknown_parameter] {
            let response = serde_json::to_value(session.handle_line(line.as_bytes())).unwrap();
            let message = response["payload"]["message"].as_str().unwrap();
            assert!(
                message.starts_with("invalid command: unknown field, "),
                "{message}"
            );
            assert!(!message.contains("yyy"), "{message}");
        }
    }

    #[test]
    fn messages_for_errors_not_shown_elsewhere() {
        assert_eq!(
            CommandError::Init(StorageError::WriteFailed).to_string(),
            "storage write failed: not initialized"
        );
        assert_eq!(
            CommandError::Restart(StorageError::NothingSaved).to_string(),
            "storage holds no saved state: restart failed"
        );
        assert_eq!(CommandError::Internal.to_string(), "internal error");
    }

    #[test]
    fn a_failed_write_ends_the_run_without_writing_anything_more() {
        /// Accepts `room` bytes, fails once, then accepts everything.
        struct Glitchy {
            written: Vec<u8>,
            room: usize,
        }
        impl Write for Glitchy {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.room == 0 {
                    self.room = usize::MAX;
                    return Err(io::Error::from(ErrorKind::StorageFull));
                }
                let n = buf.len().min(self.room);
                self.written.extend_from_slice(&buf[..n]);
                self.room -= n;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut one_response = Vec::new();
        run(&b"{}\n"[..], &mut one_response).unwrap();
        // Room for the first response and the start of the second.
        let mut output = Glitchy {
            written: Vec::new(),
            room: one_response.len() + 10,
        };
        let error = run(&b"{}\n{}\n{}\n"[..], &mut output).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::StorageFull);
        // The first response whole, then the start of the second and nothing
        // after it: no fallback message glued onto the partial line, and no
        // third response.
        let mut expected = one_response;
        expected.extend_from_slice(br#"{"status":"#);
        assert_eq!(output.written, expected);
    }
}
