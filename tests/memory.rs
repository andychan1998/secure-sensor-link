//! No copy of a retired or revoked key is left in the receiver's memory, and no
//! key's hex text is either.
//!
//! Runs the real receiver, retires and revokes keys through the protocol, then
//! reads the receiver's memory through `/proc` (Linux only) and counts copies
//! of each key. The active key must still be found, which shows the scan
//! really reads the receiver's memory.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice
)]

mod support;

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::process::{Command, Stdio};

use support::{Frame, add_key_line, receive_line, revoke_key_line};

/// Distinctive keys, never all one byte value.
const CAM1_KEY0: &str = "a53c910e77d24b18c65fe02983bd166a4ff1029e5837cb7d10aa64e93b85d421";
const CAM2_KEY0: &str = "5bc31f806e2db49749f00bd67238ae15e48c53019a6fc72e41bb0d967c33e85a";
const CAM1_KEY1: &str = "139f66d82ac1740bb548ee31875c0fa36df924b09547da187e02cf613ae58b54";
const CAM1_KEY2: &str = "e1d2c3b4a5968778695a4b3c2d1e0f00f1e2d3c4b5a69788796a5b4c3d2e1f10";
/// Sent in two pieces, split in the middle of the key.
const SPLIT_KEY: &str = "4b8e1f6a92c3d70e5f14a8b6c29d3e7f0a5c81e4b6d92f37c0e8a15d4b7f2c96";
/// Sent with a JSON escape, so it is refused.
const REFUSED_KEY: &str = "7c4e2a91d35b08f6e1a9c47d2b5e80f3a6d19c4e72b58f0a3d6e91c2b47a5f08";

fn init_line() -> String {
    format!(
        r#"{{"command":"init","parameters":{{"period_ms":50,"max_jitter_ms":5,"pair_window_ms":20,"max_pending":4,"keys":{{"cam1":"{CAM1_KEY0}","cam2":"{CAM2_KEY0}"}}}}}}"#
    )
}

/// How many times `needle` appears in the readable memory of process `pid`.
fn copies_in_memory(pid: u32, needle: &[u8]) -> usize {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let mut mem = File::open(format!("/proc/{pid}/mem")).unwrap();
    let mut count = 0;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (range, perms) = (fields.next().unwrap(), fields.next().unwrap());
        let name = fields.nth(3).unwrap_or("");
        if !perms.starts_with('r') || name == "[vvar]" || name == "[vsyscall]" {
            continue;
        }
        let (start, end) = range.split_once('-').unwrap();
        let start = u64::from_str_radix(start, 16).unwrap();
        let end = u64::from_str_radix(end, 16).unwrap();
        let mut data = vec![0; usize::try_from(end - start).unwrap()];
        if mem.seek(SeekFrom::Start(start)).is_err() || mem.read_exact(&mut data).is_err() {
            continue;
        }
        count += data
            .windows(needle.len())
            .filter(|window| window == &needle)
            .count();
    }
    count
}

#[test]
fn retired_and_revoked_keys_leave_no_copies_in_memory() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_secure-sensor-link"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let lines = [
        init_line(),
        receive_line(&Frame::new(1, 1, 1000).key(CAM1_KEY0).hex()),
        receive_line(&Frame::new(2, 1, 1003).key(CAM2_KEY0).hex()),
        add_key_line("cam1", 1, CAM1_KEY1),
        add_key_line("cam1", 2, CAM1_KEY2),
        // cam1 moves to key 2: keys 0 and 1 are retired.
        receive_line(&Frame::new(1, 2, 1050).v2(2, CAM1_KEY2).hex()),
        revoke_key_line("cam2", 0),
        r#"{"command":"get_state","parameters":{}}"#.to_owned(),
    ];
    for line in &lines {
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        let mut response = String::new();
        stdout.read_line(&mut response).unwrap();
        assert!(response.contains(r#""status":"ok""#), "{line}\n{response}");
    }
    // A line that arrives in two reads: the second part must not make the
    // line buffer move, which would leave the first part behind. Padded with
    // JSON whitespace so it is longer than any line before it.
    let split = add_key_line("cam2", 1, SPLIT_KEY).replacen(
        &format!("\"{SPLIT_KEY}\""),
        &format!("\"{SPLIT_KEY}\"{}", " ".repeat(4000)),
        1,
    );
    let middle = split.find(SPLIT_KEY).unwrap() + 32;
    stdin.write_all(&split.as_bytes()[..middle]).unwrap();
    stdin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(100));
    writeln!(stdin, "{}", &split[middle..]).unwrap();
    stdin.flush().unwrap();
    let mut response = String::new();
    stdout.read_line(&mut response).unwrap();
    assert!(response.contains(r#""status":"ok""#), "{response}");

    // A key written with an escape is refused before the JSON library decodes
    // it, so no decoded copy is made anywhere.
    let escaped = format!("{}u0037{}", char::from(0x5c_u8), &REFUSED_KEY[1..]);
    writeln!(stdin, "{}", add_key_line("cam1", 3, &escaped)).unwrap();
    stdin.flush().unwrap();
    let mut response = String::new();
    stdout.read_line(&mut response).unwrap();
    assert!(response.contains("escape sequences"), "{response}");

    // The receiver now waits for more input, with everything above done.
    let pid = child.id();
    let raw = |hex: &str| hex::decode(hex).unwrap();

    // Each half is searched for on its own: when the allocator reuses a freed
    // block, it writes its own bookkeeping over the start of it, which would
    // hide a whole-key match while the rest of the key is still there.
    let halves = |bytes: Vec<u8>| -> [usize; 2] {
        let (first, second) = bytes.split_at(bytes.len() / 2);
        [copies_in_memory(pid, first), copies_in_memory(pid, second)]
    };
    for (name, key) in [
        ("cam1 key 0 (retired)", CAM1_KEY0),
        ("cam1 key 1 (retired)", CAM1_KEY1),
        ("cam2 key 0 (revoked)", CAM2_KEY0),
        ("refused key", REFUSED_KEY),
    ] {
        assert_eq!(halves(raw(key)), [0, 0], "{name}: bytes");
    }
    for key in [
        CAM1_KEY0,
        CAM1_KEY1,
        CAM2_KEY0,
        CAM1_KEY2,
        SPLIT_KEY,
        REFUSED_KEY,
    ] {
        assert_eq!(halves(key.as_bytes().to_vec()), [0, 0], "hex text of {key}");
    }
    // The active key is in the keyring and in the simulated storage, and
    // nowhere else.
    assert_eq!(halves(raw(CAM1_KEY2)), [2, 2], "cam1 key 2 (active)");

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
