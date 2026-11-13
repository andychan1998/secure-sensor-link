//! No copy of a retired or revoked key is left in the receiver's memory, in
//! any form HMAC derives from it either, and no key's hex text is either.
//!
//! Runs the real receiver, retires and revokes keys through the protocol, then
//! reads the receiver's memory through `/proc` (Linux only) and counts copies
//! of each key. The active key must still be found, which shows the scan
//! really reads the receiver's memory; and the scan must find the states of an
//! HMAC in use in another process, which shows it would find a derived form.

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

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sha2::block_api::compress256;
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

/// SHA-256's starting state.
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The SHA-256 state after hashing `block` from the start, as it sits in
/// memory: eight 32-bit words in this machine's byte order.
fn state_after(block: &[u8; 64]) -> [u32; 8] {
    let mut state = SHA256_IV;
    compress256(&mut state, &[*block]);
    state
}

/// A 32-byte key padded to one 64-byte block, combined with `pad` by XOR.
fn padded(key: &[u8], pad: u8) -> [u8; 64] {
    let mut block = [pad; 64];
    for (byte, k) in block.iter_mut().zip(key) {
        *byte ^= k;
    }
    block
}

/// What HMAC-SHA256 derives from a key, each as good as the key itself: the
/// key combined by XOR with the inner (0x36) and outer (0x5c) pads, and the
/// SHA-256 state after hashing each padded block, which the HMAC keeps for the
/// whole time it is in use. Only the key's half of each padded block is
/// searched for; the other half is the pad alone.
fn derived_forms(key: &[u8]) -> [(&'static str, Vec<u8>); 4] {
    let (inner, outer) = (padded(key, 0x36), padded(key, 0x5c));
    let bytes = |state: [u32; 8]| state.iter().flat_map(|word| word.to_ne_bytes()).collect();
    [
        ("key XOR inner pad", inner[..32].to_vec()),
        ("key XOR outer pad", outer[..32].to_vec()),
        ("inner SHA-256 state", bytes(state_after(&inner))),
        ("outer SHA-256 state", bytes(state_after(&outer))),
    ]
}

/// The derived forms above are the real ones: an HMAC finished from the two
/// states gives the same tag as the HMAC library.
#[test]
fn derived_forms_are_what_hmac_uses() {
    /// Continues SHA-256 from `state`, after one 64-byte block, over `message`.
    fn finish(mut state: [u32; 8], message: &[u8]) -> [u8; 32] {
        let mut tail = message.to_vec();
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        let bits = (64 + u64::try_from(message.len()).unwrap()) * 8;
        tail.extend_from_slice(&bits.to_be_bytes());
        let blocks: Vec<[u8; 64]> = tail.chunks(64).map(|c| c.try_into().unwrap()).collect();
        compress256(&mut state, &blocks);
        let mut out = [0; 32];
        for (chunk, word) in out.chunks_mut(4).zip(state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
    let key = hex::decode(CAM1_KEY0).unwrap();
    let message = b"a frame's bytes";
    let inner = finish(state_after(&padded(&key, 0x36)), message);
    let tag = finish(state_after(&padded(&key, 0x5c)), &inner);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(message);
    assert_eq!(tag, mac.finalize().into_bytes()[..]);
}

/// Run in a child process by `the_search_finds_the_states_of_a_live_hmac`:
/// keeps an HMAC in use until its stdin closes. Does nothing otherwise.
#[test]
#[ignore = "run by the_search_finds_the_states_of_a_live_hmac"]
fn hold_an_hmac_while_stdin_is_open() {
    if std::env::var_os("HOLD_HMAC").is_none() {
        return;
    }
    let mac = Hmac::<Sha256>::new_from_slice(&hex::decode(CAM2_KEY0).unwrap()).unwrap();
    let mut stdout = std::io::stdout();
    writeln!(stdout, "ready").unwrap();
    stdout.flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    std::hint::black_box(&mac);
}

/// The search below does find an HMAC's states while one is in use, so
/// finding none of a retired or revoked key's means there are none.
#[test]
fn the_search_finds_the_states_of_a_live_hmac() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "hold_an_hmac_while_stdin_is_open",
            "--ignored",
            "--nocapture",
        ])
        .env("HOLD_HMAC", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while line.trim() != "ready" {
        line.clear();
        assert_ne!(
            stdout.read_line(&mut line).unwrap(),
            0,
            "the child ended early"
        );
    }
    for (form, bytes) in &derived_forms(&hex::decode(CAM2_KEY0).unwrap())[2..] {
        assert!(copies_in_memory(child.id(), bytes) >= 1, "{form} not found");
    }
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
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
        for (form, bytes) in derived_forms(&raw(key)) {
            assert_eq!(halves(bytes), [0, 0], "{name}: {form}");
        }
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

    // Still nowhere else right after a frame is checked with it. A release
    // build leaves a copy of the key on the stack while checking a frame, and
    // only the stack scrub after each command removes it. A debug build leaves
    // none, so only a release run of this test can tell the scrub is missing.
    writeln!(
        stdin,
        "{}",
        receive_line(&Frame::new(1, 3, 1100).v2(2, CAM1_KEY2).hex())
    )
    .unwrap();
    stdin.flush().unwrap();
    let mut response = String::new();
    stdout.read_line(&mut response).unwrap();
    assert!(response.contains(r#""status":"ok""#), "{response}");
    assert_eq!(
        halves(raw(CAM1_KEY2)),
        [2, 2],
        "cam1 key 2 (active), right after checking a frame"
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
}
