//! The safety nets, through the real protocol: a panic in the middle of a
//! command is answered with "internal error" instead of ending the process,
//! and if it interrupted a commit, the receiver refuses every change until a
//! restart rebuilds it from storage.
//!
//! The panic comes from storage that faults partway through a write, the one
//! place a commit can be interrupted from outside.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod support;

use secure_sensor_link::protocol::Session;
use secure_sensor_link::storage::{MemoryStore, Record, Saved, Storage, StorageError};
use serde_json::Value;
use support::{
    Frame, GET_STATE, KEY2, RESTART, add_key_line, init_line, receive_line, revoke_key_line,
};

/// Storage that faults (panics) partway through saving a replay floor above
/// 1000, or keys that include key id 9.
#[derive(Debug, Default)]
struct Faulty(MemoryStore);

impl Storage for Faulty {
    fn write(&mut self, records: &[Record<'_>]) -> Result<(), StorageError> {
        for record in records {
            let faults = match record {
                Record::Floor(_, floor) => *floor > 1000,
                Record::Keys(_, keys) => keys.entries().iter().any(|entry| entry.key_id.0 == 9),
                Record::Config(_) => false,
            };
            assert!(!faults, "storage fault in the middle of a write");
        }
        self.0.write(records)
    }

    fn load(&self) -> Result<Saved, StorageError> {
        self.0.load()
    }
}

fn respond(session: &mut Session<Faulty>, line: &str) -> Value {
    serde_json::to_value(session.handle_line(line.as_bytes())).unwrap()
}

fn message(response: &Value) -> &str {
    assert_eq!(response["status"], "error", "{response}");
    response["payload"]["message"].as_str().unwrap()
}

fn cam1(seq: u32) -> String {
    receive_line(&Frame::new(1, seq, 1000 + i64::from(seq) * 50).hex())
}

const HALTED: &str = "receiver halted: an internal error interrupted an earlier command, so its state can't be trusted until a restart";

/// Checks that every command that changes something is refused, and that
/// state is still reported.
fn assert_halted(session: &mut Session<Faulty>) {
    assert_eq!(message(&respond(session, &cam1(2))), HALTED);
    assert_eq!(
        message(&respond(session, &add_key_line("cam1", 1, KEY2))),
        HALTED
    );
    assert_eq!(
        message(&respond(session, &revoke_key_line("cam2", 0))),
        HALTED
    );
    assert_eq!(respond(session, GET_STATE)["status"], "ok");
}

#[test]
fn a_fault_while_saving_a_frame_halts_the_receiver_until_a_restart() {
    let mut session = Session::default();
    assert_eq!(
        respond(&mut session, &init_line(50, 5, 20, 4))["status"],
        "ok"
    );
    assert_eq!(respond(&mut session, &cam1(1))["status"], "ok"); // floor 101
    // Seq 950 needs floor 1050: the write faults mid-commit.
    assert_eq!(
        message(&respond(&mut session, &cam1(950))),
        "internal error"
    );
    assert_halted(&mut session);

    // A restart rebuilds memory from storage, which still holds floor 101.
    let state = respond(&mut session, RESTART);
    assert_eq!(state["payload"]["cameras"]["cam1"]["last_seq"], Value::Null);
    assert_eq!(
        message(&respond(&mut session, &cam1(101))),
        "stale or replayed frame: cam1 seq 101"
    );
    assert_eq!(respond(&mut session, &cam1(102))["status"], "ok");
}

#[test]
fn a_fault_while_saving_keys_halts_the_receiver_until_a_restart() {
    let mut session = Session::default();
    assert_eq!(
        respond(&mut session, &init_line(50, 5, 20, 4))["status"],
        "ok"
    );
    let add_key_9 = add_key_line("cam1", 9, KEY2);
    assert_eq!(
        message(&respond(&mut session, &add_key_9)),
        "internal error"
    );
    assert_halted(&mut session);

    assert_eq!(respond(&mut session, RESTART)["status"], "ok");
    // Key 9 was never saved, so the receiver carries on without it.
    let state = respond(&mut session, GET_STATE);
    assert_eq!(
        state["payload"]["cameras"]["cam1"]["keys"],
        serde_json::json!([{"key_id": 0, "status": "active"}])
    );
    assert_eq!(respond(&mut session, &cam1(1))["status"], "ok");
}
