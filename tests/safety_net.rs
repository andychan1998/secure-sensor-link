//! The safety nets, through the real protocol: a panic in the middle of a
//! command is answered with "internal error" instead of ending the process,
//! and if it interrupted a commit, the receiver rebuilds its memory from
//! storage before the next command, as a restart would. If storage can't be
//! read, the receiver refuses every change until it can.
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

use std::cell::Cell;

use secure_sensor_link::protocol::Session;
use secure_sensor_link::storage::{MemoryStore, Record, Saved, Storage, StorageError};
use serde_json::{Value, json};
use support::{Frame, GET_STATE, KEY2, add_key_line, init_line, receive_line, revoke_key_line};

/// Whether storage faults on these records: a replay floor above 1000, or
/// keys that include key id 9.
fn faults(records: &[Record<'_>]) -> bool {
    records.iter().any(|record| match record {
        Record::Floor(_, floor) => *floor > 1000,
        Record::Keys(_, keys) => keys.entries().iter().any(|entry| entry.key_id.0 == 9),
        Record::Config(_) => false,
    })
}

/// Storage that faults (panics) partway through a write of such records,
/// before anything is written.
#[derive(Debug, Default)]
struct Faulty(MemoryStore);

impl Storage for Faulty {
    fn write(&mut self, records: &[Record<'_>]) -> Result<(), StorageError> {
        assert!(!faults(records), "storage fault in the middle of a write");
        self.0.write(records)
    }

    fn load(&self) -> Result<Saved, StorageError> {
        self.0.load()
    }
}

/// Like [`Faulty`], but after a fault, the next three attempts to read
/// storage fail.
#[derive(Debug, Default)]
struct FaultyThenUnreadable {
    inner: Faulty,
    failed_reads_left: Cell<u32>,
}

impl Storage for FaultyThenUnreadable {
    fn write(&mut self, records: &[Record<'_>]) -> Result<(), StorageError> {
        if faults(records) {
            self.failed_reads_left.set(3);
        }
        self.inner.write(records)
    }

    fn load(&self) -> Result<Saved, StorageError> {
        let left = self.failed_reads_left.get();
        if left > 0 {
            self.failed_reads_left.set(left - 1);
            return Err(StorageError::NothingSaved);
        }
        self.inner.load()
    }
}

fn respond<S: Storage + Default>(session: &mut Session<S>, line: &str) -> Value {
    serde_json::to_value(session.handle_line(line.as_bytes())).unwrap()
}

fn message(response: &Value) -> &str {
    assert_eq!(response["status"], "error", "{response}");
    response["payload"]["message"].as_str().unwrap()
}

fn cam1(seq: u32) -> String {
    receive_line(&Frame::new(1, seq, 1000 + i64::from(seq) * 50).hex())
}

const HALTED: &str = "receiver halted: an internal error interrupted an earlier command, and its state couldn't be reloaded from storage";

#[test]
fn a_fault_while_saving_a_frame_is_recovered_from_storage() {
    let mut session = Session::<Faulty>::default();
    assert_eq!(
        respond(&mut session, &init_line(50, 5, 20, 4))["status"],
        "ok"
    );
    assert_eq!(respond(&mut session, &cam1(1))["status"], "ok"); // floor 101
    assert_eq!(respond(&mut session, &cam1(2))["status"], "ok");
    // Seq 950 needs floor 1050: the write faults mid-commit.
    assert_eq!(
        message(&respond(&mut session, &cam1(950))),
        "internal error"
    );

    // The next command first rebuilds memory from storage, which still holds
    // floor 101, as after a restart: the timeline and queue start empty.
    let state = respond(&mut session, GET_STATE);
    assert_eq!(state["payload"]["cameras"]["cam1"]["last_seq"], Value::Null);
    assert_eq!(state["payload"]["cameras"]["cam1"]["pending"], json!([]));
    assert_eq!(
        message(&respond(&mut session, &cam1(101))),
        "stale or replayed frame: cam1 seq 101"
    );
    assert_eq!(respond(&mut session, &cam1(102))["status"], "ok");
    assert_eq!(
        respond(&mut session, &add_key_line("cam1", 1, KEY2))["status"],
        "ok"
    );
}

#[test]
fn a_fault_while_saving_keys_is_recovered_from_storage() {
    let mut session = Session::<Faulty>::default();
    assert_eq!(
        respond(&mut session, &init_line(50, 5, 20, 4))["status"],
        "ok"
    );
    let add_key_9 = add_key_line("cam1", 9, KEY2);
    assert_eq!(
        message(&respond(&mut session, &add_key_9)),
        "internal error"
    );

    // Key 9 was never saved, so the receiver carries on without it.
    assert_eq!(respond(&mut session, &cam1(1))["status"], "ok");
    let state = respond(&mut session, GET_STATE);
    assert_eq!(
        state["payload"]["cameras"]["cam1"]["keys"],
        json!([{"key_id": 0, "status": "active"}])
    );
}

#[test]
fn the_receiver_stays_halted_until_storage_can_be_read() {
    let mut session = Session::<FaultyThenUnreadable>::default();
    assert_eq!(
        respond(&mut session, &init_line(50, 5, 20, 4))["status"],
        "ok"
    );
    assert_eq!(respond(&mut session, &cam1(1))["status"], "ok");
    assert_eq!(
        message(&respond(&mut session, &cam1(950))),
        "internal error"
    );

    // Storage can't be read for the next three attempts: every change is
    // refused, and each command tries again.
    assert_eq!(message(&respond(&mut session, &cam1(2))), HALTED);
    assert_eq!(
        message(&respond(&mut session, &add_key_line("cam1", 1, KEY2))),
        HALTED
    );
    assert_eq!(
        message(&respond(&mut session, &revoke_key_line("cam2", 0))),
        HALTED
    );

    // The fourth attempt succeeds: memory is rebuilt from storage.
    let state = respond(&mut session, GET_STATE);
    assert_eq!(state["payload"]["cameras"]["cam1"]["last_seq"], Value::Null);
    assert_eq!(
        message(&respond(&mut session, &cam1(101))),
        "stale or replayed frame: cam1 seq 101"
    );
    assert_eq!(respond(&mut session, &cam1(102))["status"], "ok");
}

#[test]
fn state_is_still_reported_while_halted() {
    let mut session = Session::<FaultyThenUnreadable>::default();
    assert_eq!(
        respond(&mut session, &init_line(50, 5, 20, 4))["status"],
        "ok"
    );
    assert_eq!(respond(&mut session, &cam1(1))["status"], "ok");
    assert_eq!(
        message(&respond(&mut session, &cam1(950))),
        "internal error"
    );
    // Storage can't be read, so get_state reports memory as it is, for
    // diagnosis.
    let state = respond(&mut session, GET_STATE);
    assert_eq!(state["status"], "ok");
    assert_eq!(state["payload"]["cameras"]["cam1"]["last_seq"], 1);
}
