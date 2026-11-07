//! Non-volatile storage: what survives a restart.
//!
//! The receiver writes three kinds of record:
//!
//! - the configuration, once, at `init`;
//! - a camera's keys, on every key event (`add_key`, `revoke_key`, and the
//!   camera moving to a new key). These are rare, so they're written at once;
//! - a camera's replay floor, within the spec's write budget (see
//!   [`crate::floor`]).
//!
//! Each [`Storage::write`] is atomic: every record in it is written, or none is.
//! The receiver always writes before it changes its memory, so storage is never
//! behind anything the receiver has accepted.
//!
//! Storage is trusted (threat model): an attacker can't read, change or roll it
//! back. On real hardware that needs keys in a secure element or encrypted, a
//! monotonic counter against rollback, and two slots with a checksum for
//! atomic writes.

use std::fmt;

use crate::camera::{Camera, PerCamera};
use crate::config::Config;
use crate::keyring::Keyring;

/// One record to write.
#[derive(Clone, Copy, Debug)]
pub enum Record<'a> {
    Config(Config),
    Keys(Camera, &'a Keyring),
    Floor(Camera, u64),
}

/// Everything the receiver needs to start again after a restart.
#[derive(Debug)]
pub struct Saved {
    pub config: Config,
    pub keys: PerCamera<Keyring>,
    pub floors: PerCamera<Option<u64>>,
}

/// Non-volatile storage.
pub trait Storage {
    /// Writes every record, or none of them.
    ///
    /// # Errors
    ///
    /// Returns an error if the write failed; then nothing was written.
    fn write(&mut self, records: &[Record<'_>]) -> Result<(), StorageError>;

    /// Reads back everything written so far.
    ///
    /// # Errors
    ///
    /// Returns an error if storage doesn't hold a configuration and both
    /// cameras' keys, which `init` always writes first.
    fn load(&self) -> Result<Saved, StorageError>;
}

/// A storage operation that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    WriteFailed,
    NothingSaved,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WriteFailed => "storage write failed",
            Self::NothingSaved => "storage holds no saved state",
        })
    }
}

impl std::error::Error for StorageError {}

/// How many records of each kind have been written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Writes {
    pub config: u64,
    pub keys: PerCamera<u64>,
    pub floors: PerCamera<u64>,
}

/// Simulated non-volatile storage: survives a restart because the receiver's
/// memory is rebuilt around it. Counts every write, so tests can check the
/// write budget.
#[derive(Debug, Default)]
pub struct MemoryStore {
    config: Option<Config>,
    keys: PerCamera<Option<Keyring>>,
    floors: PerCamera<Option<u64>>,
    writes: Writes,
}

impl MemoryStore {
    /// The number of records written so far, by kind.
    #[must_use]
    pub const fn writes(&self) -> Writes {
        self.writes
    }
}

impl Storage for MemoryStore {
    fn write(&mut self, records: &[Record<'_>]) -> Result<(), StorageError> {
        // Writing to memory can't fail, so the batch is trivially atomic.
        for record in records {
            match *record {
                Record::Config(config) => {
                    self.config = Some(config);
                    self.writes.config = self.writes.config.saturating_add(1);
                }
                Record::Keys(camera, keys) => {
                    *self.keys.get_mut(camera) = Some(keys.duplicate());
                    let count = self.writes.keys.get_mut(camera);
                    *count = count.saturating_add(1);
                }
                Record::Floor(camera, floor) => {
                    *self.floors.get_mut(camera) = Some(floor);
                    let count = self.writes.floors.get_mut(camera);
                    *count = count.saturating_add(1);
                }
            }
        }
        Ok(())
    }

    fn load(&self) -> Result<Saved, StorageError> {
        let (Some(config), Some(cam1), Some(cam2)) = (
            self.config,
            self.keys.get(Camera::Cam1),
            self.keys.get(Camera::Cam2),
        ) else {
            return Err(StorageError::NothingSaved);
        };
        Ok(Saved {
            config,
            keys: PerCamera::new(cam1.duplicate(), cam2.duplicate()),
            floors: self.floors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigInput;
    use crate::key::{Key, KeyId};
    use crate::keyring::KeyStatus;

    fn config() -> Config {
        Config::new(ConfigInput {
            period_ms: 50,
            max_jitter_ms: 5,
            pair_window_ms: 20,
            max_pending: 4,
            persist_interval: Some(7),
        })
        .unwrap()
    }

    fn keyring(byte: u8) -> Keyring {
        Keyring::new(Key::from_hex(&format!("{byte:02x}").repeat(32)).unwrap())
    }

    #[test]
    fn nothing_loads_before_init_writes() {
        let mut store = MemoryStore::default();
        assert_eq!(store.load().unwrap_err(), StorageError::NothingSaved);
        store.write(&[Record::Config(config())]).unwrap();
        assert_eq!(store.load().unwrap_err(), StorageError::NothingSaved);
        let one = keyring(1);
        store.write(&[Record::Keys(Camera::Cam1, &one)]).unwrap();
        assert_eq!(store.load().unwrap_err(), StorageError::NothingSaved);
        let mut store = MemoryStore::default();
        store
            .write(&[
                Record::Keys(Camera::Cam1, &one),
                Record::Keys(Camera::Cam2, &one),
            ])
            .unwrap();
        assert_eq!(store.load().unwrap_err(), StorageError::NothingSaved);
    }

    #[test]
    fn loads_what_was_written_last_and_counts_each_write() {
        let mut store = MemoryStore::default();
        let (one, two) = (keyring(1), keyring(2));
        store
            .write(&[
                Record::Config(config()),
                Record::Keys(Camera::Cam1, &one),
                Record::Keys(Camera::Cam2, &two),
            ])
            .unwrap();
        let revoked = two.with_revoked(KeyId(0)).unwrap().unwrap();
        store
            .write(&[
                Record::Floor(Camera::Cam2, 107),
                Record::Keys(Camera::Cam2, &revoked),
            ])
            .unwrap();
        store.write(&[Record::Floor(Camera::Cam2, 300)]).unwrap();

        let saved = store.load().unwrap();
        assert_eq!(saved.config, config());
        assert_eq!(saved.floors, PerCamera::new(None, Some(300)));
        assert_eq!(
            saved.keys.get(Camera::Cam2).entries()[0].status,
            KeyStatus::Revoked
        );
        assert!(saved.keys.get(Camera::Cam1).usable(KeyId(0)).is_ok());
        assert_eq!(
            store.writes(),
            Writes {
                config: 1,
                keys: PerCamera::new(1, 2),
                floors: PerCamera::new(0, 2),
            }
        );
        // Loading changes nothing.
        let _ = store.load().unwrap();
        assert_eq!(store.writes().floors, PerCamera::new(0, 2));
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            StorageError::WriteFailed.to_string(),
            "storage write failed"
        );
        assert_eq!(
            StorageError::NothingSaved.to_string(),
            "storage holds no saved state"
        );
    }
}
