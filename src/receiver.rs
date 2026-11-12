//! The receiver: checks each frame, then commits its effects.
//!
//! Every frame goes through `Receiver::plan`, which runs all checks in the
//! documented order and computes every result without changing the receiver's
//! state (it writes only to its scratch room, `Scratch`), and then
//! `Receiver::commit`, which first writes to storage whatever must survive a
//! restart, then applies the plan to memory with steps that can't fail. A
//! rejected frame, or a failed storage write, changes nothing, with one
//! exception after a restart (`Decision::BelowRestartFloor`). Key management
//! (`add_key`, `revoke_key`) follows the same pattern.
//!
//! The receiver owns its storage. A restart ([`Receiver::restart`]) throws away
//! everything in memory and rebuilds it from storage alone.
//!
//! If a panic ever escapes a commit (a bug), the receiver can't vouch for its
//! memory, so it changes nothing more until a restart rebuilds it from
//! storage: see [`Receiver::is_halted`]. Storage is always written first, so it
//! is never behind what memory may hold.

use std::fmt;

use serde::Serialize;

use crate::camera::{Camera, PerCamera};
use crate::config::Config;
use crate::floor::ReplayFloor;
use crate::frame::{self, FrameError, MAX_FRAME_LEN, RawFrame, VerifiedFrame};
use crate::key::{Key, KeyId};
use crate::keyring::{AddKeyError, KeyEntry, Keyring, Unusable};
use crate::storage::{Record, Saved, Storage, StorageError};
use crate::sync::{self, Pending, Queues, SyncPlan, SyncRecord};
use crate::timeline::{self, Anchor, Millis};
use crate::tree::{Tree, TreeError};

/// The receiver after a successful `init`.
#[derive(Debug)]
pub struct Receiver<S> {
    /// Survives a restart.
    store: S,
    /// Lost on a restart, and rebuilt from `store`.
    memory: Memory,
    /// Room for one frame's work. Holds nothing between frames.
    scratch: Scratch,
}

/// Room for one frame's work, reserved at `init` at the largest size each part
/// can need: the frame's bytes, its tree and level order, and the records it
/// produces. Handling a frame then makes no large allocation, the kind most
/// likely to fail on a fragmented heap.
///
/// Holds nothing that matters between frames: each use starts by clearing
/// what it uses. None of it is secret (frames are signed, not encrypted), so
/// it needs no erasing.
struct Scratch {
    bytes: Vec<u8>,
    tree: Tree,
    synced: Vec<SyncRecord>,
}

/// Leaves out the contents: up to 64 KiB of the last frame is just noise.
impl fmt::Debug for Scratch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scratch").finish_non_exhaustive()
    }
}

impl Scratch {
    fn new(config: &Config) -> Self {
        Self {
            bytes: Vec::with_capacity(MAX_FRAME_LEN),
            tree: Tree::with_full_capacity(),
            synced: Vec::with_capacity(sync::most_records(config.max_pending())),
        }
    }
}

/// Everything the receiver holds in memory. A restart replaces it whole, so
/// nothing in it can survive one by accident.
#[derive(Debug)]
struct Memory {
    config: Config,
    keys: PerCamera<Keyring>,
    floors: PerCamera<ReplayFloor>,
    /// The last accepted frame from each camera.
    last: PerCamera<Option<Anchor>>,
    queues: Queues,
    /// Set for the duration of a commit. If it's still set when a command starts,
    /// a panic interrupted a commit and memory may be half-changed.
    commit_in_progress: bool,
}

impl Memory {
    /// Memory with no frames accepted: after `init`, or after a restart.
    fn new(config: Config, keys: PerCamera<Keyring>, floors: PerCamera<ReplayFloor>) -> Self {
        Self {
            queues: Queues::new(config.max_pending()),
            config,
            keys,
            floors,
            last: PerCamera::default(),
            commit_in_progress: false,
        }
    }
}

/// What an accepted frame produced. The tree and records are borrowed from
/// the receiver's scratch room, so they last until its next command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted<'a> {
    pub camera: Camera,
    pub key_id: KeyId,
    pub seq: u32,
    pub timestamp: Millis,
    pub corrected: bool,
    pub tree: &'a [Option<i32>],
    pub synced: &'a [SyncRecord],
}

/// Everything an accepted frame will change, computed before changing it. The
/// frame's tree and records wait in the scratch room.
#[derive(Debug)]
struct Plan {
    camera: Camera,
    key_id: KeyId,
    anchor: Anchor,
    corrected: bool,
    /// The floor to save first, if the saved one doesn't cover this seq.
    floor: Option<u64>,
    /// The camera's keys afterwards, if the frame moves it to a new key.
    keys: Option<Keyring>,
    sync: SyncPlan,
}

/// What the checks decided for a frame.
#[derive(Debug)]
enum Decision {
    Accept(Plan),
    /// Rejected only because its seq is at or below the floor loaded at the
    /// last restart: it may be a replay from before the restart. Without the
    /// restart it would have been accepted, so it still moves the camera to its
    /// key (`keys`), as an accepted frame would. Otherwise a key rotation seen
    /// only below the floor would be lost, and an attacker holding the old key
    /// could get frames accepted that the receiver would have rejected without
    /// the restart.
    BelowRestartFloor {
        camera: Camera,
        seq: u32,
        keys: Option<Keyring>,
    },
}

impl<S: Storage> Receiver<S> {
    /// A receiver with no frames accepted yet. Each camera's `init` key is its
    /// key 0. The configuration and keys are written to `store` first.
    ///
    /// # Errors
    ///
    /// Returns an error if they couldn't be written.
    pub fn new(config: Config, keys: PerCamera<Key>, mut store: S) -> Result<Self, StorageError> {
        let (cam1, cam2) = keys.into_parts();
        let keys = PerCamera::new(Keyring::new(cam1), Keyring::new(cam2));
        store.write(&[
            Record::Config(config),
            Record::Keys(Camera::Cam1, keys.get(Camera::Cam1)),
            Record::Keys(Camera::Cam2, keys.get(Camera::Cam2)),
        ])?;
        Ok(Self {
            store,
            memory: Memory::new(config, keys, PerCamera::default()),
            scratch: Scratch::new(&config),
        })
    }

    /// Simulates a power loss and reboot: everything in memory is lost, and
    /// the receiver starts again from what storage holds. Timelines and queues
    /// start empty; queued frames are dropped without being emitted. Also
    /// clears a halt, since memory is rebuilt from storage.
    ///
    /// # Errors
    ///
    /// Returns an error if storage can't be read; then nothing changes.
    pub fn restart(&mut self) -> Result<(), StorageError> {
        let Saved {
            config,
            keys,
            floors,
        } = self.store.load()?;
        let floors = floors.map(|_, &saved| ReplayFloor::restored(saved));
        self.memory = Memory::new(config, keys, floors);
        Ok(())
    }

    /// The receiver's storage, for inspection.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Processes one hex-encoded frame.
    ///
    /// # Errors
    ///
    /// Returns why the frame was rejected. A rejected frame changes nothing,
    /// with one exception: after a restart, a frame rejected only because of
    /// the restart floor, but otherwise valid, still moves its camera to its
    /// key (see `Decision::BelowRestartFloor`).
    pub fn receive(&mut self, frame_hex: &str) -> Result<Accepted<'_>, ReceiveError> {
        if self.is_halted() {
            return Err(ReceiveError::Halted);
        }
        match Self::plan(&self.memory, &mut self.scratch, frame_hex)? {
            Decision::Accept(plan) => self.commit(plan),
            Decision::BelowRestartFloor { camera, seq, keys } => {
                if let Some(keys) = keys {
                    self.commit_keys(camera, keys)
                        .map_err(ReceiveError::Storage)?;
                }
                Err(ReceiveError::Stale { camera, seq })
            }
        }
    }

    /// Whether an earlier commit was interrupted, so the receiver refuses to
    /// change anything until it is restarted.
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        self.memory.commit_in_progress
    }

    /// Runs every check, in order, and computes the frame's effects. Reads
    /// memory only; works in `scratch`.
    fn plan(
        memory: &Memory,
        scratch: &mut Scratch,
        frame_hex: &str,
    ) -> Result<Decision, ReceiveError> {
        // 1-3: hex, version, layout. Only the camera and key id are readable.
        frame::decode_hex_into(frame_hex, &mut scratch.bytes)?;
        let raw = RawFrame::parse(&scratch.bytes)?;
        let camera = raw.camera();
        let key_id = raw.key_id();

        // 4: key status. A revoked or retired key isn't even tried.
        let keys = memory.keys.get(camera);
        let key = keys.usable(key_id).map_err(|reason| ReceiveError::Key {
            camera,
            key_id,
            reason,
        })?;

        // 5: the tag.
        let frame = raw.verify(key)?;
        let seq = frame.seq();

        // 6: replay: at or below the last accepted seq or, after a restart, at
        // or below the floor loaded from storage. Only ever judges a seq the
        // camera really sent.
        let last = *memory.last.get(camera);
        if last.is_some_and(|anchor| seq <= anchor.seq) {
            return Err(ReceiveError::Stale { camera, seq });
        }
        let floor = memory.floors.get(camera);
        // 7-8: timestamp, then the tree, the most complex parsing, last.
        let contents = check_contents(&frame, &mut scratch.tree);
        if !floor.admits(seq) {
            // Reported as stale whatever 7-8 found, as the order of checks says.
            return Ok(Decision::BelowRestartFloor {
                camera,
                seq,
                keys: contents.ok().and_then(|_| keys.after_use(key_id)),
            });
        }
        let raw_timestamp = contents?;

        // Effects: timestamp correction and pairing.
        let corrected = timeline::correct(last, seq, raw_timestamp, &memory.config)
            .ok_or(ReceiveError::Internal)?;
        let pending = Pending {
            seq,
            timestamp: corrected.timestamp,
            key_id,
        };
        let sync = memory
            .queues
            .plan(camera, pending, &memory.config, &mut scratch.synced)
            .ok_or(ReceiveError::Internal)?;

        Ok(Decision::Accept(Plan {
            camera,
            key_id,
            anchor: Anchor {
                seq,
                timestamp: corrected.timestamp,
            },
            corrected: corrected.corrected,
            floor: floor.to_save(seq, memory.config.persist_interval()),
            keys: keys.after_use(key_id),
            sync,
        }))
    }

    /// Writes what must survive a restart, then applies the plan to memory.
    /// Only the storage write can fail, and then nothing has changed.
    fn commit(&mut self, plan: Plan) -> Result<Accepted<'_>, ReceiveError> {
        let camera = plan.camera;
        self.begin_commit(&[
            plan.floor.map(|floor| Record::Floor(camera, floor)),
            plan.keys.as_ref().map(|keys| Record::Keys(camera, keys)),
        ])
        .map_err(ReceiveError::Storage)?;
        let memory = &mut self.memory;
        *memory.last.get_mut(camera) = Some(plan.anchor);
        if let Some(floor) = plan.floor {
            memory.floors.get_mut(camera).saved_as(floor);
        }
        if let Some(keys) = plan.keys {
            // Dropping the old keyring erases the keys it retired.
            *memory.keys.get_mut(camera) = keys;
        }
        memory.queues.apply(&plan.sync);
        memory.commit_in_progress = false;
        let scratch = &mut self.scratch;
        Ok(Accepted {
            camera,
            key_id: plan.key_id,
            seq: plan.anchor.seq,
            timestamp: plan.anchor.timestamp,
            corrected: plan.corrected,
            tree: scratch.tree.level_order(),
            synced: &scratch.synced,
        })
    }

    /// Marks a commit as in progress, then writes the given records (skipping
    /// `None`s) to storage. If the write fails, nothing was written, so the
    /// commit is abandoned and the receiver carries on unchanged. A panic from
    /// here until the commit ends leaves the receiver halted.
    fn begin_commit(&mut self, records: &[Option<Record<'_>>]) -> Result<(), StorageError> {
        self.memory.commit_in_progress = true;
        let records: Vec<Record<'_>> = records.iter().flatten().copied().collect();
        if !records.is_empty()
            && let Err(error) = self.store.write(&records)
        {
            self.memory.commit_in_progress = false;
            return Err(error);
        }
        Ok(())
    }

    /// Saves `camera`'s new keys, then puts them in place of the old ones
    /// (dropping the old keyring erases any key it retired or revoked).
    fn commit_keys(&mut self, camera: Camera, keys: Keyring) -> Result<(), StorageError> {
        self.begin_commit(&[Some(Record::Keys(camera, &keys))])?;
        *self.memory.keys.get_mut(camera) = keys;
        self.memory.commit_in_progress = false;
        Ok(())
    }

    /// Provisions `key` as `camera`'s key `key_id`.
    ///
    /// # Errors
    ///
    /// Refuses a revoked id, an id the camera has moved past, and a different key
    /// under an id already provisioned. Re-adding the identical key succeeds and
    /// changes nothing (and writes nothing).
    pub fn add_key(
        &mut self,
        camera: Camera,
        key_id: KeyId,
        key: Key,
    ) -> Result<(), KeyCommandError> {
        if self.is_halted() {
            return Err(KeyCommandError::Halted);
        }
        let next = self
            .memory
            .keys
            .get(camera)
            .with_added(key_id, key)
            .map_err(|reason| KeyCommandError::Add {
                camera,
                key_id,
                reason,
            })?;
        match next {
            Some(next) => self
                .commit_keys(camera, next)
                .map_err(KeyCommandError::Storage),
            None => Ok(()),
        }
    }

    /// Revokes `camera`'s key `key_id`: frames using it are rejected from now on,
    /// and frames it authenticated that are still waiting to be paired are
    /// dropped without being emitted. Revoking a revoked key changes nothing.
    ///
    /// # Errors
    ///
    /// Refuses a key id that was never provisioned.
    pub fn revoke_key(&mut self, camera: Camera, key_id: KeyId) -> Result<(), KeyCommandError> {
        if self.is_halted() {
            return Err(KeyCommandError::Halted);
        }
        let next = self
            .memory
            .keys
            .get(camera)
            .with_revoked(key_id)
            .map_err(|reason| KeyCommandError::Unusable {
                camera,
                key_id,
                reason,
            })?;
        let Some(next) = next else {
            return Ok(());
        };
        self.begin_commit(&[Some(Record::Keys(camera, &next))])
            .map_err(KeyCommandError::Storage)?;
        // Dropping the old keyring erases the revoked key.
        *self.memory.keys.get_mut(camera) = next;
        self.memory.queues.drop_key(camera, key_id);
        self.memory.commit_in_progress = false;
        Ok(())
    }

    /// The state reported by `get_state` and other commands.
    #[must_use]
    pub fn state(&self) -> State {
        let memory = &self.memory;
        State {
            cameras: memory.last.map(|camera, last| CameraState {
                last_seq: last.map(|anchor| anchor.seq),
                last_timestamp: last.map(|anchor| anchor.timestamp),
                pending: memory.queues.pending_seqs(camera).collect(),
                keys: memory.keys.get(camera).entries(),
            }),
        }
    }
}

/// Checks 7 and 8: the timestamp isn't negative, and the payload is a tree
/// within the limits. Returns the timestamp; the tree is decoded into `tree`.
fn check_contents(frame: &VerifiedFrame<'_>, tree: &mut Tree) -> Result<i64, ReceiveError> {
    let raw_timestamp = frame.timestamp();
    if raw_timestamp < 0 {
        return Err(ReceiveError::NegativeTimestamp(raw_timestamp));
    }
    tree.decode_from(frame.payload())?;
    Ok(raw_timestamp)
}

/// The receiver state as reported in responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct State {
    pub cameras: PerCamera<CameraState>,
}

/// One camera's part of the state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CameraState {
    pub last_seq: Option<u32>,
    pub last_timestamp: Option<Millis>,
    pub pending: Vec<u32>,
    pub keys: Vec<KeyEntry>,
}

/// Why a frame was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveError {
    Frame(FrameError),
    Key {
        camera: Camera,
        key_id: KeyId,
        reason: Unusable,
    },
    Stale {
        camera: Camera,
        seq: u32,
    },
    NegativeTimestamp(i64),
    Tree(TreeError),
    /// The frame couldn't be saved to storage, so it wasn't accepted.
    Storage(StorageError),
    /// An earlier commit was interrupted; frames are refused until a restart.
    Halted,
    /// A calculation that the checks make impossible failed.
    Internal,
}

impl From<FrameError> for ReceiveError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<TreeError> for ReceiveError {
    fn from(error: TreeError) -> Self {
        Self::Tree(error)
    }
}

impl fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => error.fmt(f),
            Self::Key {
                camera,
                key_id,
                reason,
            } => write!(f, "{camera} key {key_id} {reason}"),
            Self::Stale { camera, seq } => write!(f, "stale or replayed frame: {camera} seq {seq}"),
            Self::NegativeTimestamp(timestamp) => {
                write!(f, "malformed frame: negative timestamp {timestamp}")
            }
            Self::Tree(error) => write!(f, "malformed frame: {error}"),
            Self::Storage(error) => write!(f, "{error}: frame not accepted"),
            Self::Halted => f.write_str(
                "receiver halted: an internal error interrupted an earlier command, so its state can't be trusted until a restart",
            ),
            Self::Internal => f.write_str("internal error"),
        }
    }
}

impl std::error::Error for ReceiveError {}

/// Why `add_key` or `revoke_key` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCommandError {
    Add {
        camera: Camera,
        key_id: KeyId,
        reason: AddKeyError,
    },
    Unusable {
        camera: Camera,
        key_id: KeyId,
        reason: Unusable,
    },
    /// The change couldn't be saved to storage, so it wasn't made.
    Storage(StorageError),
    Halted,
}

impl fmt::Display for KeyCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add {
                camera,
                key_id,
                reason,
            } => match reason {
                AddKeyError::Revoked => write!(f, "{camera} key {key_id} is revoked"),
                AddKeyError::Retired => write!(f, "{camera} key {key_id} is retired"),
                AddKeyError::BelowCurrent { current } => write!(
                    f,
                    "{camera} key {key_id} would be retired at once: {camera} already uses key {current}"
                ),
                AddKeyError::DifferentKey => write!(
                    f,
                    "{camera} key {key_id} is already provisioned with a different key"
                ),
            },
            Self::Unusable {
                camera,
                key_id,
                reason,
            } => write!(f, "{camera} key {key_id} {reason}"),
            Self::Storage(error) => write!(f, "{error}: keys not changed"),
            Self::Halted => ReceiveError::Halted.fmt(f),
        }
    }
}

impl std::error::Error for KeyCommandError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigInput;
    use crate::keyring::KeyStatus;
    use crate::storage::MemoryStore;

    const KEY1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const KEY2: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const SPEC_FRAME: &str = "01010000000100000000000003e8001f010000000101000000020000010000000301000000040000010000000500\
                              00fe04b3dcfd1aa96276d46024a02a89e9125a556fa6a3e1b14628fb7cd4375d82";

    /// Storage whose writes can be made to fail.
    #[derive(Debug, Default)]
    struct FlakyStore {
        inner: MemoryStore,
        fail: bool,
    }

    impl Storage for FlakyStore {
        fn write(&mut self, records: &[Record<'_>]) -> Result<(), StorageError> {
            if self.fail {
                return Err(StorageError::WriteFailed);
            }
            self.inner.write(records)
        }

        fn load(&self) -> Result<Saved, StorageError> {
            self.inner.load()
        }
    }

    fn config() -> Config {
        Config::new(ConfigInput {
            period_ms: 50,
            max_jitter_ms: 5,
            pair_window_ms: 20,
            max_pending: 4,
            persist_interval: None,
        })
        .unwrap()
    }

    fn keys() -> PerCamera<Key> {
        PerCamera::new(Key::from_hex(KEY1).unwrap(), Key::from_hex(KEY2).unwrap())
    }

    fn receiver() -> Receiver<FlakyStore> {
        Receiver::new(config(), keys(), FlakyStore::default()).unwrap()
    }

    fn statuses(r: &Receiver<FlakyStore>) -> Vec<KeyStatus> {
        r.state()
            .cameras
            .get(Camera::Cam1)
            .keys
            .iter()
            .map(|entry| entry.status)
            .collect()
    }

    #[test]
    fn accepts_the_spec_frame_and_saves_its_floor() {
        let mut r = receiver();
        let accepted = r.receive(SPEC_FRAME).unwrap();
        assert_eq!(accepted.seq, 1);
        assert_eq!(accepted.timestamp, 1000);
        assert!(!r.is_halted());
        assert_eq!(r.memory.floors.get(Camera::Cam1).saved(), Some(101));
        let writes = r.store().inner.writes();
        assert_eq!(writes.floors.get(Camera::Cam1), &1);
        // Key 0 is where cam1 started, so its keys weren't written again.
        assert_eq!(writes.keys.get(Camera::Cam1), &1);
    }

    #[test]
    fn init_fails_if_storage_cant_be_written() {
        let store = FlakyStore {
            fail: true,
            ..FlakyStore::default()
        };
        assert_eq!(
            Receiver::new(config(), keys(), store).unwrap_err(),
            StorageError::WriteFailed
        );
    }

    #[test]
    fn a_failed_storage_write_changes_nothing() {
        let mut r = receiver();
        let before = r.state();
        r.store.fail = true;
        assert_eq!(
            r.receive(SPEC_FRAME),
            Err(ReceiveError::Storage(StorageError::WriteFailed))
        );
        let key = Key::from_hex(&"11".repeat(32)).unwrap();
        assert_eq!(
            r.add_key(Camera::Cam1, KeyId(1), key),
            Err(KeyCommandError::Storage(StorageError::WriteFailed))
        );
        assert_eq!(
            r.revoke_key(Camera::Cam1, KeyId::INITIAL),
            Err(KeyCommandError::Storage(StorageError::WriteFailed))
        );
        assert_eq!(r.state(), before);
        assert_eq!(r.memory.floors.get(Camera::Cam1).saved(), None);
        assert!(!r.is_halted(), "a clean storage failure isn't a halt");
        // Once storage works again, so does the receiver.
        r.store.fail = false;
        r.receive(SPEC_FRAME).unwrap();
    }

    #[test]
    fn commands_that_change_nothing_write_nothing() {
        let mut r = receiver();
        r.receive(SPEC_FRAME).unwrap();
        r.revoke_key(Camera::Cam2, KeyId::INITIAL).unwrap();
        r.store.fail = true;
        // Identical re-add, repeated revoke: nothing to write, so they succeed.
        r.add_key(Camera::Cam1, KeyId::INITIAL, Key::from_hex(KEY1).unwrap())
            .unwrap();
        r.revoke_key(Camera::Cam2, KeyId::INITIAL).unwrap();
    }

    #[test]
    fn messages_for_errors_not_shown_elsewhere() {
        assert_eq!(
            ReceiveError::Storage(StorageError::WriteFailed).to_string(),
            "storage write failed: frame not accepted"
        );
        assert_eq!(ReceiveError::Internal.to_string(), "internal error");
        assert_eq!(
            KeyCommandError::Storage(StorageError::WriteFailed).to_string(),
            "storage write failed: keys not changed"
        );
    }

    #[test]
    fn an_interrupted_commit_halts_the_receiver_until_a_restart() {
        let mut r = receiver();
        r.receive(SPEC_FRAME).unwrap();
        // As if a panic had escaped the middle of a commit.
        r.memory.commit_in_progress = true;
        assert!(r.is_halted());
        assert_eq!(r.receive(SPEC_FRAME), Err(ReceiveError::Halted));
        let key = Key::from_hex(&"11".repeat(32)).unwrap();
        assert_eq!(
            r.add_key(Camera::Cam1, KeyId(1), key),
            Err(KeyCommandError::Halted)
        );
        assert_eq!(
            r.revoke_key(Camera::Cam1, KeyId::INITIAL),
            Err(KeyCommandError::Halted)
        );
        assert_eq!(
            KeyCommandError::Halted.to_string(),
            ReceiveError::Halted.to_string()
        );
        // Nothing changed, and state is still reported, for diagnosis.
        assert_eq!(statuses(&r), vec![KeyStatus::Active]);
        assert_eq!(r.state().cameras.get(Camera::Cam1).last_seq, Some(1));

        // A restart rebuilds memory from storage, which is never behind.
        r.restart().unwrap();
        assert!(!r.is_halted());
        assert_eq!(r.state().cameras.get(Camera::Cam1).last_seq, None);
        assert_eq!(
            r.receive(SPEC_FRAME),
            Err(ReceiveError::Stale {
                camera: Camera::Cam1,
                seq: 1
            })
        );
    }

    #[test]
    fn a_restart_keeps_storage_and_nothing_else() {
        let mut r = receiver();
        r.receive(SPEC_FRAME).unwrap();
        r.add_key(
            Camera::Cam1,
            KeyId(1),
            Key::from_hex(&"11".repeat(32)).unwrap(),
        )
        .unwrap();
        r.revoke_key(Camera::Cam1, KeyId::INITIAL).unwrap();
        let before = r.memory.floors;
        r.restart().unwrap();
        assert_eq!(statuses(&r), vec![KeyStatus::Revoked, KeyStatus::Active]);
        assert_eq!(r.memory.floors.get(Camera::Cam1).saved(), Some(101));
        assert!(!r.memory.floors.get(Camera::Cam1).admits(101));
        assert!(r.memory.floors.get(Camera::Cam2).admits(0));
        assert_ne!(r.memory.floors, before, "the loaded floor now applies");
        assert_eq!(r.memory.config, config());
    }

    /// A version 1 frame from `camera`, signed with `key`.
    fn signed(camera: u8, seq: u32, timestamp: i64, payload: &[u8], key: &str) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        let mut bytes = vec![1, camera];
        bytes.extend(seq.to_be_bytes());
        bytes.extend(timestamp.to_be_bytes());
        bytes.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());
        bytes.extend(payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(&hex::decode(key).unwrap()).unwrap();
        mac.update(&bytes);
        bytes.extend(mac.finalize().into_bytes());
        hex::encode(bytes)
    }

    /// A complete tree of `nodes` nodes, every value -1.
    fn complete_tree(nodes: usize) -> Vec<u8> {
        fn encode(index: usize, nodes: usize, out: &mut Vec<u8>) {
            if index >= nodes {
                out.push(0x00);
                return;
            }
            out.push(0x01);
            out.extend((-1_i32).to_be_bytes());
            encode(2 * index + 1, nodes, out);
            encode(2 * index + 2, nodes, out);
        }
        let mut out = Vec::new();
        encode(0, nodes, &mut out);
        out
    }

    /// The capacity of each part of the scratch room.
    fn room(r: &Receiver<MemoryStore>) -> ([usize; 2], [usize; 4]) {
        (
            [r.scratch.bytes.capacity(), r.scratch.synced.capacity()],
            r.scratch.tree.room(),
        )
    }

    #[test]
    fn the_scratch_room_never_grows_even_at_the_largest_sizes() {
        let config = Config::new(ConfigInput {
            period_ms: 50,
            max_jitter_ms: 5,
            pair_window_ms: 20,
            max_pending: crate::config::MAX_PENDING_LIMIT,
            persist_interval: None,
        })
        .unwrap();
        let mut r = Receiver::new(config, keys(), MemoryStore::default()).unwrap();
        let reserved = room(&r);
        assert_eq!(reserved.0, [MAX_FRAME_LEN, 1_025]);

        // cam2 is silent: cam1's queue fills to 1,024 and stays there.
        for seq in 1..=1_100 {
            let frame = signed(1, seq, 1000 + i64::from(seq) * 50, &[0x00], KEY1);
            r.receive(&frame).unwrap();
        }
        // The largest frame there can be: decoded, then refused for its tree.
        let mut largest = complete_tree(1_025);
        largest.resize(65_535, 0x00);
        let frame = signed(2, 1, 1000, &largest, KEY2);
        assert!(matches!(r.receive(&frame), Err(ReceiveError::Tree(_))));
        // A full-size tree that releases every waiting frame: the most one
        // frame can produce.
        let frame = signed(2, 2, 1_000_000, &complete_tree(1_024), KEY2);
        let accepted = r.receive(&frame).unwrap();
        assert_eq!(accepted.tree.len(), 1_024);
        assert_eq!(accepted.synced.len(), 1_024);
        assert_eq!(room(&r), reserved);
    }

    #[test]
    fn debug_output_never_shows_the_work_buffers() {
        let mut r = receiver();
        r.receive(SPEC_FRAME).unwrap();
        assert_eq!(format!("{:?}", r.scratch), "Scratch { .. }");
    }

    #[test]
    fn a_restart_fails_cleanly_if_storage_cant_be_read() {
        let mut r = receiver();
        r.receive(SPEC_FRAME).unwrap();
        r.store.inner = MemoryStore::default();
        assert_eq!(r.restart(), Err(StorageError::NothingSaved));
        assert_eq!(r.state().cameras.get(Camera::Cam1).last_seq, Some(1));
    }
}
