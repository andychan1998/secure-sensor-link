//! The receiver: checks each frame, then commits its effects.
//!
//! Every frame goes through [`Receiver::plan`], which runs all checks in the
//! documented order and computes every result without changing anything, and
//! then [`Receiver::commit`], which applies the plan with steps that can't fail.
//! A rejected frame therefore changes nothing.
//!
//! Key management (`add_key`, `revoke_key`) follows the same pattern: decide,
//! then apply.
//!
//! If a panic ever escapes a commit (a bug), the receiver can't vouch for its
//! state, so it stops changing it: see [`Receiver::is_halted`].

use std::fmt;

use serde::Serialize;

use crate::camera::{Camera, PerCamera};
use crate::config::Config;
use crate::frame::{self, FrameError, RawFrame};
use crate::key::{Key, KeyId};
use crate::keyring::{AddKeyError, KeyEntry, Keyring, Unusable};
use crate::sync::{Pending, Queues, SyncPlan, SyncRecord};
use crate::timeline::{self, Anchor, Millis};
use crate::tree::{Tree, TreeError};

/// The receiver after a successful `init`.
#[derive(Debug)]
pub struct Receiver {
    config: Config,
    keys: PerCamera<Keyring>,
    /// The last accepted frame from each camera.
    last: PerCamera<Option<Anchor>>,
    queues: Queues,
    /// Set for the duration of a commit. If it's still set when a command starts,
    /// a panic interrupted a commit and the state may be half-changed.
    commit_in_progress: bool,
}

/// What an accepted frame produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub camera: Camera,
    pub key_id: KeyId,
    pub seq: u32,
    pub timestamp: Millis,
    pub corrected: bool,
    pub tree: Vec<Option<i32>>,
    pub synced: Vec<SyncRecord>,
}

/// Everything an accepted frame will change, computed before changing it.
#[derive(Debug)]
struct Plan {
    camera: Camera,
    key_id: KeyId,
    anchor: Anchor,
    accepted: Accepted,
    sync: SyncPlan,
}

impl Receiver {
    /// A receiver with no frames accepted yet. Each camera's `init` key is
    /// its key 0.
    #[must_use]
    pub fn new(config: Config, keys: PerCamera<Key>) -> Self {
        let (cam1, cam2) = keys.into_parts();
        Self {
            queues: Queues::new(config.max_pending()),
            config,
            keys: PerCamera::new(Keyring::new(cam1), Keyring::new(cam2)),
            last: PerCamera::default(),
            commit_in_progress: false,
        }
    }

    /// Processes one hex-encoded frame.
    ///
    /// # Errors
    ///
    /// Returns why the frame was rejected. A rejected frame changes nothing.
    pub fn receive(&mut self, frame_hex: &str) -> Result<Accepted, ReceiveError> {
        if self.is_halted() {
            return Err(ReceiveError::Halted);
        }
        let plan = self.plan(frame_hex)?;
        Ok(self.commit(plan))
    }

    /// Whether an earlier commit was interrupted, so frames are refused.
    #[must_use]
    pub const fn is_halted(&self) -> bool {
        self.commit_in_progress
    }

    /// Runs every check, in order, and computes the frame's effects.
    fn plan(&self, frame_hex: &str) -> Result<Plan, ReceiveError> {
        // 1-3: hex, version, layout. Only the camera and key id are readable.
        let bytes = frame::decode_hex(frame_hex)?;
        let raw = RawFrame::parse(&bytes)?;
        let camera = raw.camera();
        let key_id = raw.key_id();

        // 4: key status. A revoked or retired key isn't even tried.
        let key = self
            .keys
            .get(camera)
            .usable(key_id)
            .map_err(|reason| ReceiveError::Key {
                camera,
                key_id,
                reason,
            })?;

        // 5: the tag.
        let frame = raw.verify(key)?;
        let seq = frame.seq();

        // 6: replay. Only ever judges a seq the camera really sent.
        let last = *self.last.get(camera);
        if last.is_some_and(|anchor| seq <= anchor.seq) {
            return Err(ReceiveError::Stale { camera, seq });
        }

        // 7-8: timestamp, then the tree, the most complex parsing, last.
        let raw_timestamp = frame.timestamp();
        if raw_timestamp < 0 {
            return Err(ReceiveError::NegativeTimestamp(raw_timestamp));
        }
        let tree = Tree::decode(frame.payload())?;

        // Effects: timestamp correction and pairing.
        let corrected = timeline::correct(last, seq, raw_timestamp, &self.config)
            .ok_or(ReceiveError::Internal)?;
        let pending = Pending {
            seq,
            timestamp: corrected.timestamp,
            key_id,
        };
        let sync = self
            .queues
            .plan(camera, pending, &self.config)
            .ok_or(ReceiveError::Internal)?;

        Ok(Plan {
            camera,
            key_id,
            anchor: Anchor {
                seq,
                timestamp: corrected.timestamp,
            },
            accepted: Accepted {
                camera,
                key_id,
                seq,
                timestamp: corrected.timestamp,
                corrected: corrected.corrected,
                tree: tree.level_order(),
                synced: sync.records().to_vec(),
            },
            sync,
        })
    }

    /// Applies a plan. Nothing here can fail.
    fn commit(&mut self, plan: Plan) -> Accepted {
        self.commit_in_progress = true;
        *self.last.get_mut(plan.camera) = Some(plan.anchor);
        self.keys.get_mut(plan.camera).mark_used(plan.key_id);
        self.queues.apply(&plan.sync);
        self.commit_in_progress = false;
        plan.accepted
    }

    /// Provisions `key` as `camera`'s key `key_id`.
    ///
    /// # Errors
    ///
    /// Refuses a revoked id, an id the camera has moved past, and a different key
    /// under an id already provisioned. Re-adding the identical key succeeds and
    /// changes nothing.
    pub fn add_key(
        &mut self,
        camera: Camera,
        key_id: KeyId,
        key: Key,
    ) -> Result<(), KeyCommandError> {
        if self.is_halted() {
            return Err(KeyCommandError::Halted);
        }
        let plan = self
            .keys
            .get(camera)
            .plan_add(key_id, key)
            .map_err(|reason| KeyCommandError::Add {
                camera,
                key_id,
                reason,
            })?;
        self.commit_in_progress = true;
        self.keys.get_mut(camera).apply_add(plan);
        self.commit_in_progress = false;
        Ok(())
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
        let plan = self
            .keys
            .get(camera)
            .plan_revoke(key_id)
            .map_err(|reason| KeyCommandError::Unusable {
                camera,
                key_id,
                reason,
            })?;
        self.commit_in_progress = true;
        self.keys.get_mut(camera).apply_revoke(plan);
        self.queues.drop_key(camera, key_id);
        self.commit_in_progress = false;
        Ok(())
    }

    /// The state reported by `get_state` and other commands.
    #[must_use]
    pub fn state(&self) -> State {
        State {
            cameras: self.last.map(|camera, last| CameraState {
                last_seq: last.map(|anchor| anchor.seq),
                last_timestamp: last.map(|anchor| anchor.timestamp),
                pending: self.queues.pending_seqs(camera).collect(),
                keys: self.keys.get(camera).entries(),
            }),
        }
    }
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
    /// An earlier commit was interrupted; frames are refused.
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
            Self::Halted => f.write_str(
                "receiver halted: an internal error interrupted an earlier frame, so its state can't be trusted",
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
            Self::Halted => ReceiveError::Halted.fmt(f),
        }
    }
}

impl std::error::Error for KeyCommandError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigInput;

    const KEY1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const KEY2: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const SPEC_FRAME: &str = "01010000000100000000000003e8001f010000000101000000020000010000000301000000040000010000000500\
                              00fe04b3dcfd1aa96276d46024a02a89e9125a556fa6a3e1b14628fb7cd4375d82";

    fn receiver() -> Receiver {
        let config = Config::new(ConfigInput {
            period_ms: 50,
            max_jitter_ms: 5,
            pair_window_ms: 20,
            max_pending: 4,
        })
        .unwrap();
        let keys = PerCamera::new(Key::from_hex(KEY1).unwrap(), Key::from_hex(KEY2).unwrap());
        Receiver::new(config, keys)
    }

    #[test]
    fn accepts_the_spec_frame() {
        let mut r = receiver();
        let accepted = r.receive(SPEC_FRAME).unwrap();
        assert_eq!(accepted.seq, 1);
        assert_eq!(accepted.timestamp, 1000);
        assert!(!r.is_halted());
    }

    #[test]
    fn an_interrupted_commit_halts_the_receiver() {
        let mut r = receiver();
        // As if a panic had escaped the middle of a commit.
        r.commit_in_progress = true;
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
        assert_eq!(
            r.state().cameras.get(Camera::Cam1).keys,
            vec![KeyEntry {
                key_id: KeyId::INITIAL,
                status: crate::keyring::KeyStatus::Active
            }]
        );
        assert_eq!(r.state().cameras.get(Camera::Cam1).last_seq, None);
    }
}
