//! One camera's keys: which are provisioned, which the camera has moved past,
//! and which have been revoked.
//!
//! A key is in one of three states:
//!
//! - usable: provisioned, not revoked, and not below the camera's current key;
//! - retired: the camera has used a higher key, so frames using this one are
//!   rejected (cameras only move forward through their keys);
//! - revoked: suspected compromised; frames using it are rejected from now on.
//!
//! Only usable keys keep their bytes. A key's bytes are erased the moment it is
//! retired or revoked, because it can never verify a frame again.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use crate::key::{Key, KeyId};

/// One camera's keys. Holds at most 256 entries, one per possible key id.
#[derive(Debug)]
pub struct Keyring {
    slots: BTreeMap<KeyId, Slot>,
    /// The key the camera is on: the highest key id used by an accepted
    /// frame, or key 0 until then. Always provisioned (keys are never removed).
    current: KeyId,
}

#[derive(Debug)]
enum Slot {
    Usable(Key),
    Retired,
    Revoked,
}

/// A key's status as reported in the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

/// One entry of a camera's key list in the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct KeyEntry {
    pub key_id: KeyId,
    pub status: KeyStatus,
}

/// Why a frame's key can't be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unusable {
    NotProvisioned,
    Revoked,
    Retired,
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotProvisioned => "is not provisioned",
            Self::Revoked => "is revoked",
            Self::Retired => "is retired",
        })
    }
}

/// Why `add_key` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddKeyError {
    /// Revocation is permanent: a revoked id never comes back.
    Revoked,
    /// The camera has already moved past this id.
    Retired,
    /// An id below the camera's current key would be retired at once.
    BelowCurrent { current: KeyId },
    /// A different key is already provisioned under this id.
    DifferentKey,
}

impl Keyring {
    /// A camera's keys after `init`: one usable key, key 0.
    #[must_use]
    pub fn new(initial: Key) -> Self {
        Self {
            slots: BTreeMap::from([(KeyId::INITIAL, Slot::Usable(initial))]),
            current: KeyId::INITIAL,
        }
    }

    /// The key for `id`, if a frame may use it.
    ///
    /// # Errors
    ///
    /// Returns why the key can't be used: not provisioned, revoked or retired,
    /// checked in that order.
    pub fn usable(&self, id: KeyId) -> Result<&Key, Unusable> {
        match self.slots.get(&id) {
            None => Err(Unusable::NotProvisioned),
            Some(Slot::Revoked) => Err(Unusable::Revoked),
            Some(Slot::Retired) => Err(Unusable::Retired),
            // Usable slots are never below the current key: `after_use` retires
            // them and `with_added` refuses them.
            Some(Slot::Usable(key)) => Ok(key),
        }
    }

    /// The keys after a frame using `id` is accepted, or `None` if nothing
    /// changes. Using a key above the current one moves the camera to it and
    /// retires every lower key; the new keyring holds no copy of their bytes.
    #[must_use]
    pub fn after_use(&self, id: KeyId) -> Option<Self> {
        if id <= self.current {
            return None;
        }
        let mut next = self.duplicate();
        next.current = id;
        for (_, slot) in next.slots.range_mut(..id) {
            if matches!(slot, Slot::Usable(_)) {
                // Dropping the old key erases its bytes.
                *slot = Slot::Retired;
            }
        }
        Some(next)
    }

    /// The keys with `key` added as `id`, or `None` if that exact key is
    /// already provisioned under `id`.
    ///
    /// # Errors
    ///
    /// Returns why the key can't be added.
    pub fn with_added(&self, id: KeyId, key: Key) -> Result<Option<Self>, AddKeyError> {
        match self.slots.get(&id) {
            Some(Slot::Revoked) => Err(AddKeyError::Revoked),
            Some(Slot::Retired) => Err(AddKeyError::Retired),
            Some(Slot::Usable(existing)) => {
                if existing.ct_eq(&key) {
                    Ok(None)
                } else {
                    Err(AddKeyError::DifferentKey)
                }
            }
            None if id < self.current => Err(AddKeyError::BelowCurrent {
                current: self.current,
            }),
            None => {
                let mut next = self.duplicate();
                next.slots.insert(id, Slot::Usable(key));
                Ok(Some(next))
            }
        }
    }

    /// The keys with `id` revoked, or `None` if it already is.
    ///
    /// # Errors
    ///
    /// Returns [`Unusable::NotProvisioned`] if `id` was never provisioned.
    pub fn with_revoked(&self, id: KeyId) -> Result<Option<Self>, Unusable> {
        match self.slots.get(&id) {
            None => Err(Unusable::NotProvisioned),
            Some(Slot::Revoked) => Ok(None),
            Some(Slot::Usable(_) | Slot::Retired) => {
                let mut next = self.duplicate();
                // Dropping a usable key erases its bytes.
                next.slots.insert(id, Slot::Revoked);
                Ok(Some(next))
            }
        }
    }

    /// An explicit copy, made only for storage and for planning a change. Keys
    /// are copied with [`Key::duplicate`].
    #[must_use]
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            slots: self
                .slots
                .iter()
                .map(|(&id, slot)| {
                    let slot = match slot {
                        Slot::Usable(key) => Slot::Usable(key.duplicate()),
                        Slot::Retired => Slot::Retired,
                        Slot::Revoked => Slot::Revoked,
                    };
                    (id, slot)
                })
                .collect(),
            current: self.current,
        }
    }

    /// Every provisioned key and its status, by key id.
    #[must_use]
    pub fn entries(&self) -> Vec<KeyEntry> {
        self.slots
            .iter()
            .map(|(&key_id, slot)| KeyEntry {
                key_id,
                status: match slot {
                    Slot::Revoked => KeyStatus::Revoked,
                    Slot::Retired => KeyStatus::Retired,
                    Slot::Usable(_) => KeyStatus::Active,
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key {
        Key::from_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn statuses(ring: &Keyring) -> Vec<(u8, KeyStatus)> {
        ring.entries()
            .iter()
            .map(|e| (e.key_id.0, e.status))
            .collect()
    }

    fn added(ring: &Keyring, id: u8, byte: u8) -> Keyring {
        ring.with_added(KeyId(id), key(byte)).unwrap().unwrap()
    }

    #[test]
    fn starts_with_key_zero_active() {
        let ring = Keyring::new(key(1));
        assert!(ring.usable(KeyId(0)).is_ok());
        assert_eq!(statuses(&ring), vec![(0, KeyStatus::Active)]);
        assert_eq!(ring.usable(KeyId(1)).unwrap_err(), Unusable::NotProvisioned);
    }

    #[test]
    fn using_a_higher_key_retires_the_lower_ones() {
        let ring = added(&added(&Keyring::new(key(1)), 2, 2), 5, 5);
        let ring = ring.after_use(KeyId(2)).unwrap();
        assert_eq!(
            statuses(&ring),
            vec![
                (0, KeyStatus::Retired),
                (2, KeyStatus::Active),
                (5, KeyStatus::Active)
            ]
        );
        assert_eq!(ring.usable(KeyId(0)).unwrap_err(), Unusable::Retired);
        assert!(ring.usable(KeyId(2)).unwrap().ct_eq(&key(2)));
        // Using the current key or a lower one changes nothing.
        assert!(ring.after_use(KeyId(2)).is_none());
        assert!(ring.after_use(KeyId(0)).is_none());
        // Moving on again.
        let ring = ring.after_use(KeyId(5)).unwrap();
        assert_eq!(ring.usable(KeyId(2)).unwrap_err(), Unusable::Retired);
    }

    #[test]
    fn a_camera_starts_on_key_zero() {
        let ring = Keyring::new(key(1));
        assert!(ring.after_use(KeyId(0)).is_none(), "nothing changes");
        // Key 1 can be added: it isn't below the current key.
        added(&ring, 1, 2);
    }

    #[test]
    fn add_key_rules() {
        let ring = Keyring::new(key(1));
        // Same bytes under the same id: nothing to do. Different bytes: refused.
        assert!(ring.with_added(KeyId(0), key(1)).unwrap().is_none());
        assert_eq!(
            ring.with_added(KeyId(0), key(9)).unwrap_err(),
            AddKeyError::DifferentKey
        );
        let ring = added(&ring, 3, 3).after_use(KeyId(3)).unwrap();
        // Below the current key: retired, or would be retired at once.
        assert_eq!(
            ring.with_added(KeyId(0), key(1)).unwrap_err(),
            AddKeyError::Retired
        );
        assert_eq!(
            ring.with_added(KeyId(2), key(2)).unwrap_err(),
            AddKeyError::BelowCurrent { current: KeyId(3) }
        );
        // Revoked ids never come back, even with the same bytes.
        let ring = ring.with_revoked(KeyId(3)).unwrap().unwrap();
        assert_eq!(
            ring.with_added(KeyId(3), key(3)).unwrap_err(),
            AddKeyError::Revoked
        );
        // Above the current key: fine.
        let ring = added(&ring, 255, 7);
        assert!(ring.usable(KeyId(255)).unwrap().ct_eq(&key(7)));
    }

    #[test]
    fn revoke_rules() {
        let ring = Keyring::new(key(1));
        assert_eq!(
            ring.with_revoked(KeyId(7)).unwrap_err(),
            Unusable::NotProvisioned
        );
        let ring = ring.with_revoked(KeyId(0)).unwrap().unwrap();
        assert_eq!(ring.usable(KeyId(0)).unwrap_err(), Unusable::Revoked);
        assert!(ring.with_revoked(KeyId(0)).unwrap().is_none());
        assert_eq!(statuses(&ring), vec![(0, KeyStatus::Revoked)]);
    }

    #[test]
    fn a_retired_key_can_be_revoked() {
        let ring = added(&Keyring::new(key(1)), 1, 2)
            .after_use(KeyId(1))
            .unwrap();
        let ring = ring.with_revoked(KeyId(0)).unwrap().unwrap();
        assert_eq!(
            statuses(&ring),
            vec![(0, KeyStatus::Revoked), (1, KeyStatus::Active)]
        );
        assert_eq!(ring.usable(KeyId(0)).unwrap_err(), Unusable::Revoked);
    }

    #[test]
    fn planning_a_change_leaves_the_original_alone() {
        let ring = Keyring::new(key(1));
        let _ = ring.with_revoked(KeyId(0)).unwrap();
        let _ = ring.with_added(KeyId(1), key(2)).unwrap();
        let _ = ring.after_use(KeyId(1));
        assert_eq!(statuses(&ring), vec![(0, KeyStatus::Active)]);
    }

    #[test]
    fn a_duplicate_has_the_same_keys_and_current_key() {
        let ring = added(&Keyring::new(key(1)), 4, 4)
            .after_use(KeyId(4))
            .unwrap();
        let copy = ring.duplicate();
        assert_eq!(statuses(&copy), statuses(&ring));
        assert!(copy.usable(KeyId(4)).unwrap().ct_eq(&key(4)));
        // The current key came along: key 3 is below it.
        assert_eq!(
            copy.with_added(KeyId(3), key(3)).unwrap_err(),
            AddKeyError::BelowCurrent { current: KeyId(4) }
        );
    }
}
