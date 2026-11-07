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
    /// The highest key id used by an accepted frame, if any.
    current: Option<KeyId>,
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

/// What `add_key` will do, decided before anything changes.
#[derive(Debug)]
pub enum AddKey {
    /// The same key is already provisioned under this id: nothing to do.
    AlreadyPresent,
    Insert(KeyId, Key),
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

/// What `revoke_key` will do, decided before anything changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revoke {
    AlreadyRevoked,
    Revoke(KeyId),
}

impl Keyring {
    /// A camera's keys after `init`: one usable key, key 0.
    #[must_use]
    pub fn new(initial: Key) -> Self {
        Self {
            slots: BTreeMap::from([(KeyId::INITIAL, Slot::Usable(initial))]),
            current: None,
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
            // Usable slots are never below the current key: `mark_used` retires
            // them and `plan_add` refuses them.
            Some(Slot::Usable(key)) => Ok(key),
        }
    }

    /// Records that a frame using `id` was accepted: every lower key is now
    /// retired, and its bytes are erased. Can't fail.
    pub fn mark_used(&mut self, id: KeyId) {
        if self.current.is_some_and(|current| current >= id) {
            return;
        }
        self.current = Some(id);
        for (_, slot) in self.slots.range_mut(..id) {
            if matches!(slot, Slot::Usable(_)) {
                // Dropping the old key erases its bytes.
                *slot = Slot::Retired;
            }
        }
    }

    /// Decides what adding `key` under `id` does, without changing anything.
    ///
    /// # Errors
    ///
    /// Returns why the key can't be added.
    pub fn plan_add(&self, id: KeyId, key: Key) -> Result<AddKey, AddKeyError> {
        match self.slots.get(&id) {
            Some(Slot::Revoked) => Err(AddKeyError::Revoked),
            Some(Slot::Retired) => Err(AddKeyError::Retired),
            Some(Slot::Usable(existing)) => {
                if existing.ct_eq(&key) {
                    Ok(AddKey::AlreadyPresent)
                } else {
                    Err(AddKeyError::DifferentKey)
                }
            }
            None => match self.current {
                Some(current) if id < current => Err(AddKeyError::BelowCurrent { current }),
                _ => Ok(AddKey::Insert(id, key)),
            },
        }
    }

    /// Carries out a plan from [`Keyring::plan_add`].
    pub fn apply_add(&mut self, plan: AddKey) {
        if let AddKey::Insert(id, key) = plan {
            self.slots.insert(id, Slot::Usable(key));
        }
    }

    /// Decides what revoking `id` does, without changing anything.
    ///
    /// # Errors
    ///
    /// Returns [`Unusable::NotProvisioned`] if `id` was never provisioned.
    pub fn plan_revoke(&self, id: KeyId) -> Result<Revoke, Unusable> {
        match self.slots.get(&id) {
            None => Err(Unusable::NotProvisioned),
            Some(Slot::Revoked) => Ok(Revoke::AlreadyRevoked),
            Some(Slot::Usable(_) | Slot::Retired) => Ok(Revoke::Revoke(id)),
        }
    }

    /// Carries out a plan from [`Keyring::plan_revoke`]. Can't fail.
    pub fn apply_revoke(&mut self, plan: Revoke) {
        if let Revoke::Revoke(id) = plan
            && let Some(slot) = self.slots.get_mut(&id)
        {
            // Dropping a usable key erases its bytes.
            *slot = Slot::Revoked;
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

    #[test]
    fn starts_with_key_zero_active() {
        let ring = Keyring::new(key(1));
        assert!(ring.usable(KeyId(0)).is_ok());
        assert_eq!(statuses(&ring), vec![(0, KeyStatus::Active)]);
        assert_eq!(ring.usable(KeyId(1)).unwrap_err(), Unusable::NotProvisioned);
    }

    #[test]
    fn using_a_higher_key_retires_the_lower_ones() {
        let mut ring = Keyring::new(key(1));
        let plan = ring.plan_add(KeyId(2), key(2)).unwrap();
        ring.apply_add(plan);
        let plan = ring.plan_add(KeyId(5), key(5)).unwrap();
        ring.apply_add(plan);
        ring.mark_used(KeyId(2));
        assert_eq!(
            statuses(&ring),
            vec![
                (0, KeyStatus::Retired),
                (2, KeyStatus::Active),
                (5, KeyStatus::Active)
            ]
        );
        assert_eq!(ring.usable(KeyId(0)).unwrap_err(), Unusable::Retired);
        assert!(ring.usable(KeyId(2)).is_ok());
        // Using a lower key later can't happen (it's rejected), and changes nothing.
        ring.mark_used(KeyId(0));
        assert!(ring.usable(KeyId(2)).is_ok());
    }

    #[test]
    fn add_key_rules() {
        let mut ring = Keyring::new(key(1));
        // Same bytes under the same id: nothing to do. Different bytes: refused.
        assert!(matches!(
            ring.plan_add(KeyId(0), key(1)),
            Ok(AddKey::AlreadyPresent)
        ));
        assert_eq!(
            ring.plan_add(KeyId(0), key(9)).unwrap_err(),
            AddKeyError::DifferentKey
        );
        let plan = ring.plan_add(KeyId(3), key(3)).unwrap();
        ring.apply_add(plan);
        ring.mark_used(KeyId(3));
        // Below the current key: retired, or would be retired at once.
        assert_eq!(
            ring.plan_add(KeyId(0), key(1)).unwrap_err(),
            AddKeyError::Retired
        );
        assert_eq!(
            ring.plan_add(KeyId(2), key(2)).unwrap_err(),
            AddKeyError::BelowCurrent { current: KeyId(3) }
        );
        // Revoked ids never come back, even with the same bytes.
        let plan = ring.plan_revoke(KeyId(3)).unwrap();
        ring.apply_revoke(plan);
        assert_eq!(
            ring.plan_add(KeyId(3), key(3)).unwrap_err(),
            AddKeyError::Revoked
        );
        // Above the current key: fine.
        assert!(matches!(
            ring.plan_add(KeyId(255), key(7)),
            Ok(AddKey::Insert(KeyId(255), _))
        ));
    }

    #[test]
    fn revoke_rules() {
        let mut ring = Keyring::new(key(1));
        assert_eq!(
            ring.plan_revoke(KeyId(7)).unwrap_err(),
            Unusable::NotProvisioned
        );
        let plan = ring.plan_revoke(KeyId(0)).unwrap();
        assert_eq!(plan, Revoke::Revoke(KeyId(0)));
        ring.apply_revoke(plan);
        assert_eq!(ring.usable(KeyId(0)).unwrap_err(), Unusable::Revoked);
        assert_eq!(ring.plan_revoke(KeyId(0)).unwrap(), Revoke::AlreadyRevoked);
        assert_eq!(statuses(&ring), vec![(0, KeyStatus::Revoked)]);
    }

    #[test]
    fn a_retired_key_can_be_revoked() {
        let mut ring = Keyring::new(key(1));
        let plan = ring.plan_add(KeyId(1), key(2)).unwrap();
        ring.apply_add(plan);
        ring.mark_used(KeyId(1));
        let plan = ring.plan_revoke(KeyId(0)).unwrap();
        ring.apply_revoke(plan);
        assert_eq!(
            statuses(&ring),
            vec![(0, KeyStatus::Revoked), (1, KeyStatus::Active)]
        );
        assert_eq!(ring.usable(KeyId(0)).unwrap_err(), Unusable::Revoked);
    }
}
