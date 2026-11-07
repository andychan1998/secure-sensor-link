//! Camera keys: 32 secret bytes that erase themselves and never print.

use std::fmt;

use ctutils::CtEq;
use hmac::digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a camera key in bytes.
pub const KEY_LEN: usize = 32;

/// A camera's HMAC-SHA256 key.
///
/// The bytes are erased when the key is dropped, using the HMAC library's
/// `zeroize` support (volatile writes the compiler may not remove). The type has
/// no `Clone`: the only copies are made by `Key::duplicate`, for storage. Its
/// `Debug` output never shows the bytes.
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Decodes a key from exactly 64 hex characters (either case).
    ///
    /// # Errors
    ///
    /// Returns an error if `hex` isn't exactly 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        // Start from zeros so that a half-decoded key is still erased on error.
        let mut key = Self([0; KEY_LEN]);
        let expected = KEY_LEN.saturating_mul(2);
        if hex.len() != expected {
            return Err(KeyError::WrongLength { len: hex.len() });
        }
        hex::decode_to_slice(hex, &mut key.0).map_err(|_| KeyError::NotHex)?;
        Ok(key)
    }

    /// An explicit copy, made only where a key is written to storage or loaded
    /// back from it (non-volatile storage must hold the keys to survive a
    /// restart). Each copy erases itself when dropped.
    #[must_use]
    pub(crate) const fn duplicate(&self) -> Self {
        Self(self.0)
    }

    /// The key bytes, for computing a tag.
    pub(crate) const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Whether two keys are the same, in time that doesn't depend on where
    /// they differ, so timing can't reveal a stored key byte by byte.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).to_bool()
    }
}

/// A key's number within its camera, from 0 to 255. Keys given to `init` are
/// key 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct KeyId(pub u8);

impl KeyId {
    /// The key used by version 1 frames and set up by `init`.
    pub const INITIAL: Self = Self(0);
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Key {}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(redacted)")
    }
}

/// Why a key string was rejected. Never contains key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    WrongLength { len: usize },
    NotHex,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { len } => {
                write!(f, "must be 64 hex characters (a 32-byte key), got {len}")
            }
            Self::NotHex => f.write_str("must contain only hex characters"),
        }
    }
}

impl std::error::Error for KeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn decodes_either_case() {
        let lower = Key::from_hex(HEX).unwrap();
        let upper = Key::from_hex(&HEX.to_uppercase()).unwrap();
        assert_eq!(lower.as_bytes(), upper.as_bytes());
        assert_eq!(lower.as_bytes()[31], 0x1f);
    }

    #[test]
    fn rejects_wrong_length_and_non_hex() {
        assert_eq!(
            Key::from_hex(&HEX[..62]).unwrap_err(),
            KeyError::WrongLength { len: 62 }
        );
        assert_eq!(
            Key::from_hex(&format!("{HEX}00")).unwrap_err(),
            KeyError::WrongLength { len: 66 }
        );
        let not_hex = format!("{}zz", &HEX[..62]);
        assert_eq!(Key::from_hex(&not_hex).unwrap_err(), KeyError::NotHex);
    }

    #[test]
    fn a_duplicate_is_equal_and_separate() {
        let key = Key::from_hex(HEX).unwrap();
        let copy = key.duplicate();
        assert!(copy.ct_eq(&key));
        drop(key);
        assert_eq!(copy.as_bytes()[31], 0x1f);
    }

    #[test]
    fn constant_time_equality() {
        let a = Key::from_hex(HEX).unwrap();
        let b = Key::from_hex(HEX).unwrap();
        assert!(a.ct_eq(&b));
        // A difference in the first or the last byte is found either way.
        let first = Key::from_hex(&format!("01{}", &HEX[2..])).unwrap();
        let last = Key::from_hex(&format!("{}1e", &HEX[..62])).unwrap();
        assert!(!a.ct_eq(&first));
        assert!(!a.ct_eq(&last));
    }

    #[test]
    fn debug_output_hides_the_bytes() {
        let key = Key::from_hex(HEX).unwrap();
        assert_eq!(format!("{key:?}"), "Key(redacted)");
    }
}
