//! Camera keys: 32 secret bytes that erase themselves and never print.

use std::fmt;

use hmac::digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a camera key in bytes.
pub const KEY_LEN: usize = 32;

/// A camera's HMAC-SHA256 key.
///
/// The bytes are erased when the key is dropped, using the HMAC library's
/// `zeroize` support (volatile writes the compiler may not remove). The type has
/// no `Clone`, so the only copy is the one the receiver holds, and its `Debug`
/// output never shows the bytes.
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

    /// The key bytes, for computing a tag.
    pub(crate) const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
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
    fn debug_output_hides_the_bytes() {
        let key = Key::from_hex(HEX).unwrap();
        assert_eq!(format!("{key:?}"), "Key(redacted)");
    }
}
