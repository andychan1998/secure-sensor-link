//! The frame wire format, and the step that turns untrusted bytes into a
//! verified frame.
//!
//! A frame moves through two types:
//!
//! - [`RawFrame`]: the layout has been checked, but nothing in it is trusted.
//!   The only thing code can read is the camera, which picks the key.
//! - [`VerifiedFrame`]: the tag matched the camera's key. Only now can code read
//!   the seq, timestamp and payload.
//!
//! [`RawFrame::verify`] is the only way to get a `VerifiedFrame`, so reading a
//! seq before the tag is checked doesn't compile.
//!
//! Version 1 frames carry no key id and use key 0. Version 2 frames add a
//! one-byte key id after the camera byte.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::camera::Camera;
use crate::key::{Key, KeyId};

/// Length of the HMAC-SHA256 tag.
pub const TAG_LEN: usize = 32;
/// Length of a version 1 header: version, camera, seq, timestamp, `payload_len`.
pub const V1_HEADER_LEN: usize = 16;
/// Length of a version 2 header: version 1's plus a key id.
pub const V2_HEADER_LEN: usize = 17;
pub const VERSION_1: u8 = 0x01;
pub const VERSION_2: u8 = 0x02;
/// Largest possible frame: the longest header plus the largest payload and tag.
pub const MAX_FRAME_LEN: usize = V2_HEADER_LEN + 65_535 + TAG_LEN;
/// Largest possible frame in hex characters.
pub const MAX_FRAME_HEX_LEN: usize = 2 * MAX_FRAME_LEN;

/// Decodes a frame's hex text (either case) into bytes.
///
/// The length is checked before anything is allocated, so an oversized frame
/// costs nothing.
///
/// # Errors
///
/// Returns an error if the text is too long, has an odd length or isn't hex.
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, FrameError> {
    if hex.len() > MAX_FRAME_HEX_LEN {
        return Err(FrameError::HexTooLong { len: hex.len() });
    }
    if !hex.len().is_multiple_of(2) {
        return Err(FrameError::OddHexLength { len: hex.len() });
    }
    hex::decode(hex).map_err(|_| FrameError::NotHex)
}

/// A frame whose layout has been checked but whose tag has not.
///
/// The seq, timestamp and payload are parsed but private: they can only be read
/// after [`RawFrame::verify`] succeeds.
#[derive(Debug)]
pub struct RawFrame<'a> {
    camera: Camera,
    key_id: KeyId,
    /// Header and payload: the bytes the tag covers.
    signed: &'a [u8],
    tag: &'a [u8; TAG_LEN],
    seq: u32,
    timestamp: i64,
    payload: &'a [u8],
}

impl<'a> RawFrame<'a> {
    /// Checks the frame's layout: version, length, camera and `payload_len`.
    ///
    /// Only fixed-position fields are read, and nothing here is trusted beyond
    /// choosing a key and finding the tag.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first layout problem found.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FrameError> {
        let len = bytes.len();
        let (&version, _) = bytes.split_first().ok_or(FrameError::Empty)?;
        let header_len = match version {
            VERSION_1 => V1_HEADER_LEN,
            VERSION_2 => V2_HEADER_LEN,
            other => return Err(FrameError::UnsupportedVersion(other)),
        };
        let min_len = header_len.saturating_add(TAG_LEN);
        if len < min_len {
            return Err(FrameError::TooShort { len, min: min_len });
        }
        let (signed, tag) = bytes
            .split_last_chunk::<TAG_LEN>()
            .ok_or(FrameError::TooShort { len, min: min_len })?;

        let mut header = Reader(signed);
        let _version = header.u8()?;
        let camera_byte = header.u8()?;
        let camera =
            Camera::from_wire(camera_byte).ok_or(FrameError::UnknownCamera(camera_byte))?;
        let key_id = if version == VERSION_2 {
            KeyId(header.u8()?)
        } else {
            KeyId::INITIAL
        };
        let seq = header.u32()?;
        let timestamp = header.i64()?;
        let payload_len = header.u16()?;
        let expected = usize::from(payload_len)
            .checked_add(min_len)
            .ok_or(FrameError::Internal)?;
        if len != expected {
            return Err(FrameError::LengthMismatch {
                payload_len,
                expected,
                actual: len,
            });
        }
        Ok(Self {
            camera,
            key_id,
            signed,
            tag,
            seq,
            timestamp,
            payload: header.0,
        })
    }

    /// The camera the frame claims to come from. Used only to pick the key.
    #[must_use]
    pub const fn camera(&self) -> Camera {
        self.camera
    }

    /// The key the frame claims to use (key 0 for version 1). Used only to pick
    /// the key.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Checks the tag against `key`, in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::AuthenticationFailed`] if the tag doesn't match.
    pub fn verify(self, key: &Key) -> Result<VerifiedFrame<'a>, FrameError> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| FrameError::Internal)?;
        mac.update(self.signed);
        // `verify_slice` compares in constant time.
        mac.verify_slice(self.tag)
            .map_err(|_| FrameError::AuthenticationFailed(self.camera))?;
        Ok(VerifiedFrame {
            seq: self.seq,
            timestamp: self.timestamp,
            payload: self.payload,
        })
    }
}

/// A frame whose tag matched its camera's key. Its camera and key id were
/// read from the [`RawFrame`] to pick the key, and are covered by the tag.
#[derive(Debug)]
pub struct VerifiedFrame<'a> {
    seq: u32,
    timestamp: i64,
    payload: &'a [u8],
}

impl<'a> VerifiedFrame<'a> {
    #[must_use]
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// The camera's timestamp as sent. It may still be negative: that check
    /// comes after the replay check.
    #[must_use]
    pub const fn timestamp(&self) -> i64 {
        self.timestamp
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Reads big-endian fields from the front of a byte slice, never past its end.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(FrameError::Internal)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, FrameError> {
        self.take::<1>().map(u8::from_be_bytes)
    }

    fn u16(&mut self) -> Result<u16, FrameError> {
        self.take::<2>().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        self.take::<4>().map(u32::from_be_bytes)
    }

    fn i64(&mut self) -> Result<i64, FrameError> {
        self.take::<8>().map(i64::from_be_bytes)
    }
}

/// Why a frame was rejected before or at the tag check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    HexTooLong {
        len: usize,
    },
    OddHexLength {
        len: usize,
    },
    NotHex,
    Empty,
    UnsupportedVersion(u8),
    TooShort {
        len: usize,
        min: usize,
    },
    UnknownCamera(u8),
    LengthMismatch {
        payload_len: u16,
        expected: usize,
        actual: usize,
    },
    AuthenticationFailed(Camera),
    /// A check that earlier checks make impossible failed.
    Internal,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HexTooLong { len } => write!(
                f,
                "malformed frame: {len} hex characters is more than the {MAX_FRAME_HEX_LEN} maximum"
            ),
            Self::OddHexLength { len } => {
                write!(f, "malformed frame: odd number of hex characters ({len})")
            }
            Self::NotHex => f.write_str("malformed frame: not valid hex"),
            Self::Empty => f.write_str("malformed frame: empty frame"),
            Self::UnsupportedVersion(version) => {
                write!(f, "malformed frame: unsupported version {version}")
            }
            Self::TooShort { len, min } => write!(
                f,
                "malformed frame: {len} bytes is shorter than the {min}-byte minimum"
            ),
            Self::UnknownCamera(byte) => write!(f, "malformed frame: unknown camera 0x{byte:02x}"),
            Self::LengthMismatch {
                payload_len,
                expected,
                actual,
            } => write!(
                f,
                "malformed frame: payload_len {payload_len} implies a {expected}-byte frame, got {actual} bytes"
            ),
            Self::AuthenticationFailed(camera) => write!(f, "authentication failed for {camera}"),
            Self::Internal => f.write_str("internal error while reading the frame"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    /// The spec's first example frame: cam1, seq 1, timestamp 1000, 31-byte tree.
    const SPEC_FRAME: &str = "01010000000100000000000003e8001f010000000101000000020000010000000301000000040000010000000500\
                              00fe04b3dcfd1aa96276d46024a02a89e9125a556fa6a3e1b14628fb7cd4375d82";

    fn key1() -> Key {
        Key::from_hex(KEY1).unwrap()
    }

    #[test]
    fn verifies_the_spec_example() {
        let bytes = decode_hex(SPEC_FRAME).unwrap();
        let raw = RawFrame::parse(&bytes).unwrap();
        assert_eq!(raw.camera(), Camera::Cam1);
        let frame = raw.verify(&key1()).unwrap();
        assert_eq!(frame.seq(), 1);
        assert_eq!(frame.timestamp(), 1000);
        assert_eq!(frame.payload().len(), 31);
    }

    #[test]
    fn hex_is_case_insensitive() {
        let bytes = decode_hex(&SPEC_FRAME.to_uppercase()).unwrap();
        RawFrame::parse(&bytes).unwrap().verify(&key1()).unwrap();
    }

    #[test]
    fn any_changed_byte_fails_the_tag() {
        let bytes = decode_hex(SPEC_FRAME).unwrap();
        // Change one byte in every position except version, camera and payload_len,
        // which would fail the layout checks first.
        for i in (2..14).chain(16..bytes.len()) {
            let mut changed = bytes.clone();
            changed[i] ^= 0x01;
            let raw = RawFrame::parse(&changed).unwrap();
            assert_eq!(
                raw.verify(&key1()).unwrap_err(),
                FrameError::AuthenticationFailed(Camera::Cam1),
                "byte {i}"
            );
        }
    }

    #[test]
    fn the_wrong_key_fails_the_tag() {
        let other =
            Key::from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
                .unwrap();
        let bytes = decode_hex(SPEC_FRAME).unwrap();
        assert_eq!(
            RawFrame::parse(&bytes).unwrap().verify(&other).unwrap_err(),
            FrameError::AuthenticationFailed(Camera::Cam1)
        );
    }

    #[test]
    fn size_limits_are_exact() {
        assert_eq!(MAX_FRAME_LEN, 65_584);
        assert_eq!(MAX_FRAME_HEX_LEN, 131_168);
        // Exactly the maximum passes the length check (and decodes); one byte more doesn't.
        assert_eq!(
            decode_hex(&"00".repeat(MAX_FRAME_LEN)).unwrap().len(),
            MAX_FRAME_LEN
        );
    }

    #[test]
    fn hex_checks() {
        assert_eq!(decode_hex("abc"), Err(FrameError::OddHexLength { len: 3 }));
        assert_eq!(decode_hex("zz"), Err(FrameError::NotHex));
        let too_long = "00".repeat(MAX_FRAME_LEN + 1);
        assert_eq!(
            decode_hex(&too_long),
            Err(FrameError::HexTooLong {
                len: MAX_FRAME_HEX_LEN + 2
            })
        );
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn layout_checks_in_order() {
        assert_eq!(RawFrame::parse(&[]).unwrap_err(), FrameError::Empty);
        assert_eq!(
            RawFrame::parse(&[0x03; 60]).unwrap_err(),
            FrameError::UnsupportedVersion(3)
        );
        assert_eq!(
            RawFrame::parse(&[0x00; 60]).unwrap_err(),
            FrameError::UnsupportedVersion(0)
        );
        assert_eq!(
            RawFrame::parse(&[0x01; 47]).unwrap_err(),
            FrameError::TooShort { len: 47, min: 48 }
        );
        assert_eq!(
            RawFrame::parse(&[0x02; 48]).unwrap_err(),
            FrameError::TooShort { len: 48, min: 49 }
        );
        let mut unknown_camera = vec![0u8; 49];
        unknown_camera[0] = 0x01;
        unknown_camera[1] = 0x03;
        assert_eq!(
            RawFrame::parse(&unknown_camera).unwrap_err(),
            FrameError::UnknownCamera(3)
        );
    }

    /// The spec's follow-on 1 example: cam1, key 1, seq 5, timestamp 1200, tree [5].
    const SPEC_V2_FRAME: &str = "0201010000000500000000000004b0000701000000050000bf5420c0cf3ae90a\
                                 54057c6bbde21814ff9d4763edb475d13d0009d7880841e1";
    const KEY1_ID1: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

    #[test]
    fn verifies_a_version_2_frame_and_reads_its_key_id() {
        let bytes = decode_hex(SPEC_V2_FRAME).unwrap();
        let raw = RawFrame::parse(&bytes).unwrap();
        assert_eq!(raw.camera(), Camera::Cam1);
        assert_eq!(raw.key_id(), KeyId(1));
        let frame = raw.verify(&Key::from_hex(KEY1_ID1).unwrap()).unwrap();
        assert_eq!(frame.seq(), 5);
        assert_eq!(frame.timestamp(), 1200);
        assert_eq!(frame.payload(), &[1, 0, 0, 0, 5, 0, 0]);
        // The key id is covered by the tag.
        let mut changed = bytes.clone();
        changed[2] = 0;
        let raw = RawFrame::parse(&changed).unwrap();
        assert_eq!(raw.key_id(), KeyId(0));
        assert!(raw.verify(&Key::from_hex(KEY1_ID1).unwrap()).is_err());
    }

    #[test]
    fn version_1_frames_use_key_zero() {
        let bytes = decode_hex(SPEC_FRAME).unwrap();
        let raw = RawFrame::parse(&bytes).unwrap();
        assert_eq!(raw.key_id(), KeyId(0));
        assert_eq!(raw.verify(&key1()).unwrap().seq(), 1);
    }

    #[test]
    fn version_2_length_mismatch_counts_the_longer_header() {
        let mut bytes = vec![0u8; 49];
        bytes[0] = 0x02;
        bytes[1] = 0x01;
        bytes[16] = 1;
        assert_eq!(
            RawFrame::parse(&bytes).unwrap_err().to_string(),
            "malformed frame: payload_len 1 implies a 50-byte frame, got 49 bytes"
        );
    }

    #[test]
    fn length_mismatch_matches_the_spec_message() {
        // 55 bytes claiming payload_len 65535, as in the spec's example.
        let mut bytes = vec![0u8; 55];
        bytes[0] = 0x01;
        bytes[1] = 0x01;
        bytes[14] = 0xff;
        bytes[15] = 0xff;
        let err = RawFrame::parse(&bytes).unwrap_err();
        assert_eq!(
            err.to_string(),
            "malformed frame: payload_len 65535 implies a 65583-byte frame, got 55 bytes"
        );
    }

    #[test]
    fn largest_and_smallest_payloads_parse() {
        for payload_len in [0usize, 65_535] {
            let mut bytes = vec![0u8; 48 + payload_len];
            bytes[0] = 0x01;
            bytes[1] = 0x02;
            bytes[14..16].copy_from_slice(&u16::try_from(payload_len).unwrap().to_be_bytes());
            let raw = RawFrame::parse(&bytes).unwrap();
            assert_eq!(raw.camera(), Camera::Cam2);
        }
    }

    #[test]
    fn extreme_header_values_are_read_exactly() {
        let mut bytes = vec![0u8; 49];
        bytes[0] = 0x01;
        bytes[1] = 0x01;
        bytes[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        bytes[6..14].copy_from_slice(&i64::MIN.to_be_bytes());
        bytes[15] = 1;
        let mut mac = Hmac::<Sha256>::new_from_slice(key1().as_bytes()).unwrap();
        mac.update(&bytes[..17]);
        bytes[17..].copy_from_slice(&mac.finalize().into_bytes());
        let frame = RawFrame::parse(&bytes).unwrap().verify(&key1()).unwrap();
        assert_eq!(frame.seq(), u32::MAX);
        assert_eq!(frame.timestamp(), i64::MIN);
    }

    #[test]
    fn messages_for_errors_not_shown_elsewhere() {
        assert_eq!(
            FrameError::HexTooLong { len: 200_000 }.to_string(),
            format!(
                "malformed frame: 200000 hex characters is more than the {MAX_FRAME_HEX_LEN} maximum"
            )
        );
        assert_eq!(
            FrameError::Internal.to_string(),
            "internal error while reading the frame"
        );
    }
}
