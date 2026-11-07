//! Timestamp correction for one camera.
//!
//! Corrected timestamps are 128-bit: the expected timestamp
//! `T + (seq - S) * period_ms` can exceed the 64-bit range (T near the 64-bit
//! maximum, a seq gap of 4 billion times 60,000 ms), and the spec requires exact
//! arithmetic. Every operation is checked.

use crate::config::Config;

/// A timestamp in milliseconds, wide enough for any corrected value.
pub type Millis = i128;

/// The last accepted frame from a camera: what the next frame is measured from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub seq: u32,
    pub timestamp: Millis,
}

/// A frame's timestamp after correction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corrected {
    pub timestamp: Millis,
    /// Whether the camera's timestamp was replaced with the expected one.
    pub corrected: bool,
}

/// Applies the spec's correction rule to a frame with `seq` and camera
/// timestamp `raw`.
///
/// The first frame from a camera (`anchor` is `None`) keeps its timestamp. Every
/// later frame is compared with `T + (seq - S) * period_ms`; if it differs by
/// more than `max_jitter_ms`, the expected value replaces it.
///
/// Returns `None` only if `seq` isn't above the anchor's seq, which the replay
/// check rules out before this is called.
#[must_use]
pub fn correct(anchor: Option<Anchor>, seq: u32, raw: i64, config: &Config) -> Option<Corrected> {
    let raw = Millis::from(raw);
    let Some(anchor) = anchor else {
        return Some(Corrected {
            timestamp: raw,
            corrected: false,
        });
    };
    let gap = seq.checked_sub(anchor.seq).filter(|gap| *gap > 0)?;
    let expected = Millis::from(gap)
        .checked_mul(Millis::from(config.period_ms()))?
        .checked_add(anchor.timestamp)?;
    let difference = raw.checked_sub(expected)?.unsigned_abs();
    if difference > u128::from(config.max_jitter_ms()) {
        Some(Corrected {
            timestamp: expected,
            corrected: true,
        })
    } else {
        Some(Corrected {
            timestamp: raw,
            corrected: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigInput;

    fn config(period: u64, jitter: u64) -> Config {
        Config::new(ConfigInput {
            period_ms: period,
            max_jitter_ms: jitter,
            pair_window_ms: 0,
            max_pending: 1,
            persist_interval: None,
        })
        .unwrap()
    }

    fn anchor(seq: u32, timestamp: Millis) -> Option<Anchor> {
        Some(Anchor { seq, timestamp })
    }

    #[test]
    fn first_frame_keeps_its_timestamp() {
        let c = correct(None, 7, 1234, &config(50, 5)).unwrap();
        assert_eq!(
            c,
            Corrected {
                timestamp: 1234,
                corrected: false
            }
        );
    }

    #[test]
    fn spec_example_glitch_is_replaced() {
        // cam2: last accepted seq 1 at 1005; seq 2 arrives claiming 9999.
        let c = correct(anchor(1, 1005), 2, 9999, &config(50, 5)).unwrap();
        assert_eq!(
            c,
            Corrected {
                timestamp: 1055,
                corrected: true
            }
        );
    }

    #[test]
    fn jitter_boundary_is_inclusive() {
        let cfg = config(50, 5);
        // Expected 1050: 1045 and 1055 are within jitter, 1044 and 1056 are not.
        for (raw, expect) in [(1045, 1045), (1055, 1055), (1044, 1050), (1056, 1050)] {
            assert_eq!(
                correct(anchor(1, 1000), 2, raw, &cfg).unwrap().timestamp,
                expect,
                "raw {raw}"
            );
        }
    }

    #[test]
    fn seq_gaps_scale_the_expected_timestamp() {
        // Spec example: frame 3 lost, expected 1050 + (4 - 2) * 50 = 1150.
        let c = correct(anchor(2, 1050), 4, 1150, &config(50, 5)).unwrap();
        assert_eq!(
            c,
            Corrected {
                timestamp: 1150,
                corrected: false
            }
        );
    }

    #[test]
    fn largest_values_are_exact_beyond_64_bits() {
        // Anchor at the 64-bit maximum, the largest possible seq gap and period.
        let start = Millis::from(i64::MAX);
        let c = correct(anchor(0, start), u32::MAX, 0, &config(60_000, 0)).unwrap();
        let expected = start + Millis::from(u32::MAX) * 60_000;
        assert_eq!(expected, 9_223_629_734_892_475_807);
        assert_eq!(
            c,
            Corrected {
                timestamp: expected,
                corrected: true
            }
        );
    }

    #[test]
    fn refuses_a_seq_that_is_not_newer() {
        let cfg = config(50, 5);
        assert_eq!(correct(anchor(5, 1000), 5, 1000, &cfg), None);
        assert_eq!(correct(anchor(5, 1000), 4, 1000, &cfg), None);
    }
}
