//! The receiver's configuration, validated once at `init`.

use std::fmt;

/// Largest allowed `period_ms`.
pub const MAX_PERIOD_MS: u64 = 60_000;
/// Largest allowed `max_pending`.
pub const MAX_PENDING_LIMIT: u64 = 1_024;

/// Validated configuration. Only [`Config::new`] can build one, so every
/// `Config` in the program satisfies the spec's ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    period_ms: u32,
    max_jitter_ms: u32,
    pair_window_ms: u32,
    max_pending: usize,
}

/// The raw numbers from an `init` command, before validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigInput {
    pub period_ms: u64,
    pub max_jitter_ms: u64,
    pub pair_window_ms: u64,
    pub max_pending: u64,
}

impl Config {
    /// Checks every parameter against the spec's range.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first parameter out of range.
    pub fn new(input: ConfigInput) -> Result<Self, ConfigError> {
        let period_ms = in_range("period_ms", input.period_ms, 1, MAX_PERIOD_MS)?;
        // period_ms >= 1 here, so period_ms - 1 can't underflow.
        let below_period = period_ms.saturating_sub(1);
        let max_jitter_ms = in_range("max_jitter_ms", input.max_jitter_ms, 0, below_period)?;
        let pair_window_ms = in_range("pair_window_ms", input.pair_window_ms, 0, below_period)?;
        let max_pending = in_range("max_pending", input.max_pending, 1, MAX_PENDING_LIMIT)?;
        Ok(Self {
            period_ms: narrow(period_ms)?,
            max_jitter_ms: narrow(max_jitter_ms)?,
            pair_window_ms: narrow(pair_window_ms)?,
            max_pending: usize::try_from(max_pending).map_err(|_| ConfigError::Internal)?,
        })
    }

    #[must_use]
    pub const fn period_ms(&self) -> u32 {
        self.period_ms
    }

    #[must_use]
    pub const fn max_jitter_ms(&self) -> u32 {
        self.max_jitter_ms
    }

    #[must_use]
    pub const fn pair_window_ms(&self) -> u32 {
        self.pair_window_ms
    }

    #[must_use]
    pub const fn max_pending(&self) -> usize {
        self.max_pending
    }
}

fn in_range(name: &'static str, value: u64, min: u64, max: u64) -> Result<u64, ConfigError> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::OutOfRange {
            name,
            value,
            min,
            max,
        })
    }
}

/// Narrows a value already known to be at most 60,000.
fn narrow(value: u64) -> Result<u32, ConfigError> {
    u32::try_from(value).map_err(|_| ConfigError::Internal)
}

/// Why an `init` configuration was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    OutOfRange {
        name: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },
    /// A conversion that the range checks make impossible failed.
    Internal,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange {
                name,
                value,
                min,
                max,
            } => write!(f, "{name} must be from {min} to {max}, got {value}"),
            Self::Internal => f.write_str("internal error while reading the configuration"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(period: u64, jitter: u64, window: u64, pending: u64) -> ConfigInput {
        ConfigInput {
            period_ms: period,
            max_jitter_ms: jitter,
            pair_window_ms: window,
            max_pending: pending,
        }
    }

    #[test]
    fn accepts_the_spec_example_and_every_boundary() {
        let config = Config::new(input(50, 5, 20, 4)).unwrap();
        assert_eq!(config.period_ms(), 50);
        assert_eq!(config.max_pending(), 4);
        Config::new(input(1, 0, 0, 1)).unwrap();
        Config::new(input(60_000, 59_999, 59_999, 1_024)).unwrap();
    }

    #[test]
    fn rejects_each_parameter_just_outside_its_range() {
        let cases = [
            (
                input(0, 0, 0, 1),
                "period_ms must be from 1 to 60000, got 0",
            ),
            (
                input(60_001, 0, 0, 1),
                "period_ms must be from 1 to 60000, got 60001",
            ),
            (
                input(50, 50, 0, 1),
                "max_jitter_ms must be from 0 to 49, got 50",
            ),
            (
                input(50, 0, 50, 1),
                "pair_window_ms must be from 0 to 49, got 50",
            ),
            (
                input(50, 0, 0, 0),
                "max_pending must be from 1 to 1024, got 0",
            ),
            (
                input(50, 0, 0, 1_025),
                "max_pending must be from 1 to 1024, got 1025",
            ),
            (
                input(u64::MAX, 0, 0, 1),
                "period_ms must be from 1 to 60000, got 18446744073709551615",
            ),
        ];
        for (bad, message) in cases {
            assert_eq!(Config::new(bad).unwrap_err().to_string(), message);
        }
    }
}
