//! Replay protection that survives a restart, within the storage write budget.
//!
//! In memory, the receiver rejects any seq at or below the last accepted one.
//! A restart loses that, so each camera also has a *floor* in storage: an upper
//! bound on every seq the camera has had accepted.
//!
//! - Before accepting a seq `s` above the saved floor, the receiver saves a new
//!   floor `s + persist_interval`. A floor is always saved before the frame it
//!   covers is accepted, so a power cut can't leave an accepted seq uncovered.
//! - After a restart, frames at or below the loaded floor are rejected. Every
//!   seq accepted before the restart is at or below it, so no replay gets in.
//! - The loaded floor is at most `S + persist_interval`, where `S` is the
//!   highest seq accepted before the restart, so every frame above that is
//!   accepted, as the spec requires.
//! - A frame rejected only by the loaded floor would have been accepted
//!   without the restart. If it is otherwise valid, it still moves its camera
//!   to its key, so a key rotation isn't lost under the floor (see
//!   `Decision::BelowRestartFloor` in the receiver).
//! - Each save after the first needs a seq above the previous floor, so the
//!   accepted seqs have grown by more than `persist_interval` since the last
//!   save. That keeps the number of saves within the spec's budget of
//!   `1 + (S_max - S_min) / persist_interval`.
//!
//! Floors are `u64`: a seq plus an interval, both at most `u32::MAX`, always
//! fits, so the sum is exact.

/// One camera's floors.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayFloor {
    /// The floor last saved to storage. Every accepted seq is at or below it.
    saved: Option<u64>,
    /// The floor loaded at the last restart. A frame at or below it may have
    /// been accepted before the restart, so it is rejected.
    loaded: Option<u64>,
}

impl ReplayFloor {
    /// The floors after a restart, from the floor found in storage.
    #[must_use]
    pub const fn restored(saved: Option<u64>) -> Self {
        Self {
            saved,
            loaded: saved,
        }
    }

    /// Whether `seq` is above the floor loaded at the last restart.
    #[must_use]
    pub fn admits(&self, seq: u32) -> bool {
        self.loaded.is_none_or(|floor| u64::from(seq) > floor)
    }

    /// The floor to save before accepting `seq`, or `None` if the saved floor
    /// already covers it.
    #[must_use]
    pub fn to_save(&self, seq: u32, persist_interval: u32) -> Option<u64> {
        let seq = u64::from(seq);
        if self.saved.is_some_and(|floor| seq <= floor) {
            return None;
        }
        // Can't saturate: both terms are at most u32::MAX.
        Some(seq.saturating_add(u64::from(persist_interval)))
    }

    /// Records that `floor` was saved.
    pub const fn saved_as(&mut self, floor: u64) {
        self.saved = Some(floor);
    }

    /// The floor last saved, if any.
    #[must_use]
    pub const fn saved(&self) -> Option<u64> {
        self.saved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts `seq` the way the receiver does: save first if needed.
    fn accept(floor: &mut ReplayFloor, seq: u32, interval: u32, saves: &mut u32) {
        assert!(floor.admits(seq));
        if let Some(new) = floor.to_save(seq, interval) {
            floor.saved_as(new);
            *saves += 1;
        }
    }

    #[test]
    fn saves_only_when_a_seq_passes_the_floor() {
        let mut floor = ReplayFloor::default();
        assert_eq!(floor.to_save(5, 100), Some(105));
        floor.saved_as(105);
        assert_eq!(floor.to_save(6, 100), None);
        assert_eq!(floor.to_save(105, 100), None);
        assert_eq!(floor.to_save(106, 100), Some(206));
        assert_eq!(floor.saved(), Some(105));
    }

    #[test]
    fn nothing_is_rejected_before_a_restart() {
        let floor = ReplayFloor::default();
        assert!(floor.admits(0));
        let mut floor = floor;
        floor.saved_as(105);
        assert!(floor.admits(0), "the in-memory last seq handles replays");
    }

    #[test]
    fn after_a_restart_seqs_up_to_the_floor_are_rejected() {
        let floor = ReplayFloor::restored(Some(106));
        assert!(!floor.admits(0));
        assert!(!floor.admits(6));
        assert!(!floor.admits(106));
        assert!(floor.admits(107));
        // The saved floor carries over, so the first accepted frame saves again.
        assert_eq!(floor.to_save(107, 100), Some(207));
        // A camera with nothing saved accepts anything.
        assert!(ReplayFloor::restored(None).admits(0));
    }

    #[test]
    fn floors_are_exact_at_the_extremes() {
        let floor = ReplayFloor::default();
        assert_eq!(
            floor.to_save(u32::MAX, u32::MAX),
            Some(2 * u64::from(u32::MAX))
        );
        // With the largest interval, one save covers every possible seq.
        let mut floor = floor;
        floor.saved_as(u64::from(u32::MAX));
        assert_eq!(floor.to_save(u32::MAX, 1), None);
        assert!(!ReplayFloor::restored(Some(u64::from(u32::MAX))).admits(u32::MAX));
    }

    #[test]
    fn saves_stay_within_the_spec_budget() {
        for interval in [1, 2, 3, 7, 100] {
            for step in [1, 2, 3, 5, 99, 100, 101, 250] {
                let mut floor = ReplayFloor::default();
                let mut saves = 0;
                let first = 3;
                let mut seq = first;
                for _ in 0..200 {
                    accept(&mut floor, seq, interval, &mut saves);
                    seq += step;
                }
                let last = seq - step;
                let budget = 1 + (last - first) / interval;
                assert!(
                    saves <= budget,
                    "interval {interval}, step {step}: {saves} saves, budget {budget}"
                );
            }
        }
    }
}
