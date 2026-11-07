//! Pairing frames from the two cameras into one synchronized stream.
//!
//! Each camera has a queue of accepted frames waiting for a partner. When a
//! frame is accepted it joins the end of its camera's queue, and then (spec):
//!
//! 1. While both queues are non-empty, compare the oldest frame in each. If
//!    their timestamps differ by at most `pair_window_ms`, remove both and emit
//!    a pair stamped with the floor of their average. Otherwise remove the older
//!    one and emit it unpaired.
//! 2. If a queue now holds more than `max_pending` frames, remove its oldest and
//!    emit it unpaired.
//!
//! The work is split in two so the receiver can check everything before
//! changing anything: [`Queues::plan`] computes the outcome without touching
//! the queues (and is where every fallible calculation happens), and
//! [`Queues::apply`] carries it out with steps that can't fail.

use std::collections::VecDeque;

use serde::Serialize;

use crate::camera::{Camera, PerCamera};
use crate::config::Config;
use crate::key::KeyId;
use crate::timeline::Millis;

/// An accepted frame waiting for a partner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub seq: u32,
    pub timestamp: Millis,
    /// The key that authenticated the frame, so revoking it can drop the frame.
    pub key_id: KeyId,
}

/// One record of the synchronized stream: a pair, or a frame that can never be
/// paired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SyncRecord {
    pub timestamp: Millis,
    pub cam1: Option<u32>,
    pub cam2: Option<u32>,
}

impl SyncRecord {
    fn unpaired(camera: Camera, frame: Pending) -> Self {
        let seq = Some(frame.seq);
        match camera {
            Camera::Cam1 => Self {
                timestamp: frame.timestamp,
                cam1: seq,
                cam2: None,
            },
            Camera::Cam2 => Self {
                timestamp: frame.timestamp,
                cam1: None,
                cam2: seq,
            },
        }
    }
}

/// The outcome of adding one frame, computed without changing the queues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncPlan {
    camera: Camera,
    frame: Pending,
    /// How many frames leave the front of each queue (existing frames only).
    removed: PerCamera<usize>,
    /// Whether the new frame stays queued (it may be paired or dropped at once).
    keep_new: bool,
    records: Vec<SyncRecord>,
}

impl SyncPlan {
    /// The records this frame produces, in order.
    #[must_use]
    pub fn records(&self) -> &[SyncRecord] {
        &self.records
    }
}

/// The two queues of frames waiting for a partner.
#[derive(Clone, Debug)]
pub struct Queues {
    queues: PerCamera<VecDeque<Pending>>,
}

impl Queues {
    /// Empty queues with room for `max_pending + 1` frames each, so applying a
    /// plan never needs to allocate.
    #[must_use]
    pub fn new(max_pending: usize) -> Self {
        let capacity = max_pending.saturating_add(1);
        Self {
            queues: PerCamera::from_fn(|_| VecDeque::with_capacity(capacity)),
        }
    }

    /// The seqs waiting in `camera`'s queue, oldest first.
    pub fn pending_seqs(&self, camera: Camera) -> impl Iterator<Item = u32> + '_ {
        self.queues.get(camera).iter().map(|frame| frame.seq)
    }

    /// Works out what adding `frame` to `camera`'s queue produces, without
    /// changing anything.
    ///
    /// Returns `None` only if a calculation would overflow, which 128-bit
    /// timestamps make impossible for real inputs.
    #[must_use]
    pub fn plan(&self, camera: Camera, frame: Pending, config: &Config) -> Option<SyncPlan> {
        let own = self.queues.get(camera);
        let other = self.queues.get(camera.other());
        // The camera's queue as it would be with the new frame on the end.
        let own_at = |i: usize| -> Option<Pending> {
            match i.cmp(&own.len()) {
                std::cmp::Ordering::Less => own.get(i).copied(),
                std::cmp::Ordering::Equal => Some(frame),
                std::cmp::Ordering::Greater => None,
            }
        };
        let own_len = own.len().checked_add(1)?;
        let window = u128::from(config.pair_window_ms());
        let mut records = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);

        // Step 1.
        while let (Some(mine), Some(theirs)) = (own_at(i), other.get(j).copied()) {
            let difference = mine.timestamp.checked_sub(theirs.timestamp)?.unsigned_abs();
            if difference <= window {
                let average = mine.timestamp.checked_add(theirs.timestamp)?.div_euclid(2);
                let (cam1, cam2) = match camera {
                    Camera::Cam1 => (mine.seq, theirs.seq),
                    Camera::Cam2 => (theirs.seq, mine.seq),
                };
                records.push(SyncRecord {
                    timestamp: average,
                    cam1: Some(cam1),
                    cam2: Some(cam2),
                });
                i = i.checked_add(1)?;
                j = j.checked_add(1)?;
            } else if mine.timestamp < theirs.timestamp {
                records.push(SyncRecord::unpaired(camera, mine));
                i = i.checked_add(1)?;
            } else {
                records.push(SyncRecord::unpaired(camera.other(), theirs));
                j = j.checked_add(1)?;
            }
        }

        // Step 2. Only the camera's own queue grew, so only it can be over.
        if own_len.checked_sub(i)? > config.max_pending() {
            records.push(SyncRecord::unpaired(camera, own_at(i)?));
            i = i.checked_add(1)?;
        }

        let removed_own = i.min(own.len());
        let removed = match camera {
            Camera::Cam1 => PerCamera::new(removed_own, j),
            Camera::Cam2 => PerCamera::new(j, removed_own),
        };
        Some(SyncPlan {
            camera,
            frame,
            removed,
            keep_new: i <= own.len(),
            records,
        })
    }

    /// Removes `camera`'s waiting frames that were authenticated with `key_id`,
    /// without emitting them. Used when that key is revoked: the frames might
    /// have been forged with it and haven't been paired yet. Can't fail.
    pub fn drop_key(&mut self, camera: Camera, key_id: KeyId) {
        self.queues
            .get_mut(camera)
            .retain(|frame| frame.key_id != key_id);
    }

    /// Carries out a plan made by [`Queues::plan`] on these same queues.
    ///
    /// Only removes from the front and pushes onto space reserved in
    /// [`Queues::new`]: nothing here can fail or allocate.
    pub fn apply(&mut self, plan: &SyncPlan) {
        for camera in Camera::ALL {
            let queue = self.queues.get_mut(camera);
            let count = (*plan.removed.get(camera)).min(queue.len());
            queue.drain(..count);
        }
        if plan.keep_new {
            self.queues.get_mut(plan.camera).push_back(plan.frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigInput;

    fn config(window: u64, max_pending: u64) -> Config {
        Config::new(ConfigInput {
            period_ms: 50,
            max_jitter_ms: 5,
            pair_window_ms: window,
            max_pending,
        })
        .unwrap()
    }

    fn frame(seq: u32, timestamp: Millis) -> Pending {
        Pending {
            seq,
            timestamp,
            key_id: KeyId(0),
        }
    }

    /// Plans and applies, returning the records.
    fn add(queues: &mut Queues, camera: Camera, f: Pending, cfg: &Config) -> Vec<SyncRecord> {
        let plan = queues.plan(camera, f, cfg).unwrap();
        queues.apply(&plan);
        plan.records
    }

    fn pending(queues: &Queues, camera: Camera) -> Vec<u32> {
        queues.pending_seqs(camera).collect()
    }

    fn pair(timestamp: Millis, cam1: u32, cam2: u32) -> SyncRecord {
        SyncRecord {
            timestamp,
            cam1: Some(cam1),
            cam2: Some(cam2),
        }
    }

    #[test]
    fn spec_example_sequence() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        assert!(add(&mut q, Camera::Cam1, frame(1, 1000), &cfg).is_empty());
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(1, 1005), &cfg),
            vec![pair(1002, 1, 1)]
        );
        assert!(add(&mut q, Camera::Cam1, frame(2, 1050), &cfg).is_empty());
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(2, 1055), &cfg),
            vec![pair(1052, 2, 2)]
        );
        assert!(add(&mut q, Camera::Cam1, frame(4, 1150), &cfg).is_empty());
        // cam2 frame 3 is 46 ms older than cam1 frame 4: emitted unpaired.
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(3, 1104), &cfg),
            vec![SyncRecord {
                timestamp: 1104,
                cam1: None,
                cam2: Some(3)
            }]
        );
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(4, 1155), &cfg),
            vec![pair(1152, 4, 4)]
        );
        assert!(pending(&q, Camera::Cam1).is_empty());
        assert!(pending(&q, Camera::Cam2).is_empty());
    }

    #[test]
    fn window_boundary_is_inclusive() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        add(&mut q, Camera::Cam1, frame(1, 1000), &cfg);
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(1, 1020), &cfg),
            vec![pair(1010, 1, 1)]
        );
        add(&mut q, Camera::Cam1, frame(2, 2000), &cfg);
        let records = add(&mut q, Camera::Cam2, frame(2, 2021), &cfg);
        assert_eq!(
            records,
            vec![SyncRecord {
                timestamp: 2000,
                cam1: Some(2),
                cam2: None
            }]
        );
        assert_eq!(pending(&q, Camera::Cam2), vec![2]);
    }

    #[test]
    fn pair_timestamp_is_the_floor_of_the_average() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        add(&mut q, Camera::Cam1, frame(1, 1000), &cfg);
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(1, 1001), &cfg),
            vec![pair(1000, 1, 1)]
        );
    }

    #[test]
    fn overflow_emits_the_oldest_unpaired() {
        let cfg = config(20, 2);
        let mut q = Queues::new(2);
        add(&mut q, Camera::Cam1, frame(1, 1000), &cfg);
        add(&mut q, Camera::Cam1, frame(2, 1050), &cfg);
        assert_eq!(
            add(&mut q, Camera::Cam1, frame(3, 1100), &cfg),
            vec![SyncRecord {
                timestamp: 1000,
                cam1: Some(1),
                cam2: None
            }]
        );
        assert_eq!(pending(&q, Camera::Cam1), vec![2, 3]);
    }

    #[test]
    fn a_new_frame_older_than_the_other_queue_is_emitted_at_once() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        add(&mut q, Camera::Cam2, frame(1, 5000), &cfg);
        let records = add(&mut q, Camera::Cam1, frame(1, 1000), &cfg);
        assert_eq!(
            records,
            vec![SyncRecord {
                timestamp: 1000,
                cam1: Some(1),
                cam2: None
            }]
        );
        assert!(pending(&q, Camera::Cam1).is_empty());
        assert_eq!(pending(&q, Camera::Cam2), vec![1]);
    }

    #[test]
    fn several_records_from_one_frame_come_out_in_order() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        for (seq, ts) in [(1, 1000), (2, 1050), (3, 1100)] {
            add(&mut q, Camera::Cam1, frame(seq, ts), &cfg);
        }
        // cam2 at 1105: cam1 1000 and 1050 are older and can't pair; 1100 pairs.
        let records = add(&mut q, Camera::Cam2, frame(1, 1105), &cfg);
        assert_eq!(
            records,
            vec![
                SyncRecord {
                    timestamp: 1000,
                    cam1: Some(1),
                    cam2: None
                },
                SyncRecord {
                    timestamp: 1050,
                    cam1: Some(2),
                    cam2: None
                },
                pair(1102, 3, 1),
            ]
        );
    }

    #[test]
    fn dropping_a_key_removes_only_its_frames() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        let keyed = |seq, timestamp, key| Pending {
            seq,
            timestamp,
            key_id: KeyId(key),
        };
        add(&mut q, Camera::Cam1, keyed(1, 1000, 0), &cfg);
        add(&mut q, Camera::Cam1, keyed(2, 1050, 1), &cfg);
        add(&mut q, Camera::Cam1, keyed(3, 1100, 0), &cfg);
        // Same key id on the other camera is a different key: untouched.
        q.drop_key(Camera::Cam2, KeyId(0));
        assert_eq!(pending(&q, Camera::Cam1), vec![1, 2, 3]);
        q.drop_key(Camera::Cam1, KeyId(0));
        assert_eq!(pending(&q, Camera::Cam1), vec![2]);
    }

    #[test]
    fn plan_changes_nothing_until_applied() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        add(&mut q, Camera::Cam1, frame(1, 1000), &cfg);
        let plan = q.plan(Camera::Cam2, frame(1, 1005), &cfg).unwrap();
        assert_eq!(pending(&q, Camera::Cam1), vec![1]);
        q.apply(&plan);
        assert!(pending(&q, Camera::Cam1).is_empty());
    }

    #[test]
    fn extreme_timestamps_pair_without_overflow() {
        let cfg = config(20, 4);
        let mut q = Queues::new(4);
        let big = Millis::from(i64::MAX) + Millis::from(u32::MAX) * 60_000;
        add(&mut q, Camera::Cam1, frame(1, big), &cfg);
        assert_eq!(
            add(&mut q, Camera::Cam2, frame(1, big - 1), &cfg),
            vec![pair(big - 1, 1, 1)]
        );
    }
}
