//! Fixed-size history, so "what just happened?" has an answer.
//!
//! A one-shot sampler can only see stalls it is already watching. By the time
//! a desktop unfreezes enough to open a terminal and type a command, the event
//! is gone. The daemon keeps a bounded window of recent history so the question
//! can be asked *afterwards*, which is when people actually ask it.
//!
//! Memory is capped by construction: a fixed number of frames, each holding at
//! most [`crate::MAX_STALLS`] entries. A resident diagnostic that grows without
//! bound would be its own bug report.

use crate::{MAX_STALLS, MIN_REPORTABLE_PCT, Report, Stall};
use std::collections::{HashMap, VecDeque};

/// One sampling tick.
#[derive(Clone, Debug)]
pub struct Frame {
    /// Wall-clock seconds since the epoch, for `--since` arithmetic.
    pub at_unix: u64,
    /// Measured length of this tick.
    pub window_usec: u64,
    pub stalls: Vec<Stall>,
}

/// Bounded ring of recent frames.
pub struct Ring {
    frames: VecDeque<Frame>,
    capacity: usize,
}

impl Ring {
    pub fn new(capacity: usize) -> Self {
        Self {
            frames: VecDeque::with_capacity(capacity.max(1)),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&mut self, frame: Frame) {
        if self.frames.len() == self.capacity {
            self.frames.pop_front();
        }
        self.frames.push_back(frame);
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn newest(&self) -> Option<&Frame> {
        self.frames.back()
    }

    /// Wall-clock span currently held, in seconds.
    pub fn span_secs(&self) -> u64 {
        match (self.frames.front(), self.frames.back()) {
            (Some(f), Some(b)) => b.at_unix.saturating_sub(f.at_unix),
            _ => 0,
        }
    }

    /// Aggregate every frame at or after `since_unix` into one report.
    ///
    /// Stalls are summed per (cgroup, resource, kind) and the percentage is
    /// computed against the total observed window — but `peak_pct` carries the
    /// worst individual tick, because the sum alone hides short freezes. See
    /// [`Stall::peak_pct`].
    ///
    /// Note the window is the sum of frame windows actually held, not the
    /// requested span: the daemon samples periodically rather than
    /// continuously, so claiming coverage we do not have would overstate
    /// percentages.
    pub fn aggregate(&self, since_unix: u64) -> Report {
        let mut total_window = 0u64;
        // (cgroup, resource, kind) -> (unit, summed usec, peak pct)
        let mut acc: HashMap<(String, crate::Resource, crate::PsiKind), (String, u64, f64)> =
            HashMap::new();

        for f in self.frames.iter().filter(|f| f.at_unix >= since_unix) {
            total_window += f.window_usec;
            for s in &f.stalls {
                let e = acc
                    .entry((s.cgroup.clone(), s.resource, s.kind))
                    .or_insert_with(|| (s.unit.clone(), 0, 0.0));
                e.1 += s.delta_usec;
                if s.pressure_pct > e.2 {
                    e.2 = s.pressure_pct;
                }
            }
        }

        if total_window == 0 {
            return Report::default();
        }

        let mut stalls: Vec<Stall> = acc
            .into_iter()
            .map(|((cgroup, resource, kind), (unit, usec, peak))| Stall {
                unit,
                cgroup,
                resource,
                kind,
                delta_usec: usec,
                pressure_pct: usec as f64 / total_window as f64 * 100.0,
                peak_pct: peak,
            })
            // Filter on the PEAK, not the average: a unit that froze the
            // machine for one hard second inside a long window is exactly what
            // "what just happened" is asking about, and its average is tiny.
            .filter(|s| s.peak_pct >= MIN_REPORTABLE_PCT)
            .collect();

        // Rank by peak, not by average. Someone asking "what just happened"
        // wants the thing that froze the machine hardest, not the thing with
        // the highest steady-state background cost.
        stalls.sort_by(|a, b| {
            b.peak_pct
                .partial_cmp(&a.peak_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        stalls.truncate(MAX_STALLS);

        Report {
            window_usec: total_window,
            stalls,
            // History aggregates pressure across frames; byte deltas are not
            // retained per frame, so an aggregated report carries no causes
            // rather than a fabricated total.
            causes: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PsiKind, Resource};

    fn stall(unit: &str, usec: u64, pct: f64) -> Stall {
        Stall {
            unit: unit.into(),
            cgroup: format!("/sys/fs/cgroup/{unit}"),
            resource: Resource::Io,
            kind: PsiKind::Full,
            delta_usec: usec,
            pressure_pct: pct,
            peak_pct: pct,
        }
    }

    fn frame(at: u64, stalls: Vec<Stall>) -> Frame {
        Frame {
            at_unix: at,
            window_usec: 1_000_000,
            stalls,
        }
    }

    #[test]
    fn evicts_oldest_beyond_capacity() {
        let mut r = Ring::new(3);
        for i in 0..5 {
            r.push(frame(i, vec![]));
        }
        assert_eq!(r.len(), 3);
        assert_eq!(r.newest().unwrap().at_unix, 4);
        assert_eq!(r.span_secs(), 2); // frames 2,3,4
    }

    #[test]
    fn capacity_is_never_zero() {
        let mut r = Ring::new(0);
        r.push(frame(1, vec![]));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn aggregate_sums_usec_across_frames() {
        let mut r = Ring::new(10);
        r.push(frame(100, vec![stall("a", 100_000, 10.0)]));
        r.push(frame(101, vec![stall("a", 300_000, 30.0)]));
        let rep = r.aggregate(0);
        assert_eq!(rep.window_usec, 2_000_000);
        assert_eq!(rep.stalls.len(), 1);
        assert_eq!(rep.stalls[0].delta_usec, 400_000);
        assert!((rep.stalls[0].pressure_pct - 20.0).abs() < 0.01);
    }

    #[test]
    fn peak_survives_averaging() {
        // The whole reason peak_pct exists: one catastrophic tick inside an
        // otherwise quiet minute must not be averaged into invisibility.
        let mut r = Ring::new(64);
        r.push(frame(100, vec![stall("x", 940_000, 94.0)]));
        for i in 1..60 {
            r.push(frame(100 + i, vec![]));
        }
        let rep = r.aggregate(0);
        assert!(
            rep.stalls[0].pressure_pct < 2.0,
            "average should look small"
        );
        assert!(
            (rep.stalls[0].peak_pct - 94.0).abs() < 0.01,
            "peak must survive"
        );
    }

    #[test]
    fn ranks_by_peak_not_average() {
        let mut r = Ring::new(10);
        // "steady" has a higher total; "spike" froze the machine harder once.
        r.push(frame(
            1,
            vec![
                stall("steady", 200_000, 20.0),
                stall("spike", 900_000, 90.0),
            ],
        ));
        r.push(frame(2, vec![stall("steady", 200_000, 20.0)]));
        r.push(frame(3, vec![stall("steady", 200_000, 20.0)]));
        r.push(frame(4, vec![stall("steady", 200_000, 20.0)]));
        r.push(frame(5, vec![stall("steady", 200_000, 20.0)]));
        let rep = r.aggregate(0);
        assert_eq!(rep.stalls[0].unit, "spike");
    }

    #[test]
    fn noise_is_filtered_on_peak_not_average() {
        let mut r = Ring::new(128);
        // A brief hard freeze must survive; a permanently trivial unit must not.
        r.push(frame(
            1,
            vec![stall("spike", 900_000, 90.0), stall("noise", 3_000, 0.3)],
        ));
        for i in 2..100 {
            r.push(frame(i, vec![stall("noise", 3_000, 0.3)]));
        }
        let rep = r.aggregate(0);
        let units: Vec<&str> = rep.stalls.iter().map(|s| s.unit.as_str()).collect();
        assert!(
            units.contains(&"spike"),
            "brief freeze must survive: {units:?}"
        );
        assert!(
            !units.contains(&"noise"),
            "sub-threshold noise must be dropped: {units:?}"
        );
    }

    #[test]
    fn since_filters_older_frames() {
        let mut r = Ring::new(10);
        r.push(frame(100, vec![stall("old", 500_000, 50.0)]));
        r.push(frame(200, vec![stall("new", 100_000, 10.0)]));
        let rep = r.aggregate(150);
        assert_eq!(rep.window_usec, 1_000_000);
        assert_eq!(rep.stalls.len(), 1);
        assert_eq!(rep.stalls[0].unit, "new");
    }

    #[test]
    fn empty_window_yields_empty_report() {
        let r = Ring::new(4);
        let rep = r.aggregate(0);
        assert_eq!(rep.window_usec, 0);
        assert!(rep.stalls.is_empty());
    }

    #[test]
    fn same_unit_different_resources_stay_separate() {
        let mut r = Ring::new(4);
        let mut cpu = stall("a", 100_000, 10.0);
        cpu.resource = Resource::Cpu;
        cpu.kind = PsiKind::Some;
        r.push(frame(1, vec![stall("a", 100_000, 10.0), cpu]));
        assert_eq!(r.aggregate(0).stalls.len(), 2);
    }
}
