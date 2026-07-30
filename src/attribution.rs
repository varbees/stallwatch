//! Deciding which cgroup is *responsible* for a stall.
//!
//! This is the part that makes the tool useful rather than merely informative.
//! Reading PSI is easy and several tools do it. Saying which unit to blame is
//! the work, because the kernel's accounting is hierarchical: a stall inside
//! `firefox.scope` is also counted against `app.slice`, `user@1000.service`,
//! `user-1000.slice`, `user.slice` and the root. Report those naively and the
//! answer is always "user.slice", which tells nobody anything.

use crate::cgroup;
use crate::psi::Resource;
use crate::psi::Snapshot;
use crate::{MAX_STALLS, MIN_REPORTABLE_PCT, Stall};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Share of a parent's stall a single child must own before the parent stops
/// being considered responsible.
///
/// Tuning: too low and deep leaves get blamed for pressure that is genuinely
/// spread across siblings; too high and parents hog the report. 80% means "one
/// child clearly dominates" while leaving a parent responsible when its stall
/// is the diffuse sum of many children — which is itself a real and useful
/// finding ("everything under app.slice is thrashing", not one app).
const CHILD_DOMINANCE: u64 = 80;

/// Precomputed "worst descendant" per cgroup.
///
/// The obvious implementation of the dominance rule — for each cgroup, scan
/// every other cgroup looking for descendants — is O(n^2), and cgroup paths
/// are compared component-wise so each probe is itself proportional to depth.
/// Measured at 152 cgroups it was already 60% of a tick; projected to a
/// 2,000-cgroup Kubernetes node it is ~800ms per tick, and ~5s at 5,000. The
/// duty-cycle pacing would have absorbed that by stretching the interval to
/// tens of seconds, which is safe and useless.
///
/// The tree makes it unnecessary. Sorting paths puts every descendant after
/// its ancestor, so one reverse pass propagates each subtree's maximum up to
/// its nearest present ancestor. Deepest-first means a node's own maximum is
/// already complete when it propagates. O(n log n) for the sort plus
/// O(n * depth) for the walk.
pub struct Responsibility {
    /// Largest delta anywhere strictly below each cgroup.
    max_descendant: HashMap<PathBuf, u64>,
}

impl Responsibility {
    pub fn new(deltas: &HashMap<PathBuf, u64>) -> Self {
        let mut paths: Vec<&PathBuf> = deltas.keys().collect();
        paths.sort_unstable();

        let mut max_descendant: HashMap<PathBuf, u64> =
            deltas.keys().map(|p| (p.clone(), 0u64)).collect();

        // Deepest-first: when a node propagates, its own subtree maximum is
        // already final, so a single hop to the nearest present ancestor is
        // sufficient — that ancestor propagates further when its turn comes.
        for path in paths.into_iter().rev() {
            let own = deltas.get(path).copied().unwrap_or(0);
            let subtree = own.max(max_descendant.get(path).copied().unwrap_or(0));

            let mut ancestor = path.parent();
            while let Some(a) = ancestor {
                if let Some(slot) = max_descendant.get_mut(a) {
                    if subtree > *slot {
                        *slot = subtree;
                    }
                    break;
                }
                ancestor = a.parent();
            }
        }

        Self { max_descendant }
    }

    /// Is this cgroup the one to blame, or is a child responsible?
    ///
    /// Responsible when no single descendant accounts for
    /// [`CHILD_DOMINANCE`] percent or more of its stall.
    pub fn is_responsible(&self, cg: &Path, delta: u64) -> bool {
        if delta == 0 {
            return false;
        }
        let worst_child = self.max_descendant.get(cg).copied().unwrap_or(0);
        worst_child * 100 < delta * CHILD_DOMINANCE
    }
}

/// Reference implementation of the dominance rule, kept for differential
/// testing against [`Responsibility`]. Quadratic; not used in the hot path.
#[cfg(test)]
fn is_responsible_naive(cg: &Path, delta: u64, deltas: &HashMap<PathBuf, u64>) -> bool {
    if delta == 0 {
        return false;
    }
    for (other, &d) in deltas {
        if other != cg && other.starts_with(cg) && d * 100 >= delta * CHILD_DOMINANCE {
            return false;
        }
    }
    true
}

/// Sample twice over `window` and return the responsible stalls, worst first.
///
/// Returns the measured window length alongside, because sampling thousands of
/// cgroups takes real time and percentages computed against the *requested*
/// duration would be quietly wrong.
pub fn collect(window: Duration) -> (Vec<Stall>, u64) {
    let cgroups = cgroup::all();

    let t0 = Instant::now();
    let first = cgroup::sample(&cgroups);
    std::thread::sleep(window);
    let second = cgroup::sample(&cgroups);
    let elapsed_us = t0.elapsed().as_micros() as u64;
    if elapsed_us == 0 {
        return (Vec::new(), 0);
    }

    let mut stalls = Vec::new();

    for res in Resource::ALL {
        let kind = res.primary_kind();

        let mut deltas: HashMap<PathBuf, u64> = HashMap::new();
        for (cg, after) in &second {
            // Absent from the first sample means the cgroup appeared mid-window;
            // its counter starts from an unknown base, so skip it entirely
            // rather than report a fabricated delta.
            let Some(before) = first.get(cg) else {
                continue;
            };
            let b = before.get(res).total_for(kind);
            let a = after.get(res).total_for(kind);
            // Saturating: counters restart when a cgroup is destroyed and its
            // path reused, which would otherwise underflow.
            deltas.insert(cg.clone(), a.saturating_sub(b));
        }

        let responsibility = Responsibility::new(&deltas);
        for (cg, &d) in &deltas {
            let pct = d as f64 / elapsed_us as f64 * 100.0;
            if pct < MIN_REPORTABLE_PCT || !responsibility.is_responsible(cg, d) {
                continue;
            }
            stalls.push(Stall {
                unit: cgroup::friendly_name(cg),
                cgroup: cg.to_string_lossy().into_owned(),
                resource: res,
                kind,
                delta_usec: d,
                pressure_pct: pct,
                // Single tick: the window IS the peak.
                peak_pct: pct,
            });
        }
    }

    stalls.sort_by(|a, b| {
        b.pressure_pct
            .partial_cmp(&a.pressure_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    stalls.truncate(MAX_STALLS);
    (stalls, elapsed_us)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, u64)]) -> HashMap<PathBuf, u64> {
        pairs.iter().map(|(p, d)| (PathBuf::from(p), *d)).collect()
    }

    #[test]
    fn parent_yields_to_dominant_child() {
        let d = m(&[
            ("/sys/fs/cgroup/user.slice", 1000),
            ("/sys/fs/cgroup/user.slice/app.slice", 900),
        ]);
        assert!(!is_responsible_naive(
            Path::new("/sys/fs/cgroup/user.slice"),
            1000,
            &d
        ));
        assert!(is_responsible_naive(
            Path::new("/sys/fs/cgroup/user.slice/app.slice"),
            900,
            &d
        ));
        // The fast path must agree with the reference.
        let r = Responsibility::new(&d);
        assert!(!r.is_responsible(Path::new("/sys/fs/cgroup/user.slice"), 1000));
        assert!(r.is_responsible(Path::new("/sys/fs/cgroup/user.slice/app.slice"), 900));
    }

    #[test]
    fn parent_keeps_blame_when_children_are_diffuse() {
        // No single child dominates: "everything here is stalling" is the
        // correct and useful answer.
        let d = m(&[
            ("/sys/fs/cgroup/user.slice", 1000),
            ("/sys/fs/cgroup/user.slice/a.scope", 500),
            ("/sys/fs/cgroup/user.slice/b.scope", 500),
        ]);
        assert!(is_responsible_naive(
            Path::new("/sys/fs/cgroup/user.slice"),
            1000,
            &d
        ));
    }

    #[test]
    fn zero_delta_is_never_responsible() {
        assert!(!is_responsible_naive(Path::new("/x"), 0, &m(&[])));
    }

    #[test]
    fn exactly_at_dominance_threshold_yields() {
        let d = m(&[("/p", 1000), ("/p/c", 800)]);
        assert!(!is_responsible_naive(Path::new("/p"), 1000, &d));
    }

    #[test]
    fn just_under_threshold_keeps_blame() {
        let d = m(&[("/p", 1000), ("/p/c", 799)]);
        assert!(is_responsible_naive(Path::new("/p"), 1000, &d));
    }

    #[test]
    fn sibling_prefix_is_not_treated_as_a_child() {
        // "/p2" starts_with "/p" as a string but is not a descendant path.
        // PathBuf::starts_with compares components, which is why this holds —
        // guard it with a test so nobody "optimises" it into a string compare.
        let d = m(&[("/p", 1000), ("/p2", 900)]);
        assert!(is_responsible_naive(Path::new("/p"), 1000, &d));
    }
}

/// Continuous sampler that retains the previous snapshot.
///
/// [`collect`] takes two sweeps of the cgroup tree per call — sample, sleep,
/// sample — which is correct for a one-shot CLI invocation and wasteful for a
/// resident daemon, because the closing sweep of one tick is the opening sweep
/// of the next.
///
/// Measured on a 152-cgroup desktop a sweep costs ~10ms, so a 1Hz daemon spent
/// ~2% of a core on redundant reads. Extrapolated to a 2,000-cgroup Kubernetes
/// node that is ~26% of a core — a tool that exists to observe contention
/// would have become a meaningful source of it. Retaining state halves that,
/// and [`Sampler::recommended_interval`] handles the rest.
pub struct Sampler {
    prev: HashMap<PathBuf, Snapshot>,
    prev_at: Instant,
    last_sweep: Duration,
}

impl Sampler {
    /// Takes the opening snapshot immediately, so the first `tick` has a base.
    pub fn new() -> Self {
        let t = Instant::now();
        let prev = cgroup::sample(&cgroup::all());
        Self {
            prev,
            prev_at: t,
            last_sweep: t.elapsed(),
        }
    }

    /// Cost of the most recent sweep. Exposed so callers can pace themselves.
    pub fn last_sweep(&self) -> Duration {
        self.last_sweep
    }

    /// Sleep interval that keeps sampling under `duty` of one core.
    ///
    /// A fixed tick is wrong across three orders of magnitude of cgroup count.
    /// Rather than make operators discover that, the daemon paces itself to a
    /// duty-cycle budget and reports the interval it chose.
    pub fn recommended_interval(&self, duty: f64, floor: Duration, ceil: Duration) -> Duration {
        let sweep = self.last_sweep.as_secs_f64().max(0.000_1);
        Duration::from_secs_f64(
            (sweep / duty.clamp(0.001, 1.0)).clamp(floor.as_secs_f64(), ceil.as_secs_f64()),
        )
    }

    /// One sweep, diffed against the previous one.
    ///
    /// The window is the real elapsed time since the last sweep, not a
    /// configured tick: a daemon that is descheduled or paced adaptively would
    /// otherwise compute percentages against a duration that never happened.
    pub fn tick(&mut self) -> (Vec<Stall>, u64) {
        let started = Instant::now();
        let now = cgroup::sample(&cgroup::all());
        self.last_sweep = started.elapsed();

        let elapsed_us = self.prev_at.elapsed().as_micros() as u64;
        let stalls = if elapsed_us == 0 {
            Vec::new()
        } else {
            diff(&self.prev, &now, elapsed_us)
        };

        self.prev = now;
        self.prev_at = Instant::now();
        (stalls, elapsed_us)
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared diff logic between [`collect`] and [`Sampler::tick`].
fn diff(
    first: &HashMap<PathBuf, Snapshot>,
    second: &HashMap<PathBuf, Snapshot>,
    elapsed_us: u64,
) -> Vec<Stall> {
    let mut stalls = Vec::new();

    for res in Resource::ALL {
        let kind = res.primary_kind();
        let mut deltas: HashMap<PathBuf, u64> = HashMap::new();
        for (cg, after) in second {
            // Absent from the first sample means the cgroup appeared mid-window;
            // its counter starts from an unknown base, so skip it rather than
            // report a fabricated delta.
            let Some(before) = first.get(cg) else {
                continue;
            };
            let b = before.get(res).total_for(kind);
            let a = after.get(res).total_for(kind);
            // Saturating: counters restart when a cgroup is destroyed and its
            // path reused, which would otherwise underflow.
            deltas.insert(cg.clone(), a.saturating_sub(b));
        }

        let responsibility = Responsibility::new(&deltas);
        for (cg, &d) in &deltas {
            let pct = d as f64 / elapsed_us as f64 * 100.0;
            if pct < MIN_REPORTABLE_PCT || !responsibility.is_responsible(cg, d) {
                continue;
            }
            stalls.push(Stall {
                unit: cgroup::friendly_name(cg),
                cgroup: cg.to_string_lossy().into_owned(),
                resource: res,
                kind,
                delta_usec: d,
                pressure_pct: pct,
                peak_pct: pct,
            });
        }
    }

    stalls.sort_by(|a, b| {
        b.pressure_pct
            .partial_cmp(&a.pressure_pct)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    stalls.truncate(MAX_STALLS);
    stalls
}

#[cfg(test)]
mod responsibility_tests {
    use super::*;

    fn m(pairs: &[(&str, u64)]) -> HashMap<PathBuf, u64> {
        pairs.iter().map(|(p, d)| (PathBuf::from(p), *d)).collect()
    }

    /// The fast path must agree with the quadratic reference on every input.
    fn assert_agrees(d: &HashMap<PathBuf, u64>) {
        let r = Responsibility::new(d);
        for (p, &delta) in d {
            assert_eq!(
                r.is_responsible(p, delta),
                is_responsible_naive(p, delta, d),
                "disagreement at {p:?} delta={delta}"
            );
        }
    }

    #[test]
    fn agrees_with_reference_on_a_deep_tree() {
        assert_agrees(&m(&[
            ("/sys/fs/cgroup", 1000),
            ("/sys/fs/cgroup/user.slice", 900),
            ("/sys/fs/cgroup/user.slice/user-1000.slice", 880),
            ("/sys/fs/cgroup/user.slice/user-1000.slice/app.slice", 870),
            (
                "/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/a.scope",
                800,
            ),
            (
                "/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/b.scope",
                40,
            ),
            ("/sys/fs/cgroup/system.slice", 100),
            ("/sys/fs/cgroup/system.slice/x.service", 10),
        ]));
    }

    #[test]
    fn agrees_when_children_are_diffuse() {
        assert_agrees(&m(&[("/p", 1000), ("/p/a", 500), ("/p/b", 500)]));
    }

    #[test]
    fn agrees_on_sibling_prefix_traps() {
        // "/p2" shares a string prefix with "/p" but is not a descendant.
        assert_agrees(&m(&[("/p", 1000), ("/p2", 900), ("/p/c", 10)]));
    }

    #[test]
    fn agrees_with_gaps_in_the_hierarchy() {
        // Intermediate cgroups can be absent from the delta map entirely
        // (no pressure files, or unreadable). Propagation must still find the
        // nearest present ancestor rather than stopping at the first gap.
        assert_agrees(&m(&[("/a", 1000), ("/a/b/c/d", 950)]));
    }

    #[test]
    fn agrees_on_zero_and_single_entries() {
        assert_agrees(&m(&[]));
        assert_agrees(&m(&[("/only", 500)]));
        assert_agrees(&m(&[("/z", 0), ("/z/c", 0)]));
    }

    #[test]
    fn scales_without_quadratic_blowup() {
        // 5,000 cgroups is a dense Kubernetes node. The quadratic version
        // projected to ~5s per tick here.
        let mut d = HashMap::new();
        for i in 0..5000u64 {
            d.insert(
                PathBuf::from(format!(
                    "/sys/fs/cgroup/system.slice/svc{}.service",
                    i % 250
                ))
                .join(format!("task{i}.scope")),
                i % 977,
            );
        }
        let t = std::time::Instant::now();
        let r = Responsibility::new(&d);
        let build = t.elapsed();
        let _ = r.is_responsible(Path::new("/sys/fs/cgroup/system.slice"), 100);
        assert!(
            build < Duration::from_millis(250),
            "5k cgroups took {build:?}; quadratic behaviour has returned"
        );
    }
}

#[cfg(test)]
mod sampler_tests {
    use super::*;

    #[test]
    fn sampler_produces_a_measured_window() {
        let mut s = Sampler::new();
        std::thread::sleep(Duration::from_millis(120));
        let (_stalls, window) = s.tick();
        // The window is real elapsed time, not a configured constant.
        assert!(window >= 100_000, "window too short: {window}us");
        assert!(window < 5_000_000, "window implausibly long: {window}us");
    }

    #[test]
    fn sampler_reports_sweep_cost() {
        let mut s = Sampler::new();
        s.tick();
        assert!(s.last_sweep() > Duration::ZERO);
        assert!(
            s.last_sweep() < Duration::from_secs(5),
            "sweep pathologically slow"
        );
    }

    #[test]
    fn recommended_interval_scales_with_sweep_cost_and_respects_bounds() {
        let mut s = Sampler::new();
        s.tick();
        let floor = Duration::from_millis(250);
        let ceil = Duration::from_secs(30);
        let i = s.recommended_interval(0.02, floor, ceil);
        assert!(i >= floor && i <= ceil, "out of bounds: {i:?}");
        // A tighter duty budget must never sample more often.
        let tight = s.recommended_interval(0.001, floor, ceil);
        assert!(tight >= i, "tighter budget should slow sampling");
    }

    #[test]
    fn consecutive_ticks_do_not_double_count() {
        // Each tick diffs against the previous sweep, so a delta can never be
        // attributed to two windows.
        let mut s = Sampler::new();
        std::thread::sleep(Duration::from_millis(60));
        let (_, w1) = s.tick();
        std::thread::sleep(Duration::from_millis(60));
        let (_, w2) = s.tick();
        assert!(w1 > 0 && w2 > 0);
        assert!(w2 < 3_000_000, "second window should not include the first");
    }
}
