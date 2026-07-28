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
use crate::{Stall, MAX_STALLS, MIN_REPORTABLE_PCT};
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

/// Is this cgroup the one to blame, or is a child responsible?
///
/// A cgroup is responsible when no single descendant accounts for
/// [`CHILD_DOMINANCE`] percent or more of its stall.
pub fn is_responsible(cg: &Path, delta: u64, deltas: &HashMap<PathBuf, u64>) -> bool {
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
            let Some(before) = first.get(cg) else { continue };
            let b = before.get(res).total_for(kind);
            let a = after.get(res).total_for(kind);
            // Saturating: counters restart when a cgroup is destroyed and its
            // path reused, which would otherwise underflow.
            deltas.insert(cg.clone(), a.saturating_sub(b));
        }

        for (cg, &d) in &deltas {
            let pct = d as f64 / elapsed_us as f64 * 100.0;
            if pct < MIN_REPORTABLE_PCT || !is_responsible(cg, d, &deltas) {
                continue;
            }
            stalls.push(Stall {
                unit: cgroup::friendly_name(cg),
                cgroup: cg.to_string_lossy().into_owned(),
                resource: res,
                kind,
                delta_usec: d,
                pressure_pct: pct,
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
        assert!(!is_responsible(Path::new("/sys/fs/cgroup/user.slice"), 1000, &d));
        assert!(is_responsible(
            Path::new("/sys/fs/cgroup/user.slice/app.slice"),
            900,
            &d
        ));
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
        assert!(is_responsible(Path::new("/sys/fs/cgroup/user.slice"), 1000, &d));
    }

    #[test]
    fn zero_delta_is_never_responsible() {
        assert!(!is_responsible(Path::new("/x"), 0, &m(&[])));
    }

    #[test]
    fn exactly_at_dominance_threshold_yields() {
        let d = m(&[("/p", 1000), ("/p/c", 800)]);
        assert!(!is_responsible(Path::new("/p"), 1000, &d));
    }

    #[test]
    fn just_under_threshold_keeps_blame() {
        let d = m(&[("/p", 1000), ("/p/c", 799)]);
        assert!(is_responsible(Path::new("/p"), 1000, &d));
    }

    #[test]
    fn sibling_prefix_is_not_treated_as_a_child() {
        // "/p2" starts_with "/p" as a string but is not a descendant path.
        // PathBuf::starts_with compares components, which is why this holds —
        // guard it with a test so nobody "optimises" it into a string compare.
        let d = m(&[("/p", 1000), ("/p2", 900)]);
        assert!(is_responsible(Path::new("/p"), 1000, &d));
    }
}
