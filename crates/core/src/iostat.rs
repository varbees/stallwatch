//! Per-cgroup block-layer byte counters, from `io.stat`.
//!
//! # Why this exists
//!
//! Pressure answers "who was *blocked*". It cannot answer "who was doing the
//! work", because that is not what the kernel measures there — a process
//! saturating a queue is not itself waiting on it. Reporting pressure alone
//! therefore names the casualty and misses the culprit, every time.
//!
//! The complement was always one file away. `io.stat` sits in the same cgroup
//! directory as `io.pressure`, is world-readable, and carries the block-layer
//! bytes that cgroup moved. Pairing the two is what separates a cause from a
//! victim.
//!
//! # Why not `/proc/<pid>/io`
//!
//! That was the original evidence source and it could not work. It returns
//! `EACCES` for any process the invoking user does not own, and in practice
//! the processes that matter are kernel threads and root-owned daemons —
//! `kworker/*`, `systemd-journald`, `mount.*`. Measured against 520,155
//! recorded incidents on one desktop: every one of 182,022 candidate processes
//! reported zero bytes, so the cause branch never executed once in 29 days.
//!
//! `io.stat` is readable for those same cgroups without privileges. The trade
//! is granularity — a cgroup rather than a pid — and that is the right trade,
//! because a cgroup is a systemd unit and a unit is what a person acts on.
//! Process-level bytes remain useful where they are readable, as enrichment.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Block-layer bytes a cgroup moved, summed across every backing device.
///
/// Summing is deliberate: a caller asking "who saturated the IO" does not care
/// that the work was split across two NVMe namespaces, and per-device detail
/// would multiply the series count for no gain in attribution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoBytes {
    pub read: u64,
    pub write: u64,
    /// Discard (TRIM) bytes. Tracked separately because discard is the one
    /// class of IO that is genuinely not the cgroup's fault to fix — it is
    /// queued by the filesystem and drained by the kernel.
    pub discard: u64,
}

impl IoBytes {
    /// Read plus write. Discard is excluded: it is kernel-side cleanup, and
    /// counting it would blame a cgroup for a deletion it already finished.
    pub fn total(self) -> u64 {
        self.read.saturating_add(self.write)
    }

    /// Difference between two readings, saturating.
    ///
    /// Counters restart when a cgroup is destroyed and its path reused, which
    /// would otherwise underflow into an enormous fabricated delta.
    pub fn delta(self, before: Self) -> Self {
        Self {
            read: self.read.saturating_sub(before.read),
            write: self.write.saturating_sub(before.write),
            discard: self.discard.saturating_sub(before.discard),
        }
    }
}

/// Parse an `io.stat` body.
///
/// One line per device:
/// ```text
/// 259:0 rbytes=6101106688 wbytes=39976960 rios=52385 wios=1364 dbytes=0 dios=0
/// ```
///
/// Unknown keys are ignored rather than rejected: the kernel has added fields
/// to this file before (`dbytes`/`dios` arrived with discard accounting) and a
/// parser that fails closed on a newer kernel is a parser that reports "no IO"
/// on exactly the systems worth measuring.
pub fn parse(body: &str) -> IoBytes {
    let mut out = IoBytes::default();
    for line in body.lines() {
        for field in line.split_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                continue; // the leading MAJ:MIN
            };
            let Ok(n) = value.parse::<u64>() else {
                continue;
            };
            match key {
                "rbytes" => out.read = out.read.saturating_add(n),
                "wbytes" => out.write = out.write.saturating_add(n),
                "dbytes" => out.discard = out.discard.saturating_add(n),
                _ => {}
            }
        }
    }
    out
}

/// Read `io.stat` for one cgroup.
///
/// `None` when the file is absent or unreadable, which is normal: cgroups
/// without block IO controllers have no `io.stat` at all, and that is not an
/// error to report.
pub fn read(cgroup: &Path) -> Option<IoBytes> {
    fs::read_to_string(cgroup.join("io.stat"))
        .ok()
        .map(|b| parse(&b))
}

/// Read `io.stat` for every cgroup that has one.
///
/// Cgroups without the file are omitted rather than recorded as zero, matching
/// [`crate::cgroup::sample`]: a cgroup that appears between two samples is
/// absent from the first map and gets skipped when diffing, instead of showing
/// up as a huge bogus delta.
pub fn sample(cgroups: &[PathBuf]) -> HashMap<PathBuf, IoBytes> {
    let mut map = HashMap::with_capacity(cgroups.len());
    for cg in cgroups {
        if let Some(b) = read(cg) {
            map.insert(cg.clone(), b);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_line() {
        let b =
            parse("259:0 rbytes=6101106688 wbytes=39976960 rios=52385 wios=1364 dbytes=0 dios=0");
        assert_eq!(b.read, 6_101_106_688);
        assert_eq!(b.write, 39_976_960);
        assert_eq!(b.discard, 0);
    }

    #[test]
    fn sums_across_devices() {
        let b = parse(
            "253:0 rbytes=100 wbytes=200 rios=1 wios=1 dbytes=7 dios=1\n\
             259:0 rbytes=300 wbytes=400 rios=1 wios=1 dbytes=3 dios=1\n",
        );
        assert_eq!(b.read, 400);
        assert_eq!(b.write, 600);
        assert_eq!(b.discard, 10);
        assert_eq!(b.total(), 1000);
    }

    #[test]
    fn an_empty_file_is_zero_not_an_error() {
        assert_eq!(parse(""), IoBytes::default());
        assert_eq!(parse("\n\n"), IoBytes::default());
    }

    #[test]
    fn unknown_fields_are_ignored_so_a_newer_kernel_still_parses() {
        let b = parse("259:0 rbytes=10 wbytes=20 newfield=99 garbage nonnumeric=xyz");
        assert_eq!(b.read, 10);
        assert_eq!(b.write, 20);
    }

    #[test]
    fn discard_is_excluded_from_total() {
        // A deletion that queued 3 GiB of TRIM is not 3 GiB of the cgroup's IO.
        let b = parse("259:0 rbytes=0 wbytes=0 dbytes=3221225472");
        assert_eq!(b.total(), 0);
        assert_eq!(b.discard, 3_221_225_472);
    }

    #[test]
    fn delta_saturates_when_a_cgroup_path_is_reused() {
        let before = IoBytes {
            read: 500,
            write: 500,
            discard: 0,
        };
        let after = IoBytes {
            read: 10,
            write: 10,
            discard: 0,
        };
        assert_eq!(after.delta(before), IoBytes::default());
    }

    #[test]
    fn delta_is_the_difference() {
        let before = IoBytes {
            read: 100,
            write: 100,
            discard: 5,
        };
        let after = IoBytes {
            read: 350,
            write: 600,
            discard: 9,
        };
        let d = after.delta(before);
        assert_eq!((d.read, d.write, d.discard), (250, 500, 4));
        assert_eq!(d.total(), 750);
    }
}
