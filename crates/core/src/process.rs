//! Drilling inside a guilty cgroup to name the actual process.
//!
//! Attribution stops at the cgroup, and for daemons and GUI apps the cgroup
//! *is* the answer. For a terminal it is not: systemd puts the terminal and
//! every shell child in one cgroup, so a `du` chewing the disk is reported as
//! the terminal. Correct, but one level too high to act on.
//!
//! # Choosing a signal
//!
//! Three candidates, evaluated on real hardware rather than from documentation:
//!
//! | Source | Verdict |
//! |---|---|
//! | `/proc/<pid>/stat` field 42 (`delayacct_blkio_ticks`) | Precise blocking time, but **off by default** since 5.14 — `kernel.task_delayacct` is 0 unless root enables it. Used when available, never relied upon. |
//! | `/proc/<pid>/stat` field 3 == `D` | Uninterruptible sleep, i.e. blocked in the kernel, nearly always on IO. Statistical (needs repeated sampling) but needs no configuration whatsoever. |
//! | `/proc/<pid>/io` `read_bytes`/`write_bytes` | Actual block-layer bytes. Answers "who is *causing* the IO" rather than "who is blocked by it" — the complement, and just as useful. |
//!
//! We sample D-state repeatedly across the window and diff the IO counters
//! across it, then report both. When delay accounting happens to be enabled we
//! add its figure, because it is strictly better than a sample count.
//!
//! A caution learned in testing: none of this registers on tmpfs. Writes to
//! `/tmp` on most systems never reach a block device, so `write_bytes` stays 0
//! and nothing ever blocks. That is correct behaviour, not a broken signal.

use std::fs;
use std::path::Path;
use std::time::Duration;

/// How many processes a drill reports. Small, because this is evidence for a
/// human to read, not a census.
const MAX_CULPRITS: usize = 6;

/// A process inside a stalling cgroup, with evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct ProcCulprit {
    pub pid: u32,
    pub comm: String,
    /// How many samples caught this process in uninterruptible sleep.
    pub blocked_samples: u32,
    pub total_samples: u32,
    /// Block-layer bytes read during the window.
    pub read_bytes: u64,
    /// Block-layer bytes written during the window.
    pub write_bytes: u64,
    /// Milliseconds blocked on block IO, when delay accounting is enabled.
    pub blkio_delay_ms: Option<u64>,
}

impl ProcCulprit {
    /// Share of samples spent blocked, 0.0–100.0.
    pub fn blocked_pct(&self) -> f64 {
        if self.total_samples == 0 {
            return 0.0;
        }
        self.blocked_samples as f64 / self.total_samples as f64 * 100.0
    }
}

/// Is kernel delay accounting switched on?
///
/// `CONFIG_TASK_DELAY_ACCT=y` only compiles it in; since 5.14 the runtime
/// default is off, so `delayacct_blkio_ticks` reads as a constant zero. Callers
/// should say "not enabled" rather than "no delay", which are very different
/// claims.
pub fn delayacct_enabled() -> bool {
    fs::read_to_string("/proc/sys/kernel/task_delayacct")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

/// Extract state and `delayacct_blkio_ticks` from a `/proc/<pid>/stat` body.
///
/// The `comm` field is wrapped in parentheses and may itself contain spaces and
/// parentheses — `(Web Content)`, `(foo) bar)` — so fields cannot be split
/// naively. Everything after the *last* `)` is positional.
fn parse_stat(body: &str) -> Option<(char, u64)> {
    let rest = &body[body.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After the closing paren, index 0 is field 3 (state), so field N is at
    // index N-3. delayacct_blkio_ticks is field 42.
    let state = fields.first()?.chars().next()?;
    let ticks = fields.get(42 - 3).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some((state, ticks))
}

fn comm_of(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "<gone>".into())
}

/// Read `read_bytes`/`write_bytes` from `/proc/<pid>/io`.
///
/// Unreadable for processes we don't own, which is expected and not an error.
fn io_bytes(pid: u32) -> Option<(u64, u64)> {
    let body = fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    let mut r = 0;
    let mut w = 0;
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("read_bytes:") {
            r = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("write_bytes:") {
            w = v.trim().parse().unwrap_or(0);
        }
    }
    Some((r, w))
}

/// Every PID in a cgroup **subtree**.
///
/// `cgroup.procs` lists only direct members, which is almost never what a user
/// means. systemd nests aggressively: a terminal is
/// `app-foo.service` while the shells it spawns land in sibling
/// `app-foo-surface-NNN.scope` children, so a `dd` chewing the disk is not in
/// the cgroup that got blamed — it is one level down. Reading only direct
/// members finds nothing and reports "no process caught blocking", which is
/// worse than useless because it reads as an all-clear.
pub fn pids_in(cgroup: &Path) -> Vec<u32> {
    let mut out = Vec::new();
    collect_pids(cgroup, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

fn collect_pids(dir: &Path, out: &mut Vec<u32>) {
    if let Ok(body) = fs::read_to_string(dir.join("cgroup.procs")) {
        out.extend(body.lines().filter_map(|l| l.trim().parse::<u32>().ok()));
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if matches!(e.file_type(), Ok(ft) if ft.is_dir()) {
            collect_pids(&e.path(), out);
        }
    }
}

/// Sample the processes in `cgroup` over `window`, ranked by evidence.
///
/// Cost is bounded by the cgroup's process count, not the system's — typically
/// a handful — so this stays cheap enough to run on demand.
pub fn drill(cgroup: &Path, window: Duration, samples: u32) -> Vec<ProcCulprit> {
    let pids = pids_in(cgroup);
    if pids.is_empty() || samples == 0 {
        return Vec::new();
    }

    let before: Vec<Option<(u64, u64)>> = pids.iter().map(|p| io_bytes(*p)).collect();
    let mut blocked = vec![0u32; pids.len()];
    let mut seen = vec![0u32; pids.len()];
    let mut ticks_before = vec![0u64; pids.len()];
    let mut ticks_after = vec![0u64; pids.len()];

    // Track the most recent successful IO reading per process.
    //
    // Reading only at the end loses everything a process did if it exits
    // during the window — and a process that finishes a burst and exits is
    // exactly the shape of the thing that caused the stall. Measured: a dd
    // writing 3 GiB was recorded as moving 0 bytes because it had exited by
    // the closing read, which then classified the culprit as a bystander.
    let mut last_io: Vec<Option<(u64, u64)>> = before.clone();

    let gap = window / samples.max(1);
    for round in 0..samples {
        for (i, pid) in pids.iter().enumerate() {
            if let Some(now) = io_bytes(*pid) {
                last_io[i] = Some(now);
            }
            let Ok(body) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue; // exited mid-window; simply stops contributing samples
            };
            let Some((state, ticks)) = parse_stat(&body) else {
                continue;
            };
            seen[i] += 1;
            if state == 'D' {
                blocked[i] += 1;
            }
            if round == 0 {
                ticks_before[i] = ticks;
            }
            ticks_after[i] = ticks;
        }
        std::thread::sleep(gap);
    }

    let delayacct = delayacct_enabled();
    let out: Vec<ProcCulprit> = pids
        .iter()
        .enumerate()
        .filter_map(|(i, &pid)| {
            // Prefer a live reading, else the last one seen before it exited.
            let end = io_bytes(pid).or(last_io[i]);
            let (rb, wb) = match (before[i], end) {
                (Some((r0, w0)), Some((r1, w1))) => (r1.saturating_sub(r0), w1.saturating_sub(w0)),
                _ => (0, 0),
            };
            // Nothing observed: no blocking, no bytes. Not a culprit.
            if blocked[i] == 0 && rb == 0 && wb == 0 {
                return None;
            }
            Some(ProcCulprit {
                pid,
                comm: comm_of(pid),
                blocked_samples: blocked[i],
                total_samples: seen[i],
                read_bytes: rb,
                write_bytes: wb,
                // USER_HZ is 100 on every Linux architecture that matters, so a
                // tick is 10ms.
                blkio_delay_ms: if delayacct {
                    Some(ticks_after[i].saturating_sub(ticks_before[i]) * 10)
                } else {
                    None
                },
            })
        })
        .collect();

    rank(out)
}

/// Choose which processes to report.
///
/// Extracted so the choice can be tested without a live kernel, because the
/// failure it guards against is silent: a ranking that looks reasonable and
/// quietly discards the only process that mattered.
fn rank(out: Vec<ProcCulprit>) -> Vec<ProcCulprit> {
    // Keep the worst blocked AND the biggest movers, because they are almost
    // never the same process.
    //
    // Ranking by blocked time alone and then truncating silently discards the
    // culprit every time: a process saturating the queue is not itself blocked,
    // so it sorts last and falls off the end. That defeats the entire purpose
    // of drilling — the caller is left with a list of casualties and no cause.
    // Measured on a real dd: it wrote 2 GiB and never appeared in the top five.
    let by_blocked = {
        let mut v: Vec<usize> = (0..out.len()).collect();
        v.sort_by_key(|&i| std::cmp::Reverse(out[i].blocked_samples));
        v
    };
    let by_bytes = {
        let mut v: Vec<usize> = (0..out.len()).collect();
        v.sort_by_key(|&i| std::cmp::Reverse(out[i].read_bytes + out[i].write_bytes));
        v
    };

    let mut keep: Vec<usize> = Vec::new();
    // Interleave so neither list starves the other under a tight cap.
    for rank in 0..out.len() {
        for src in [&by_blocked, &by_bytes] {
            if let Some(&i) = src.get(rank)
                && !keep.contains(&i)
            {
                keep.push(i);
            }
        }
        if keep.len() >= MAX_CULPRITS {
            break;
        }
    }
    keep.truncate(MAX_CULPRITS);

    let mut picked: Vec<ProcCulprit> = keep.into_iter().map(|i| out[i].clone()).collect();
    // Present bytes-first: the caller is looking for whodunnit.
    picked.sort_by_key(|c| std::cmp::Reverse(c.read_bytes + c.write_bytes));
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_state_and_ticks_from_real_format() {
        // Trimmed but positionally faithful /proc/pid/stat line.
        let mut f: Vec<String> = (3..=52).map(|n| n.to_string()).collect();
        f[42 - 3] = "777".into(); // delayacct_blkio_ticks
        f[0] = "D".into();
        let body = format!("1234 (bash) {}", f.join(" "));
        assert_eq!(parse_stat(&body), Some(('D', 777)));
    }

    #[test]
    fn comm_containing_spaces_and_parens_does_not_break_parsing() {
        // Firefox really does name threads "(Web Content)"; a naive split on
        // whitespace shifts every field and silently reports nonsense.
        let mut f: Vec<String> = (3..=52).map(|n| n.to_string()).collect();
        f[42 - 3] = "42".into();
        f[0] = "R".into();
        let body = format!("99 (Web Content (x)) {}", f.join(" "));
        assert_eq!(parse_stat(&body), Some(('R', 42)));
    }

    /// The bug this guards: ranking by blocked time then truncating drops the
    /// culprit every time, because a process saturating the queue is not itself
    /// blocked. Observed live — a dd wrote 2 GiB and never made the top five.
    #[test]
    fn the_biggest_mover_survives_truncation_alongside_the_worst_blocked() {
        // Eight processes blocked hard and moving nothing, plus one writing a
        // lot while barely blocked. The writer must not be dropped.
        let mut all: Vec<ProcCulprit> = (0..8)
            .map(|i| ProcCulprit {
                pid: 100 + i,
                comm: format!("victim{i}"),
                blocked_samples: 12,
                total_samples: 12,
                read_bytes: 0,
                write_bytes: 0,
                blkio_delay_ms: None,
            })
            .collect();
        all.push(ProcCulprit {
            pid: 999,
            comm: "dd".into(),
            blocked_samples: 1,
            total_samples: 12,
            read_bytes: 0,
            write_bytes: 5 * 1024 * 1024 * 1024,
            blkio_delay_ms: None,
        });

        let picked = rank(all);

        assert!(
            picked.iter().any(|c| c.comm == "dd"),
            "the cause was truncated away; picked: {:?}",
            picked.iter().map(|c| &c.comm).collect::<Vec<_>>()
        );
        // And a victim must still be present, or we have merely inverted the bug.
        assert!(
            picked.iter().any(|c| c.comm.starts_with("victim")),
            "victims disappeared"
        );
    }

    #[test]
    fn truncated_stat_yields_no_ticks_rather_than_panicking() {
        assert_eq!(parse_stat("1 (x) S 1 1"), Some(('S', 0)));
        assert_eq!(parse_stat("garbage"), None);
        assert_eq!(parse_stat(""), None);
    }

    #[test]
    fn blocked_pct_handles_zero_samples() {
        let c = ProcCulprit {
            pid: 1,
            comm: "x".into(),
            blocked_samples: 0,
            total_samples: 0,
            read_bytes: 0,
            write_bytes: 0,
            blkio_delay_ms: None,
        };
        assert_eq!(c.blocked_pct(), 0.0);
    }

    #[test]
    fn pids_in_descends_into_child_cgroups() {
        // Regression: reading only cgroup.procs finds direct members and misses
        // everything nested, which on a real desktop is most of the processes.
        // Verified against the live root cgroup, whose direct membership is
        // near-empty while the tree holds every process on the machine.
        let root = Path::new("/sys/fs/cgroup");
        if root.exists() {
            let direct = fs::read_to_string(root.join("cgroup.procs"))
                .map(|s| s.lines().count())
                .unwrap_or(0);
            let recursive = pids_in(root).len();
            assert!(
                recursive > direct,
                "recursive {recursive} should exceed direct {direct}"
            );
        }
    }

    #[test]
    fn pids_in_deduplicates() {
        let root = Path::new("/sys/fs/cgroup");
        if root.exists() {
            let v = pids_in(root);
            let mut u = v.clone();
            u.sort_unstable();
            u.dedup();
            assert_eq!(v.len(), u.len());
        }
    }

    #[test]
    fn drill_on_a_nonexistent_cgroup_is_empty_not_a_panic() {
        assert!(
            drill(
                Path::new("/sys/fs/cgroup/definitely-not-here"),
                Duration::from_millis(10),
                2
            )
            .is_empty()
        );
    }

    #[test]
    fn delayacct_probe_does_not_panic() {
        let _ = delayacct_enabled();
    }
}
