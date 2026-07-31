//! Prometheus exposition, aligned with the cAdvisor/Kubernetes vocabulary.
//!
//! # Counters, not deltas
//!
//! The CLI reports deltas because humans want "frozen 858 ms in the last
//! second". Prometheus wants the opposite: a monotonically increasing counter
//! that it differentiates itself with `rate()`. Exporting our computed deltas
//! would be wrong twice over — it double-samples (Prometheus already has a
//! scrape interval) and it breaks on restart because a delta has no history.
//!
//! PSI's `total=` field is already exactly the counter Prometheus wants:
//! monotonic microseconds since boot. So this module reads raw PSI totals
//! rather than reusing [`crate::Report`], which is why it does not share the
//! attribution path.
//!
//! # Naming
//!
//! cAdvisor and Kubernetes settled on
//! `container_pressure_{cpu,memory,io}_{waiting,stalled}_seconds_total`, where
//! `waiting` is PSI `some` and `stalled` is PSI `full`. We are reporting
//! systemd units rather than containers, so the prefix differs, but the shape
//! and the waiting/stalled vocabulary are deliberately identical: anything
//! already ingesting cAdvisor PSI metrics should find nothing surprising.
//!
//! # Cardinality
//!
//! This is the failure mode that takes down a Prometheus, not a bug that shows
//! up in tests. A desktop has ~300 cgroups; a busy Kubernetes node has
//! thousands, and systemd mints a fresh transient scope per shell command
//! (`app-ghostty-surface-transient-6274.scope`) — an unbounded label space
//! that would churn series forever.
//!
//! Two defences, both on by default: skip cgroups with zero accumulated
//! pressure, and cap the number of series emitted. `stallwatch_series_dropped`
//! reports what was withheld, because a silent cap is a lie.

use crate::cgroup;
use crate::psi::{PsiKind, Resource};
use std::fmt::Write as _;

/// Default ceiling on exported series per resource. Chosen to be comfortable
/// on a desktop and to force a deliberate decision on a dense node.
pub const DEFAULT_MAX_SERIES: usize = 500;

/// Escape a Prometheus label value (only `\`, `"` and newline are special).
fn esc(v: &str) -> String {
    let mut o = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

/// Render the full exposition document.
///
/// `now_unix` is passed in rather than read here so the output is a pure
/// function of its inputs and can be tested.
pub fn render(max_series: usize) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let started = std::time::Instant::now();

    // The exposition format requires every sample of a metric family to be
    // CONTIGUOUS, immediately after its HELP/TYPE. Emitting headers up front
    // and then interleaving waiting/stalled series makes the official parser
    // read each switch as a new unnamed family — it reported 589 families of
    // type "unknown" for what should be six counters. Bucket by name, emit
    // each block whole.
    let mut waiting = String::new();
    let mut stalled = String::new();

    let cgroups = cgroup::all();
    let snapshot = cgroup::sample(&cgroups);
    let mut emitted = 0usize;
    let mut dropped = 0usize;

    // Deterministic order: unstable ordering makes diffs unreadable and makes
    // textfile-collector writes churn needlessly.
    let mut paths: Vec<_> = snapshot.keys().cloned().collect();
    paths.sort();

    for path in paths {
        let snap = snapshot[&path];
        let unit = cgroup::friendly_name(&path);
        let cg = path.to_string_lossy();

        for res in Resource::ALL {
            let psi = snap.get(res);
            // Zero accumulated pressure since boot means this cgroup has never
            // contended for anything. Emitting it is pure cardinality cost.
            if psi.some_total_us == 0 && psi.full_total_us == 0 {
                continue;
            }
            if emitted >= max_series {
                dropped += 1;
                continue;
            }
            let labels = format!(
                r#"unit="{}",cgroup="{}",resource="{}""#,
                esc(&unit),
                esc(&cg),
                res
            );
            let _ = writeln!(
                waiting,
                "stallwatch_pressure_waiting_seconds_total{{{labels}}} {:.6}",
                psi.total_for(PsiKind::Some) as f64 / 1e6
            );
            // CPU has no 'full' line by construction: a task waiting for CPU
            // implies another is running on it, so total starvation is
            // impossible. A constant zero would invite false alarms.
            if res != Resource::Cpu {
                let _ = writeln!(
                    stalled,
                    "stallwatch_pressure_stalled_seconds_total{{{labels}}} {:.6}",
                    psi.total_for(PsiKind::Full) as f64 / 1e6
                );
            }
            emitted += 1;
        }
    }

    out.push_str(
        "# HELP stallwatch_pressure_waiting_seconds_total Time at least one task in this cgroup was stalled (PSI 'some').\n\
         # TYPE stallwatch_pressure_waiting_seconds_total counter\n",
    );
    out.push_str(&waiting);
    out.push_str(
        "# HELP stallwatch_pressure_stalled_seconds_total Time every non-idle task in this cgroup was stalled at once (PSI 'full').\n\
         # TYPE stallwatch_pressure_stalled_seconds_total counter\n",
    );
    out.push_str(&stalled);

    out.push_str(&pathology_series());

    let _ = write!(
        out,
        "# HELP stallwatch_series_emitted Series emitted this scrape.\n\
         # TYPE stallwatch_series_emitted gauge\n\
         stallwatch_series_emitted {emitted}\n\
         # HELP stallwatch_series_dropped Series withheld by the cardinality cap. Non-zero means the export is incomplete.\n\
         # TYPE stallwatch_series_dropped gauge\n\
         stallwatch_series_dropped {dropped}\n\
         # HELP stallwatch_cgroups_scanned Cgroups walked this scrape.\n\
         # TYPE stallwatch_cgroups_scanned gauge\n\
         stallwatch_cgroups_scanned {}\n\
         # HELP stallwatch_scrape_duration_seconds Time spent building this response.\n\
         # TYPE stallwatch_scrape_duration_seconds gauge\n\
         stallwatch_scrape_duration_seconds {:.6}\n",
        cgroups.len(),
        started.elapsed().as_secs_f64()
    );

    out
}

/// Pathology gauges: the conditions that explain stalls the counters cannot.
///
/// Each family is buffered separately and emitted with its own HELP/TYPE
/// immediately preceding its samples. Batching headers and then batching
/// samples looks tidier and is wrong: a TYPE line closes the previous family,
/// so the earlier declarations end up with zero samples and the actual series
/// arrive orphaned as type "unknown".
fn pathology_series() -> String {
    let mut unalloc = String::new();
    let mut discard = String::new();
    let mut temp = String::new();
    let mut temp_limit = String::new();

    if let Ok(entries) = std::fs::read_dir("/sys/fs/btrfs") {
        let mut fsids: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        fsids.sort();
        for base in fsids {
            if !base.join("allocation").is_dir() {
                continue;
            }
            let label = base
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            let read = |p: &str| -> Option<u64> {
                std::fs::read_to_string(base.join(p))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            };

            let mut allocated = 0u64;
            let mut ok = true;
            for kind in ["data", "metadata", "system"] {
                match read(&format!("allocation/{kind}/disk_total")) {
                    Some(v) => allocated += v,
                    None => ok = false,
                }
            }
            let mut device_size = 0u64;
            if let Ok(devs) = std::fs::read_dir(base.join("devices")) {
                for d in devs.flatten() {
                    device_size += std::fs::read_to_string(d.path().join("size"))
                        .ok()
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or(0)
                        * 512;
                }
            }
            if ok && device_size >= allocated {
                let _ = writeln!(
                    unalloc,
                    r#"stallwatch_btrfs_unallocated_bytes{{fsid="{}"}} {}"#,
                    esc(&label),
                    device_size - allocated
                );
            }
            if let Some(ext) = read("discard/discardable_extents") {
                let _ = writeln!(
                    discard,
                    r#"stallwatch_btrfs_discard_queued_extents{{fsid="{}"}} {ext}"#,
                    esc(&label)
                );
            }
        }
    }

    // Drive temperature, and ONLY for sensors publishing their own limit. A
    // sensor with no threshold is not one the drive manages against: a Samsung
    // MZVLB256HBHQ reports 91 C on such a sensor while sitting well below its
    // real limit, having never throttled in 4,979 power-on hours. Exporting it
    // hands operators a metric that alerts on healthy hardware.
    if let Ok(hwmons) = std::fs::read_dir("/sys/class/hwmon") {
        let mut dirs: Vec<_> = hwmons.flatten().map(|e| e.path()).collect();
        dirs.sort();
        for dir in dirs {
            let name = std::fs::read_to_string(dir.join("name"))
                .unwrap_or_default()
                .trim()
                .to_string();
            if !(name.starts_with("nvme") || name == "drivetemp") {
                continue;
            }
            for idx in 1..=8 {
                let read = |p: String| -> Option<u64> {
                    std::fs::read_to_string(dir.join(p))
                        .ok()?
                        .trim()
                        .parse()
                        .ok()
                };
                let Some(t) = read(format!("temp{idx}_input")) else {
                    continue;
                };
                let Some(crit) = read(format!("temp{idx}_crit")) else {
                    continue;
                };
                let label = std::fs::read_to_string(dir.join(format!("temp{idx}_label")))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| format!("temp{idx}"));
                let l = format!(r#"device="{}",sensor="{}""#, esc(&name), esc(&label));
                let _ = writeln!(
                    temp,
                    "stallwatch_drive_temperature_celsius{{{l}}} {:.1}",
                    t as f64 / 1000.0
                );
                let _ = writeln!(
                    temp_limit,
                    "stallwatch_drive_temperature_limit_celsius{{{l}}} {:.1}",
                    crit as f64 / 1000.0
                );
            }
        }
    }

    let mut out = String::new();
    let family = |out: &mut String, help: &str, name: &str, body: &str| {
        if body.is_empty() {
            return;
        }
        let _ = write!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{body}");
    };
    family(
        &mut out,
        "Device space not yet claimed by any block group. Near zero means writes stall hunting fragmented chunks even though df shows free space.",
        "stallwatch_btrfs_unallocated_bytes",
        &unalloc,
    );
    family(
        &mut out,
        "Extents awaiting async TRIM. Kernel-side work: the disk looks busy while no process shows IO delay. Transient.",
        "stallwatch_btrfs_discard_queued_extents",
        &discard,
    );
    family(
        &mut out,
        "Drive temperature. Only sensors publishing their own critical threshold are exported; auxiliary sensors read high on healthy hardware.",
        "stallwatch_drive_temperature_celsius",
        &temp,
    );
    family(
        &mut out,
        "The drive's own published critical threshold.",
        "stallwatch_drive_temperature_limit_celsius",
        &temp_limit,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_label_values() {
        assert_eq!(esc(r"app\x2dfoo"), r"app\\x2dfoo");
        assert_eq!(esc(r#"a"b"#), r#"a\"b"#);
        assert_eq!(esc("a\nb"), r"a\nb");
    }

    #[test]
    fn output_is_wellformed_exposition() {
        let doc = render(DEFAULT_MAX_SERIES);
        for line in doc.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            // metric{labels} value  -- value must parse as a float
            let value = line.rsplit(' ').next().expect("value field");
            assert!(
                value.parse::<f64>().is_ok(),
                "unparseable value in line: {line}"
            );
            assert!(!line.contains("NaN"), "NaN in output: {line}");
        }
    }

    #[test]
    fn every_metric_has_help_and_type() {
        let doc = render(DEFAULT_MAX_SERIES);
        let mut declared = std::collections::HashSet::new();
        for line in doc.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                declared.insert(rest.split(' ').next().unwrap().to_string());
            }
        }
        for line in doc.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(declared.contains(name), "undeclared metric: {name}");
        }
    }

    #[test]
    fn cpu_has_no_stalled_series() {
        // PSI does not produce a 'full' line for CPU; a constant zero would
        // invite alerts on a condition that cannot occur.
        let doc = render(DEFAULT_MAX_SERIES);
        for line in doc.lines() {
            if line.starts_with("stallwatch_pressure_stalled_seconds_total") {
                assert!(!line.contains(r#"resource="cpu""#), "{line}");
            }
        }
    }

    #[test]
    fn cardinality_cap_is_enforced_and_reported() {
        let doc = render(2);
        let emitted: usize = doc
            .lines()
            .find_map(|l| l.strip_prefix("stallwatch_series_emitted ")?.parse().ok())
            .expect("emitted gauge");
        assert!(emitted <= 2, "cap not enforced: {emitted}");
        assert!(
            doc.contains("stallwatch_series_dropped "),
            "must report drops"
        );
    }

    #[test]
    fn each_metric_family_is_contiguous() {
        // Regression: the exposition format requires all samples of a family
        // to be adjacent. Interleaving them made the official Prometheus
        // parser report 589 families of type "unknown" instead of six
        // counters, while our own "has HELP and TYPE" test passed happily.
        let doc = render(DEFAULT_MAX_SERIES);
        let mut seen_blocks: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut last_typed: Option<String> = None;
        for line in doc.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                last_typed = Some(rest.split(' ').next().unwrap().to_string());
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let name = line.split(['{', ' ']).next().unwrap().to_string();
            // A sample must belong to the most recent TYPE declaration.
            // Batching all headers then all samples silently orphans families;
            // the official parser reports them as type "unknown".
            assert_eq!(
                last_typed.as_deref(),
                Some(name.as_str()),
                "sample {name} does not follow its own TYPE declaration"
            );
            if name != current {
                assert!(
                    !seen_blocks.contains(&name),
                    "family {name} appears in more than one block"
                );
                seen_blocks.push(name.clone());
                current = name;
            }
        }
    }

    #[test]
    fn output_is_deterministically_ordered() {
        // Textfile-collector writes churn if ordering is unstable.
        let a = render(50);
        let b = render(50);
        let names = |d: &str| -> Vec<String> {
            d.lines()
                .filter(|l| l.starts_with("stallwatch_pressure_"))
                .map(|l| l.split(' ').next().unwrap().to_string())
                .collect()
        };
        assert_eq!(names(&a), names(&b));
    }
}
