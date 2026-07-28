//! Drive temperature — reported carefully, and deliberately not as a diagnosis.
//!
//! Read from `/sys/class/hwmon/*/`, which is unprivileged. The obvious
//! alternative, `nvme smart-log`, requires root and would force the whole tool
//! to be run with privileges for one optional check.
//!
//! # Why this module is so conservative
//!
//! Temperature correlates with IO stalls without causing them. A drive can sit
//! near its limit indefinitely and never throttle. The only *evidence* of
//! throttling is the drive's own counters — `Thermal Management T1/T2 Trans
//! Count` and `Warning Temperature Time` — and those need root, so this module
//! cannot see them.
//!
//! Given that, the honest contract is: report the observation, name the command
//! that settles it, and never assert the mechanism. See [`super`] for the
//! incident that produced this rule.

use super::{Severity, Warning};
use std::fs;

/// How close to its published limit before a sensor is worth mentioning.
///
/// Five degrees, not ten. At ten this fired on a drive running 72 °C against an
/// 82 °C limit that had never throttled in 4,979 power-on hours — noise dressed
/// up as a finding.
const NEAR_LIMIT_MARGIN_C: f64 = 5.0;

/// Decide whether a drive temperature is worth reporting.
///
/// Split from the sysfs walk so the thresholds are testable without hardware.
pub fn assess(label: &str, temp_c: f64, crit_c: Option<f64>) -> Option<Warning> {
    let warn = |severity, message| {
        Some(Warning {
            source: "nvme".into(),
            severity,
            transient: false,
            message,
        })
    };

    match crit_c {
        Some(crit) if temp_c >= crit => warn(
            Severity::Critical,
            format!(
                "drive sensor '{label}' is at {temp_c:.0} °C, at or above its critical limit \
                 of {crit:.0} °C. Confirm whether it is actually throttling with \
                 `sudo nvme smart-log <dev>`: 'Thermal Management T1/T2 Trans Count' greater \
                 than zero means yes."
            ),
        ),

        Some(crit) if temp_c >= crit - NEAR_LIMIT_MARGIN_C => warn(
            Severity::Note,
            format!(
                "drive sensor '{label}' is at {temp_c:.0} °C, {:.0} °C below its limit of \
                 {crit:.0} °C. Worth noting, but not proof of throttling — check 'Thermal \
                 Management T1/T2 Trans Count' in `nvme smart-log` before blaming heat for \
                 an IO stall.",
                crit - temp_c
            ),
        ),

        // A sensor with no published threshold is not a thermal-management
        // sensor, and must not be warned on at ANY temperature.
        //
        // Concretely: a Samsung MZVLB256HBHQ reports "Sensor 2" at ~91 °C while
        // Composite sits at 69 °C against an 81 °C limit, with zero seconds
        // above warning and zero throttle transitions on the counter. The drive
        // simply does not manage against that sensor. Warning on it would fire
        // on every healthy drive of the family — the fastest way to teach users
        // to ignore the tool.
        _ => None,
    }
}

pub fn check() -> Vec<Warning> {
    let mut out = Vec::new();
    let Ok(hwmons) = fs::read_dir("/sys/class/hwmon") else {
        return out;
    };
    for hw in hwmons.flatten() {
        let dir = hw.path();
        let name = fs::read_to_string(dir.join("name"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if !(name.starts_with("nvme") || name == "drivetemp") {
            continue;
        }
        for idx in 1..=8 {
            let Some(millideg) = super::btrfs::read_u64(&dir.join(format!("temp{idx}_input")))
            else {
                continue;
            };
            let label = fs::read_to_string(dir.join(format!("temp{idx}_label")))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("temp{idx}"));
            let crit_c = super::btrfs::read_u64(&dir.join(format!("temp{idx}_crit")))
                .map(|v| v as f64 / 1000.0);
            if let Some(w) = assess(&label, millideg as f64 / 1000.0, crit_c) {
                out.push(w);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comfortably_under_limit_is_silent() {
        // 72 C against an 82 C limit: this exact drive ran here for 4,979
        // power-on hours with zero throttle transitions. Not a finding.
        assert!(assess("Composite", 72.0, Some(82.0)).is_none());
        assert!(assess("Composite", 45.0, Some(81.0)).is_none());
    }

    #[test]
    fn within_margin_reports_without_claiming_causation() {
        let w = assess("Composite", 78.0, Some(82.0)).expect("should report");
        assert_eq!(w.severity, Severity::Note);
        assert!(w.message.contains("not proof of throttling"), "{}", w.message);
        assert!(w.message.contains("Trans Count"), "{}", w.message);
    }

    #[test]
    fn at_or_over_limit_escalates_but_still_defers_to_the_counters() {
        let w = assess("Composite", 98.0, Some(82.0)).expect("should report");
        assert_eq!(w.severity, Severity::Critical);
        assert!(w.message.contains("at or above"), "{}", w.message);
        assert!(w.message.contains("Trans Count"), "{}", w.message);
    }

    #[test]
    fn sensors_without_a_published_limit_are_never_warned_on() {
        // Regression for the Samsung MZVLB256HBHQ false positive.
        assert!(assess("Sensor 2", 91.0, None).is_none());
        assert!(assess("Sensor 2", 105.0, None).is_none());
        assert!(assess("temp1", 72.0, None).is_none());
    }

    #[test]
    fn check_is_infallible_regardless_of_host_hardware() {
        let _ = check();
    }
}
