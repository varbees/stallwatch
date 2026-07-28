//! stallwatch — name the unit that is stalling a Linux system, and explain why.
//!
//! # Why this exists
//!
//! Linux has exposed per-cgroup Pressure Stall Information since 4.20. Every
//! systemd unit on the machine has `cpu.pressure`, `memory.pressure` and
//! `io.pressure` sitting in its cgroup directory, readable without privileges.
//! Almost every tool that surfaces PSI reads only the system-wide
//! `/proc/pressure/*` files and stops there — so users learn *that* the machine
//! is stalling and never *who* is stalling it.
//!
//! This crate closes that gap, and adds a second layer that explains causes the
//! numbers alone cannot: a filesystem whose allocator is exhausted, a drive at
//! its thermal limit, a kernel busy with background TRIM.
//!
//! # Design commitments
//!
//! - **No privileges.** Everything is read from `/sys` and `/proc` as the
//!   invoking user. A diagnostic that needs root is a diagnostic people don't run.
//! - **No dependencies.** The engine is `std` only, so it can be reduced to a
//!   C ABI later without dragging a crate graph into someone's C++ build.
//! - **Deltas, not averages.** The kernel's `avg10/60/300` are exponentially
//!   damped; a one-second freeze is smeared away by the time anyone looks. The
//!   `total` counter is raw microseconds, so sampling it twice over a known
//!   monotonic window gives the truth for exactly that window.
//! - **No causal claims we cannot support.** A correlated observation is
//!   reported as an observation. See [`pathology`] for why that rule exists.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! let report = stallwatch::observe(Duration::from_secs(1));
//! for stall in &report.stalls {
//!     println!("{} stalled {}ms on {}", stall.unit, stall.delta_usec / 1000, stall.resource);
//! }
//! ```

use std::time::Duration;

pub mod attribution;
pub mod cgroup;
pub mod ipc;
pub mod pathology;
pub mod process;
pub mod psi;
pub mod ring;

pub use pathology::{Severity, Warning};
pub use psi::{PsiKind, Resource};

/// One unit's stall over one observation window.
///
/// This is the wire schema. Field names and semantics are deliberately aligned
/// with the conventions the container ecosystem already settled on — Kubernetes
/// and cAdvisor expose `container_pressure_{cpu,memory,io}_{waiting,stalled}`,
/// where `waiting` is PSI `some` and `stalled` is PSI `full`. Anything ingesting
/// those metrics should find nothing surprising here.
#[derive(Clone, Debug, PartialEq)]
pub struct Stall {
    /// Human-recognisable name: `firefox (flatpak)`, `systemd-journald`.
    pub unit: String,
    /// Raw cgroup v2 path the figure was read from. The audit trail — a caller
    /// should always be able to re-read the kernel and check our arithmetic.
    pub cgroup: String,
    pub resource: Resource,
    /// `Some` = at least one task blocked. `Full` = every non-idle task blocked.
    pub kind: PsiKind,
    /// Microseconds stalled during the window.
    pub delta_usec: u64,
    /// `delta_usec / window_usec * 100`.
    pub pressure_pct: f64,
    /// Worst single sampling tick inside the window.
    ///
    /// Load-bearing for anything aggregated. A two-second total freeze inside a
    /// sixty-second window averages to ~3%, which reads as "nothing happened" —
    /// the same damping that makes the kernel's own `avg300` useless for
    /// catching short stalls. The peak preserves the event.
    ///
    /// For a single-tick observation this equals `pressure_pct`.
    pub peak_pct: f64,
}

/// The result of one observation window.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Measured wall-clock length of the window, not the requested length.
    /// Sampling thousands of cgroups takes real time and the caller's numbers
    /// should reflect what actually elapsed.
    pub window_usec: u64,
    /// Responsible units, worst first, capped at [`MAX_STALLS`].
    pub stalls: Vec<Stall>,
    /// System conditions that explain stalls the pressure numbers cannot.
    pub warnings: Vec<Warning>,
}

/// Ignore anything under this share of the window. Below ~1% is indistinguishable
/// from scheduling noise on an idle desktop and only adds clutter.
pub const MIN_REPORTABLE_PCT: f64 = 1.0;

/// Cap on reported stalls. A human reading a diagnostic wants the culprits, not
/// a census.
pub const MAX_STALLS: usize = 10;

/// Sample the system over `window` and return what stalled and why.
///
/// Blocks for `window`. Cost is two passes over the cgroup tree plus a handful
/// of small sysfs reads — microseconds of CPU either side of the sleep.
pub fn observe(window: Duration) -> Report {
    let (stalls, window_usec) = attribution::collect(window);
    Report {
        window_usec,
        stalls,
        warnings: pathology::scan(),
    }
}

/// Is PSI available at all?
///
/// `CONFIG_PSI=y` is the norm, but distributions that build with
/// `CONFIG_PSI_DEFAULT_DISABLED=y` (openSUSE, historically) need `psi=1` on the
/// kernel command line. Callers should check this before reporting "no stalls",
/// which would otherwise be indistinguishable from "cannot see stalls".
pub fn psi_available() -> bool {
    std::path::Path::new("/proc/pressure").exists()
}

impl Report {
    /// Serialise to JSON without pulling in serde.
    ///
    /// Zero dependencies is a load-bearing property: the engine is meant to be
    /// consumable by C and C++ projects that will not accept a Rust crate graph
    /// in their build. Hand-rolling one small writer keeps that door open.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256 + self.stalls.len() * 200);
        s.push_str("{\n  \"window_usec\": ");
        s.push_str(&self.window_usec.to_string());
        s.push_str(",\n  \"stalls\": [\n");
        for (i, st) in self.stalls.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"unit\": {}, \"cgroup\": {}, \"resource\": \"{}\", \"type\": \"{}\", \
                 \"delta_usec\": {}, \"pressure_pct\": {:.2}, \"peak_pct\": {:.2}}}{}\n",
                json_str(&st.unit),
                json_str(&st.cgroup),
                st.resource,
                st.kind,
                st.delta_usec,
                st.pressure_pct,
                st.peak_pct,
                if i + 1 == self.stalls.len() { "" } else { "," }
            ));
        }
        s.push_str("  ],\n  \"warnings\": [\n");
        for (i, w) in self.warnings.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"source\": {}, \"severity\": \"{}\", \"transient\": {}, \"message\": {}}}{}\n",
                json_str(&w.source),
                w.severity,
                w.transient,
                json_str(&w.message),
                if i + 1 == self.warnings.len() { "" } else { "," }
            ));
        }
        s.push_str("  ]\n}");
        s
    }
}

impl Report {
    /// Render for a human reading a terminal.
    ///
    /// Lives in the library, not the CLI: the daemon renders this too, so a
    /// client with no JSON parser can still ask for readable output, and every
    /// frontend shows identical wording rather than three drifting copies.
    pub fn to_text(&self) -> String {
        let mut o = String::new();
        let secs = self.window_usec as f64 / 1e6;

        if self.stalls.is_empty() {
            o.push_str(&format!(
                "No significant stalls in the last {secs:.1}s. System is responsive.\n"
            ));
        } else {
            o.push_str(&format!(
                "Over the last {secs:.1}s, these units stalled the system:\n\n"
            ));
            for s in &self.stalls {
                // Show the peak only when it differs meaningfully from the
                // average, i.e. on aggregated history. On a single tick they
                // are equal and printing both is just noise.
                let peak = if s.peak_pct - s.pressure_pct > 0.5 {
                    format!("   (worst tick {:.0}%)", s.peak_pct)
                } else {
                    String::new()
                };
                o.push_str(&format!(
                    "  {:>6.1}%  {:<7} {}  — frozen {:.0}ms waiting on {}{}\n",
                    s.pressure_pct,
                    s.resource.to_string(),
                    s.unit,
                    s.delta_usec as f64 / 1000.0,
                    s.resource,
                    peak
                ));
            }
            o.push_str(&format!("\n  worst cgroup: {}\n", self.stalls[0].cgroup));
        }

        for w in &self.warnings {
            let marker = match w.severity {
                Severity::Critical => "!!",
                Severity::Warn => " !",
                Severity::Note => " \u{b7}",
            };
            let tag = if w.transient { " [transient]" } else { "" };
            o.push_str(&format!("\n  {marker} {}{tag}: {}\n", w.source, w.message));
        }
        o
    }
}

/// Minimal RFC 8259 string escaping. Cgroup paths can legitimately contain
/// backslashes (systemd's `\x2d` encoding), so this is not theoretical.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_systemd_backslash_encoding() {
        assert_eq!(json_str(r"app\x2dfoo"), r#""app\\x2dfoo""#);
        assert_eq!(json_str("a\"b"), r#""a\"b""#);
        assert_eq!(json_str("a\nb"), r#""a\nb""#);
    }

    #[test]
    fn empty_report_is_valid_json_shape() {
        let j = Report::default().to_json();
        assert!(j.starts_with('{') && j.ends_with('}'), "{j}");
        assert!(j.contains("\"stalls\": [") && j.contains("\"warnings\": ["), "{j}");
    }

    #[test]
    fn report_json_includes_stall_fields() {
        let r = Report {
            window_usec: 1_000_000,
            stalls: vec![Stall {
                unit: "systemd-journald".into(),
                cgroup: "/sys/fs/cgroup/system.slice/systemd-journald.service".into(),
                resource: Resource::Io,
                kind: PsiKind::Full,
                delta_usec: 250_000,
                pressure_pct: 25.0,
                peak_pct: 40.0,
            }],
            warnings: vec![],
        };
        let j = r.to_json();
        assert!(j.contains("\"resource\": \"io\""), "{j}");
        assert!(j.contains("\"type\": \"full\""), "{j}");
        assert!(j.contains("\"pressure_pct\": 25.00"), "{j}");
        assert!(j.contains("\"peak_pct\": 40.00"), "{j}");
    }
}
