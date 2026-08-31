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
//! let report = stallwatch_core::observe(Duration::from_secs(1));
//! for stall in &report.stalls {
//!     println!("{} stalled {}ms on {}", stall.unit, stall.delta_usec / 1000, stall.resource);
//! }
//! ```

use std::time::Duration;

pub mod appname;
pub mod attribution;
pub mod cgroup;
pub mod config;
pub mod doctor;
pub mod filter;
pub mod incident;
pub mod iostat;
pub mod ipc;
pub mod json;
pub mod logfile;
pub mod metrics;
pub mod notify;
pub mod pathology;
pub mod process;
pub mod psi;
pub mod ring;
pub mod trigger;
pub mod varlink;

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

/// Whether a cgroup was doing the work or suffering it.
///
/// Pressure alone cannot express this. It measures who was *blocked*, so a
/// process saturating a queue registers almost no pressure while the terminal
/// it starved registers 90%. Reporting pressure alone names the casualty.
/// Pairing pressure with [`iostat`] bytes is what separates the two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Moved real bytes and was barely blocked: this is the one to act on.
    Cause,
    /// Was blocked and moved nothing: collateral damage.
    Victim,
    /// Both, or neither clearly. Named honestly rather than forced into a
    /// verdict the evidence does not support.
    Active,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Cause => "cause",
            Role::Victim => "victim",
            Role::Active => "active",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A cgroup that moved block-layer bytes during the window.
///
/// The complement of [`Stall`]. A stall says who was frozen; this says who was
/// working. The culprit is usually in this list and absent from that one.
#[derive(Clone, Debug, PartialEq)]
pub struct Cause {
    pub unit: String,
    pub cgroup: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
    /// Discard (TRIM) bytes, reported separately because they are kernel-side
    /// cleanup rather than work the cgroup can be asked to stop doing.
    pub discard_bytes: u64,
    /// This cgroup's *own* IO stall. Low here alongside high bytes is the
    /// signature of a cause; high here with no bytes is a victim.
    pub pressure_pct: f64,
    pub role: Role,
}

impl Cause {
    pub fn bytes(&self) -> u64 {
        self.read_bytes.saturating_add(self.write_bytes)
    }

    /// Can this cgroup be *named* as the thing to go and deal with?
    ///
    /// The root cgroup aggregates everything on the machine, so it always has
    /// the largest byte count and is never an answer — "the whole system wrote
    /// 108 MiB" tells a person nothing they can act on. It stays in the list as
    /// context, because a large root figure with small children is itself a
    /// finding (the IO is kernel-side, or in cgroups with no `io.stat`), but it
    /// is never the accusation.
    pub fn is_nameable(&self) -> bool {
        self.cgroup != cgroup::ROOT
    }

    /// Classify from evidence.
    ///
    /// Thresholds are deliberately asymmetric. A cgroup must move real bytes
    /// *and* be mostly unblocked to be accused; anything ambiguous is
    /// [`Role::Active`], which says "present, verdict unsupported" rather than
    /// inventing one. The previous version of this rule read process bytes
    /// from `/proc/<pid>/io`, which is unreadable for other users' processes —
    /// so the cause branch never executed once across 520,155 real incidents.
    pub fn classify(bytes: u64, pressure_pct: f64) -> Role {
        let enough = bytes >= MIN_CAUSE_BYTES;
        if enough && pressure_pct < CAUSE_MAX_PRESSURE_PCT {
            Role::Cause
        } else if !enough && pressure_pct >= CAUSE_MAX_PRESSURE_PCT {
            Role::Victim
        } else {
            Role::Active
        }
    }
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
    /// Cgroups that moved bytes during the window, biggest first.
    ///
    /// Separate from `stalls` because the culprit is usually not stalled at
    /// all — that is the entire reason a pressure-only report misleads.
    pub causes: Vec<Cause>,
    /// System conditions that explain stalls the pressure numbers cannot.
    pub warnings: Vec<Warning>,
}

/// Ignore anything under this share of the window. Below ~1% is indistinguishable
/// from scheduling noise on an idle desktop and only adds clutter.
pub const MIN_REPORTABLE_PCT: f64 = 1.0;

/// Bytes a cgroup must move before it can be called a cause.
///
/// Below a mebibyte is indistinguishable from a config read or a log line on
/// any real desktop, and accusing something of stalling the machine over 40 KiB
/// is how a diagnostic loses a user's trust permanently.
pub const MIN_CAUSE_BYTES: u64 = 1024 * 1024;

/// A cause must be *mostly unblocked*. Above this it is competing for the
/// device too, and calling it a cause overstates what the evidence supports.
pub const CAUSE_MAX_PRESSURE_PCT: f64 = 50.0;

/// Cap on reported causes, for the same reason as [`MAX_STALLS`].
pub const MAX_CAUSES: usize = 10;

/// Cap on reported stalls. A human reading a diagnostic wants the culprits, not
/// a census.
pub const MAX_STALLS: usize = 10;

/// Sample the system over `window` and return what stalled and why.
///
/// Blocks for `window`. Cost is two passes over the cgroup tree plus a handful
/// of small sysfs reads — microseconds of CPU either side of the sleep.
pub fn observe(window: Duration) -> Report {
    let (stalls, causes, window_usec) = attribution::collect(window);
    Report {
        window_usec,
        stalls,
        causes,
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
        s.push_str("  ],\n  \"causes\": [\n");
        for (i, c) in self.causes.iter().enumerate() {
            s.push_str(&format!(
                "    {{\"unit\": {}, \"cgroup\": {}, \"read_bytes\": {}, \"write_bytes\": {}, \
                 \"discard_bytes\": {}, \"pressure_pct\": {:.2}, \"role\": \"{}\"}}{}\n",
                json_str(&c.unit),
                json_str(&c.cgroup),
                c.read_bytes,
                c.write_bytes,
                c.discard_bytes,
                c.pressure_pct,
                c.role,
                if i + 1 == self.causes.len() { "" } else { "," }
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
    /// Single-line JSON, for protocols that frame one document per message.
    ///
    /// Same field names as [`Report::to_json`] by construction rather than by
    /// convention — two renderers that can drift are two schemas.
    pub fn to_json_compact(&self) -> String {
        let stalls: Vec<String> = self
            .stalls
            .iter()
            .map(|s| {
                format!(
                    r#"{{"unit":{},"cgroup":{},"resource":"{}","type":"{}","delta_usec":{},"pressure_pct":{:.2},"peak_pct":{:.2}}}"#,
                    json_str(&s.unit),
                    json_str(&s.cgroup),
                    s.resource,
                    s.kind,
                    s.delta_usec,
                    s.pressure_pct,
                    s.peak_pct
                )
            })
            .collect();
        let warnings: Vec<String> = self
            .warnings
            .iter()
            .map(|w| {
                format!(
                    r#"{{"source":{},"severity":"{}","transient":{},"message":{}}}"#,
                    json_str(&w.source),
                    w.severity,
                    w.transient,
                    json_str(&w.message)
                )
            })
            .collect();
        let causes: Vec<String> = self
            .causes
            .iter()
            .map(|c| {
                format!(
                    r#"{{"unit":{},"cgroup":{},"read_bytes":{},"write_bytes":{},"discard_bytes":{},"pressure_pct":{:.2},"role":"{}"}}"#,
                    json_str(&c.unit),
                    json_str(&c.cgroup),
                    c.read_bytes,
                    c.write_bytes,
                    c.discard_bytes,
                    c.pressure_pct,
                    c.role
                )
            })
            .collect();
        format!(
            r#"{{"window_usec":{},"stalls":[{}],"causes":[{}],"warnings":[{}]}}"#,
            self.window_usec,
            stalls.join(","),
            causes.join(","),
            warnings.join(",")
        )
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

        // Who was doing the work. This is the half a pressure-only report
        // cannot show, and the half the reader actually needs: the worst-hit
        // unit above is usually the casualty.
        //
        // Rank on bytes, not on role. A process saturating a device is itself
        // blocked once the device is saturated — that is what saturation means
        // — so gating the headline on `role == Cause` hides the biggest writer
        // exactly when it matters most. Measured: a `dd` writing 1.5 GiB was
        // classified `Active` because its own fsync blocked it, and a 21 MiB
        // journald write took the headline. Role is reported as nuance.
        if let Some(top) = self.causes.iter().find(|c| c.is_nameable()) {
            let qualifier = match top.role {
                Role::Cause => format!("and was barely blocked itself ({:.0}%)", top.pressure_pct),
                Role::Active => format!(
                    "and was contended too ({:.0}%), so it is competing rather than simply winning",
                    top.pressure_pct
                ),
                Role::Victim => {
                    "but was mostly blocked, so it is likely a casualty too".to_string()
                }
            };
            o.push_str(&format!(
                "\n  most of the IO: {} moved {} {}\n",
                top.unit,
                bytes_phrase(top.bytes()),
                qualifier
            ));
            let others: Vec<&Cause> = self
                .causes
                .iter()
                .filter(|c| c.cgroup != top.cgroup && c.is_nameable())
                .take(2)
                .collect();
            if !others.is_empty() {
                let names: Vec<String> = others
                    .iter()
                    .map(|c| format!("{} ({})", c.unit, bytes_phrase(c.bytes())))
                    .collect();
                o.push_str(&format!("  also moving data: {}\n", names.join(", ")));
            }
            // A root figure much larger than anything nameable means the work
            // is happening where we cannot attribute it. Say so plainly rather
            // than letting the reader assume the named unit is the whole story.
            if let Some(root) = self.causes.iter().find(|c| !c.is_nameable())
                && root.bytes() > top.bytes().saturating_mul(2)
            {
                o.push_str(&format!(
                    "  system-wide total was {}, so most of this is kernel-side or in\n                       cgroups with no io.stat — not attributable to a unit.\n",
                    bytes_phrase(root.bytes())
                ));
            }
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

/// Render a byte count the way a person says it out loud.
pub fn bytes_phrase(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KIB * KIB * KIB {
        format!("{:.1} GiB", b / (KIB * KIB * KIB))
    } else if b >= KIB * KIB {
        format!("{:.0} MiB", b / (KIB * KIB))
    } else if b >= KIB {
        format!("{:.0} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// Minimal RFC 8259 string escaping. Cgroup paths can legitimately contain
/// backslashes (systemd's `\x2d` encoding), so this is not theoretical.
pub(crate) fn json_str(s: &str) -> String {
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

    fn cause(unit: &str, cgroup: &str, bytes: u64, pressure: f64) -> Cause {
        Cause {
            unit: unit.into(),
            cgroup: cgroup.into(),
            read_bytes: 0,
            write_bytes: bytes,
            discard_bytes: 0,
            pressure_pct: pressure,
            role: Cause::classify(bytes, pressure),
        }
    }

    #[test]
    fn classify_needs_real_bytes_and_an_unblocked_mover() {
        let mib = 1024 * 1024;
        assert_eq!(Cause::classify(5 * mib, 10.0), Role::Cause);
        assert_eq!(Cause::classify(0, 90.0), Role::Victim);
        // Moving data AND blocked: competing, not clearly at fault.
        assert_eq!(Cause::classify(5 * mib, 90.0), Role::Active);
        // Neither: no verdict.
        assert_eq!(Cause::classify(0, 10.0), Role::Active);
    }

    #[test]
    fn a_trickle_is_never_a_cause() {
        // 40 KiB is a config read, not a reason your machine froze.
        assert_ne!(Cause::classify(40 * 1024, 0.0), Role::Cause);
    }

    #[test]
    fn the_root_cgroup_is_never_nameable() {
        assert!(!cause("whole system", cgroup::ROOT, 1 << 30, 5.0).is_nameable());
        assert!(
            cause(
                "journald",
                "/sys/fs/cgroup/system.slice/x.service",
                1 << 20,
                5.0
            )
            .is_nameable()
        );
    }

    #[test]
    fn the_headline_names_the_biggest_mover_even_when_it_is_contended() {
        // Regression: a dd writing 1.5 GiB was classified Active because its
        // own fsync blocked it, so a 21 MiB journald write took the headline.
        // Saturation blocks the saturator; ranking must be on bytes.
        let r = Report {
            window_usec: 1_000_000,
            stalls: vec![],
            causes: vec![
                cause(
                    "bigwriter",
                    "/sys/fs/cgroup/app.slice/big.scope",
                    1_500 * 1024 * 1024,
                    90.0,
                ),
                cause(
                    "systemd-journald",
                    "/sys/fs/cgroup/system.slice/j.service",
                    21 * 1024 * 1024,
                    11.0,
                ),
            ],
            warnings: vec![],
        };
        let text = r.to_text();
        assert!(text.contains("bigwriter"), "{text}");
        assert!(text.contains("contended too"), "{text}");
        let head = text.find("bigwriter").unwrap();
        let other = text.find("systemd-journald").unwrap();
        assert!(head < other, "biggest mover must lead:\n{text}");
    }

    #[test]
    fn root_never_takes_the_headline_but_is_reported_as_context() {
        let r = Report {
            window_usec: 1_000_000,
            stalls: vec![],
            causes: vec![
                cause(
                    "whole system (root cgroup)",
                    cgroup::ROOT,
                    500 * 1024 * 1024,
                    40.0,
                ),
                cause(
                    "journald",
                    "/sys/fs/cgroup/system.slice/j.service",
                    10 * 1024 * 1024,
                    5.0,
                ),
            ],
            warnings: vec![],
        };
        let text = r.to_text();
        assert!(text.contains("most of the IO: journald"), "{text}");
        assert!(
            text.contains("kernel-side"),
            "root context missing:\n{text}"
        );
    }

    #[test]
    fn causes_reach_both_json_renderers() {
        let r = Report {
            window_usec: 1_000_000,
            stalls: vec![],
            causes: vec![cause(
                "journald",
                "/sys/fs/cgroup/system.slice/j.service",
                2 * 1024 * 1024,
                5.0,
            )],
            warnings: vec![],
        };
        for j in [r.to_json(), r.to_json_compact()] {
            assert!(j.contains("\"causes\""), "{j}");
            assert!(
                j.contains("\"role\": \"cause\"") || j.contains("\"role\":\"cause\""),
                "{j}"
            );
            assert!(j.contains("2097152"), "{j}");
        }
    }

    #[test]
    fn bytes_phrase_reads_like_a_person() {
        assert_eq!(bytes_phrase(512), "512 B");
        assert_eq!(bytes_phrase(2048), "2 KiB");
        assert_eq!(bytes_phrase(5 * 1024 * 1024), "5 MiB");
        assert_eq!(bytes_phrase(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

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
        assert!(
            j.contains("\"stalls\": [") && j.contains("\"warnings\": ["),
            "{j}"
        );
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
            causes: vec![],
        };
        let j = r.to_json();
        assert!(j.contains("\"resource\": \"io\""), "{j}");
        assert!(j.contains("\"type\": \"full\""), "{j}");
        assert!(j.contains("\"pressure_pct\": 25.00"), "{j}");
        assert!(j.contains("\"peak_pct\": 40.00"), "{j}");
    }
}
