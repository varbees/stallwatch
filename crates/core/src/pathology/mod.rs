//! The "why" layer: system conditions that explain stalls the numbers cannot.
//!
//! Attribution answers *who*. This answers *why*, and it is where the tool
//! stops being another pressure gauge. A cgroup can be stalling on IO because
//! the filesystem allocator is exhausted, because the drive is throttling,
//! or because the kernel is chewing through background TRIM — three completely
//! different problems that look identical in PSI, and none of which any desktop
//! monitor surfaces.
//!
//! # The rule these checks are built around
//!
//! **Do not claim causation from a correlated observation.**
//!
//! This was learned the expensive way. An early version of the thermal check
//! saw a drive sensor reading 97 °C, concluded "thermal throttling is causing
//! your IO stalls", and said so with confidence. The drive's own counters —
//! `Thermal Management T1/T2 Trans Count`, `Warning Temperature Time` — were
//! all zero across 4,979 power-on hours. It had never throttled once. The
//! sensor was real; the mechanism was plausible; the conclusion was wrong, and
//! it sent a real investigation down a dead end for hours.
//!
//! Worse, that heuristic would have fired on every healthy drive of the same
//! family, which is the textbook way a diagnostic loses its users' trust.
//!
//! So: report what is observed, name the command that would confirm or refute
//! it, and let the human draw the conclusion.

use std::fmt;

pub mod btrfs;
pub mod thermal;

/// How much attention a finding deserves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Worth knowing; explicitly not a diagnosis.
    Note,
    /// Likely relevant to a stall being investigated.
    Warn,
    /// A condition that is degrading the system now.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Note => "note",
            Severity::Warn => "warn",
            Severity::Critical => "critical",
        })
    }
}

/// One explanatory finding about system state.
#[derive(Clone, Debug, PartialEq)]
pub struct Warning {
    /// Subsystem it came from: `btrfs`, `nvme`.
    pub source: String,
    pub severity: Severity,
    /// True when the condition clears on its own. Distinguishing "this will
    /// stop by itself in three minutes" from "this needs you to act" is most
    /// of the value of an explanation.
    pub transient: bool,
    /// Plain prose. Written to be read by someone who is annoyed and in a
    /// hurry, not by a monitoring system.
    pub message: String,
}

/// Run every pathology check.
///
/// Ordered deliberately: storage conditions first, because they explain the
/// overwhelming majority of desktop IO stalls, and thermal last, because it is
/// the one most likely to be a red herring.
pub fn scan() -> Vec<Warning> {
    let mut out = btrfs::check();
    out.extend(thermal::check());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_renders_for_the_wire() {
        assert_eq!(Severity::Note.to_string(), "note");
        assert_eq!(Severity::Warn.to_string(), "warn");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn scan_never_panics_on_this_machine() {
        // Whatever the host filesystem and hardware, scanning must be
        // infallible — a diagnostic that crashes while diagnosing is worthless.
        let _ = scan();
    }
}
