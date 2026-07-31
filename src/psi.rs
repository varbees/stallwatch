//! Reading and parsing kernel Pressure Stall Information.
//!
//! Every PSI file — `/proc/pressure/{cpu,memory,io}` and the per-cgroup
//! `{cpu,memory,io}.pressure` — has the same shape:
//!
//! ```text
//! some avg10=77.92 avg60=81.60 avg300=86.31 total=61110128878
//! full avg10=61.09 avg60=68.36 avg300=71.82 total=57620142644
//! ```
//!
//! We take `total` and ignore the averages entirely. See [`crate`] for why.

use std::fmt;

/// Which resource tasks are blocked on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resource {
    Cpu,
    Memory,
    Io,
}

impl Resource {
    pub(crate) fn file(self) -> &'static str {
        match self {
            Resource::Cpu => "cpu.pressure",
            Resource::Memory => "memory.pressure",
            Resource::Io => "io.pressure",
        }
    }

    pub const ALL: [Resource; 3] = [Resource::Cpu, Resource::Memory, Resource::Io];

    /// Which line carries the meaningful signal for this resource.
    ///
    /// `full` — every non-idle task blocked simultaneously — is the honest
    /// measure of "the machine stopped". But CPU pressure has no `full` line:
    /// if a task is waiting for CPU then by definition another task is running
    /// on it, so total starvation is impossible by construction. For CPU we
    /// therefore have to use `some`.
    pub fn primary_kind(self) -> PsiKind {
        match self {
            Resource::Cpu => PsiKind::Some,
            _ => PsiKind::Full,
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Resource::Cpu => "cpu",
            Resource::Memory => "memory",
            Resource::Io => "io",
        })
    }
}

/// Which PSI line a figure came from.
///
/// Named to match the Kubernetes/cAdvisor vocabulary, where `some` is surfaced
/// as "waiting" and `full` as "stalled".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PsiKind {
    /// At least one task was blocked.
    Some,
    /// Every non-idle task was blocked at once.
    Full,
}

impl fmt::Display for PsiKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PsiKind::Some => "some",
            PsiKind::Full => "full",
        })
    }
}

/// Cumulative microseconds stalled, as reported by one PSI file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Psi {
    pub some_total_us: u64,
    pub full_total_us: u64,
}

impl Psi {
    pub fn total_for(&self, kind: PsiKind) -> u64 {
        match kind {
            PsiKind::Some => self.some_total_us,
            PsiKind::Full => self.full_total_us,
        }
    }
}

/// All three resources for one cgroup at one instant.
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    pub cpu: Psi,
    pub memory: Psi,
    pub io: Psi,
}

impl Snapshot {
    pub fn get(&self, r: Resource) -> Psi {
        match r {
            Resource::Cpu => self.cpu,
            Resource::Memory => self.memory,
            Resource::Io => self.io,
        }
    }

    pub(crate) fn set(&mut self, r: Resource, p: Psi) {
        match r {
            Resource::Cpu => self.cpu = p,
            Resource::Memory => self.memory = p,
            Resource::Io => self.io = p,
        }
    }
}

/// Parse a PSI file body.
///
/// Tolerant by design: a missing `full` line is normal for CPU and on older
/// kernels, and a malformed line should not take down a diagnostic tool.
pub fn parse(body: &str) -> Psi {
    let mut psi = Psi::default();
    for line in body.lines() {
        let mut parts = line.split_whitespace();
        let Some(kind) = parts.next() else { continue };
        let total = parts
            .find_map(|f| f.strip_prefix("total=")?.parse::<u64>().ok())
            .unwrap_or(0);
        match kind {
            "some" => psi.some_total_us = total,
            "full" => psi.full_total_us = total,
            _ => {}
        }
    }
    psi
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_lines() {
        let psi = parse(
            "some avg10=77.92 avg60=81.60 avg300=86.31 total=61110128878\n\
             full avg10=61.09 avg60=68.36 avg300=71.82 total=57620142644\n",
        );
        assert_eq!(psi.some_total_us, 61_110_128_878);
        assert_eq!(psi.full_total_us, 57_620_142_644);
    }

    #[test]
    fn tolerates_missing_full_line() {
        let psi = parse("some avg10=0.86 avg60=0.73 avg300=1.03 total=447479420\n");
        assert_eq!(psi.some_total_us, 447_479_420);
        assert_eq!(psi.full_total_us, 0);
    }

    #[test]
    fn tolerates_garbage_without_panicking() {
        assert_eq!(parse(""), Psi::default());
        assert_eq!(parse("\n\n"), Psi::default());
        assert_eq!(parse("some"), Psi::default());
        assert_eq!(parse("some total=notanumber"), Psi::default());
    }

    #[test]
    fn cpu_uses_some_because_full_cannot_exist_for_it() {
        assert_eq!(Resource::Cpu.primary_kind(), PsiKind::Some);
        assert_eq!(Resource::Io.primary_kind(), PsiKind::Full);
        assert_eq!(Resource::Memory.primary_kind(), PsiKind::Full);
    }

    #[test]
    fn display_matches_wire_vocabulary() {
        assert_eq!(Resource::Io.to_string(), "io");
        assert_eq!(PsiKind::Full.to_string(), "full");
    }
}
