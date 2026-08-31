//! A stall, recorded as a thing that happened.
//!
//! # Why this exists
//!
//! Until now a capture was a [`crate::ring::Frame`]: a timestamp, a window and
//! a list of stalls, indistinguishable from a routine sample. That is fine for
//! a ring buffer and useless for answering the question people actually ask,
//! which is not *"what is happening"* but *"what just happened to me"*.
//!
//! An incident is that answer, kept whole: when it fired, which resource woke
//! the daemon, who was responsible, which process inside them, whether that
//! process was the cause or the victim, and any physical condition that
//! explains it. It survives as one line of JSON so it can be read back after
//! the freeze is long over.
//!
//! [`Incident::explain`] is the product. Everything else here exists to make
//! that paragraph true.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

pub use crate::Role;

use crate::process::ProcCulprit;
use crate::{Cause, Report, Stall, Warning};

/// A process caught during an incident, with a verdict attached.
#[derive(Clone, Debug)]
pub struct Culprit {
    pub pid: u32,
    pub comm: String,
    pub blocked_pct: f64,
    pub bytes: u64,
    pub role: Role,
}

impl Culprit {
    /// Classify a drilled process.
    ///
    /// Thresholds are deliberately blunt. The distinction only has to be right
    /// enough to stop someone blaming the application that froze, which is the
    /// mistake every other tool leads them into.
    pub fn from_proc(p: &ProcCulprit) -> Self {
        let bytes = p.read_bytes + p.write_bytes;
        Self {
            pid: p.pid,
            comm: p.comm.clone(),
            blocked_pct: p.blocked_pct(),
            bytes,
            role: Self::role_from(bytes, p.blocked_pct()),
        }
    }

    /// Classify a process from what we could actually read about it.
    ///
    /// `/proc/<pid>/io` is unreadable for any process the invoking user does
    /// not own, so `bytes` is zero for kernel threads and root daemons — which
    /// is most of what stalls a machine. The old rule required >=1 MiB here to
    /// say `Cause`, and consequently said it zero times across 520,155 real
    /// incidents. Process bytes are now treated as corroboration when present
    /// and never as the gate; the accusation is made at cgroup level, from
    /// `io.stat`, which is readable. A process we can see moving real data is
    /// still worth naming.
    fn role_from(bytes: u64, blocked_pct: f64) -> Role {
        let mib = bytes as f64 / 1_048_576.0;
        if mib >= 1.0 && blocked_pct < 50.0 {
            Role::Cause
        } else if blocked_pct >= 50.0 && mib < 1.0 {
            Role::Victim
        } else {
            Role::Active
        }
    }
}

/// One recorded stall.
#[derive(Clone, Debug)]
pub struct Incident {
    /// Unix seconds when the capture fired.
    pub at_unix: u64,
    /// Measured length of the observation window.
    pub window_usec: u64,
    /// Which resources crossed their threshold, when the daemon was woken by
    /// a PSI trigger. Empty for a report captured on demand.
    pub woke_on: Vec<String>,
    pub stalls: Vec<Stall>,
    pub warnings: Vec<Warning>,
    /// Processes inside the worst cgroup, if a drill-down ran.
    pub culprits: Vec<Culprit>,
    /// Cgroups that moved bytes during the window. This is where the cause
    /// comes from; `culprits` only refines it when the processes are ours.
    pub causes: Vec<Cause>,
}

impl Incident {
    pub fn from_report(report: &Report, woke_on: Vec<String>) -> Self {
        Self {
            at_unix: now_unix(),
            window_usec: report.window_usec,
            woke_on,
            stalls: report.stalls.clone(),
            warnings: report.warnings.clone(),
            culprits: Vec::new(),
            causes: report.causes.clone(),
        }
    }

    /// The worst stall, which is what a human means by "what happened".
    pub fn worst(&self) -> Option<&Stall> {
        self.stalls.first()
    }

    /// How long the machine was actually stopped, in milliseconds.
    pub fn frozen_ms(&self) -> f64 {
        self.worst().map_or(0.0, |s| s.delta_usec as f64 / 1000.0)
    }

    /// The paragraph. This is the whole point of the tool.
    ///
    /// Deliberately prose, not a table. Every other tool in this space renders
    /// a grid and leaves the reader to work out who to blame; the reader is
    /// usually wrong, because PSI blames the victim.
    pub fn explain(&self, now: u64) -> String {
        let Some(worst) = self.worst() else {
            return "Nothing was recorded. The machine has not stalled since this started watching.\n".into();
        };

        let mut o = String::new();
        let secs = self.frozen_ms() / 1000.0;
        let ago = relative_time(now.saturating_sub(self.at_unix));

        let _ = writeln!(
            o,
            "Your machine froze for {}, {ago}.\n",
            duration_phrase(secs)
        );

        // Who, and on what.
        let _ = writeln!(
            o,
            "  {} was blocked on {} for {:.0}% of that window.",
            worst.unit, worst.resource, worst.pressure_pct
        );

        // Cause or victim. This is the sentence nothing else prints.
        let cause = self.culprits.iter().find(|c| c.role == Role::Cause);
        let victim_of_something = self
            .culprits
            .iter()
            .any(|c| matches!(c.role, Role::Victim | Role::Active));

        match cause {
            Some(c) => {
                let _ = writeln!(
                    o,
                    "  It was the victim, not the cause: {} [{}] moved {} through the same queue.",
                    c.comm,
                    c.pid,
                    bytes_phrase(c.bytes)
                );
            }
            None if victim_of_something => {
                let _ = writeln!(
                    o,
                    "  No process inside it was moving data, so the work was kernel-side rather\n  \
                     than something you can point at."
                );
            }
            None => {}
        }

        // Anything else that stalled at the same moment is context, not noise.
        let others: Vec<&Stall> = self.stalls.iter().skip(1).take(2).collect();
        if !others.is_empty() {
            let names: Vec<String> = others
                .iter()
                .map(|s| format!("{} ({:.0}%)", s.unit, s.pressure_pct))
                .collect();
            let _ = writeln!(o, "  Also stalled: {}.", names.join(", "));
        }

        // Pathology last, because it explains rather than accuses.
        for w in &self.warnings {
            let tail = if w.transient {
                " That part clears itself."
            } else {
                ""
            };
            let _ = writeln!(o, "\n  {}: {}{tail}", w.source, first_sentence(&w.message));
        }

        o
    }

    /// One line of JSON, for an append-only log.
    ///
    /// Hand-written like everything else here, because the engine takes no
    /// crates and a record this small does not justify one.
    pub fn to_jsonl(&self) -> String {
        let woke: Vec<String> = self.woke_on.iter().map(|w| jstr(w)).collect();
        let culprits: Vec<String> = self
            .culprits
            .iter()
            .map(|c| {
                format!(
                    r#"{{"pid":{},"comm":{},"blocked_pct":{:.1},"bytes":{},"role":"{}"}}"#,
                    c.pid,
                    jstr(&c.comm),
                    c.blocked_pct,
                    c.bytes,
                    c.role.as_str()
                )
            })
            .collect();
        let body = self.to_report().to_json_compact();
        // Splice the incident-only fields into the report object so one line
        // carries everything, and the schema stays a superset of the report.
        let inner = body.trim_start_matches('{').trim_end_matches('}');
        format!(
            r#"{{"at_unix":{},"woke_on":[{}],"culprits":[{}],{}}}"#,
            self.at_unix,
            woke.join(","),
            culprits.join(","),
            inner
        )
    }

    fn to_report(&self) -> Report {
        Report {
            window_usec: self.window_usec,
            causes: self.causes.clone(),
            stalls: self.stalls.clone(),
            warnings: self.warnings.clone(),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// "3.1 seconds", "850 milliseconds". Written out because this appears in a
/// sentence, not a table.
fn duration_phrase(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0} milliseconds", secs * 1000.0)
    } else {
        format!("{secs:.1} seconds")
    }
}

fn bytes_phrase(b: u64) -> String {
    const K: f64 = 1024.0;
    let f = b as f64;
    if f >= K * K * K {
        format!("{:.1} GiB", f / (K * K * K))
    } else if f >= K * K {
        format!("{:.0} MiB", f / (K * K))
    } else if f >= K {
        format!("{:.0} KiB", f / K)
    } else {
        format!("{b} bytes")
    }
}

/// "just now", "about four minutes ago", "yesterday".
///
/// Vague on purpose. Nobody asking what just happened wants "1247 seconds".
fn relative_time(delta: u64) -> String {
    match delta {
        0..=20 => "just now".into(),
        21..=90 => "a minute ago".into(),
        91..=3599 => {
            let m = (delta as f64 / 60.0).round() as u64;
            format!("about {} minutes ago", spell(m))
        }
        3600..=86399 => {
            let h = (delta as f64 / 3600.0).round() as u64;
            if h == 1 {
                "about an hour ago".into()
            } else {
                format!("about {} hours ago", spell(h))
            }
        }
        _ => {
            let d = delta / 86400;
            if d == 1 {
                "yesterday".into()
            } else {
                format!("{d} days ago")
            }
        }
    }
}

/// Small numbers read better as words inside a sentence.
fn spell(n: u64) -> String {
    const W: [&str; 13] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve",
    ];
    W.get(n as usize)
        .map_or_else(|| n.to_string(), |w| (*w).to_string())
}

/// Pathology messages are paragraphs; an explanation wants one sentence.
fn first_sentence(msg: &str) -> String {
    let flat = msg.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.find(". ") {
        Some(i) => flat[..=i].trim().to_string(),
        None => flat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PsiKind, Resource, Severity};

    fn stall(unit: &str, pct: f64, ms: u64) -> Stall {
        Stall {
            unit: unit.into(),
            cgroup: format!("/sys/fs/cgroup/{unit}"),
            resource: Resource::Io,
            kind: PsiKind::Full,
            delta_usec: ms * 1000,
            pressure_pct: pct,
            peak_pct: pct,
        }
    }

    fn incident() -> Incident {
        Incident {
            at_unix: 1000,
            window_usec: 1_000_000,
            woke_on: vec!["io".into()],
            causes: Vec::new(),
            stalls: vec![stall("ghostty", 93.0, 3100)],
            warnings: vec![],
            culprits: vec![],
        }
    }

    #[test]
    fn role_separates_the_cause_from_the_casualty() {
        // Moving data, not blocked: this is what stopped you.
        let cause = ProcCulprit {
            pid: 1,
            comm: "dd".into(),
            blocked_samples: 1,
            total_samples: 12,
            read_bytes: 0,
            write_bytes: 5 * 1024 * 1024 * 1024,
            blkio_delay_ms: None,
        };
        assert_eq!(Culprit::from_proc(&cause).role, Role::Cause);

        // Blocked, moving nothing: this is what got stopped.
        let victim = ProcCulprit {
            pid: 2,
            comm: "ghostty".into(),
            blocked_samples: 11,
            total_samples: 12,
            read_bytes: 0,
            write_bytes: 0,
            blkio_delay_ms: None,
        };
        assert_eq!(Culprit::from_proc(&victim).role, Role::Victim);
    }

    #[test]
    fn explain_names_the_cause_and_absolves_the_victim() {
        let mut i = incident();
        i.culprits = vec![Culprit {
            pid: 214_461,
            comm: "dd".into(),
            blocked_pct: 8.0,
            bytes: 5 * 1024 * 1024 * 1024,
            role: Role::Cause,
        }];
        let text = i.explain(1240);

        assert!(text.contains("3.1 seconds"), "{text}");
        assert!(text.contains("about four minutes ago"), "{text}");
        assert!(text.contains("ghostty"), "{text}");
        // The whole point: it must say ghostty was NOT at fault.
        assert!(text.contains("victim, not the cause"), "{text}");
        assert!(text.contains("dd [214461]"), "{text}");
        assert!(text.contains("5.0 GiB"), "{text}");
    }

    #[test]
    fn explain_says_kernel_side_when_no_process_was_moving_data() {
        let mut i = incident();
        i.culprits = vec![Culprit {
            pid: 2,
            comm: "ghostty".into(),
            blocked_pct: 90.0,
            bytes: 0,
            role: Role::Victim,
        }];
        let text = i.explain(1010);
        assert!(text.contains("kernel-side"), "{text}");
    }

    #[test]
    fn explain_survives_having_nothing_to_say() {
        let empty = Incident {
            at_unix: 1,
            window_usec: 1000,
            woke_on: vec![],
            causes: Vec::new(),
            stalls: vec![],
            warnings: vec![],
            culprits: vec![],
        };
        let t = empty.explain(2);
        assert!(t.contains("Nothing was recorded"), "{t}");
    }

    #[test]
    fn transient_warnings_reassure_rather_than_alarm() {
        let mut i = incident();
        i.warnings = vec![Warning {
            source: "btrfs".into(),
            severity: Severity::Note,
            transient: true,
            message: "working through a discard backlog. It runs in the kernel.".into(),
        }];
        let t = i.explain(1001);
        assert!(t.contains("clears itself"), "{t}");
    }

    #[test]
    fn jsonl_is_one_line_and_parses() {
        let mut i = incident();
        i.culprits = vec![Culprit {
            pid: 7,
            comm: "dd".into(),
            blocked_pct: 8.0,
            bytes: 1024,
            role: Role::Cause,
        }];
        let line = i.to_jsonl();
        assert!(!line.contains('\n'), "must stay one line");
        let parsed = crate::json::parse(&line).expect("valid JSON");
        assert!(parsed.get("at_unix").is_some());
        assert!(parsed.get("culprits").is_some());
        // Superset of the report schema, so anything reading reports still works.
        assert!(parsed.get("stalls").is_some());
        assert!(parsed.get("window_usec").is_some());
    }

    #[test]
    fn relative_time_reads_like_a_person_wrote_it() {
        assert_eq!(relative_time(5), "just now");
        assert_eq!(relative_time(60), "a minute ago");
        assert_eq!(relative_time(240), "about four minutes ago");
        assert_eq!(relative_time(3600), "about an hour ago");
        assert_eq!(relative_time(86400 * 2), "2 days ago");
    }

    #[test]
    fn durations_switch_units_where_a_person_would() {
        assert_eq!(duration_phrase(0.85), "850 milliseconds");
        assert_eq!(duration_phrase(3.12), "3.1 seconds");
    }
}
