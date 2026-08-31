//! Telling you at the moment it happens, and only when it is worth saying.
//!
//! # What was wrong with the old rule
//!
//! It fired on a single capture crossing 70% peak pressure, at most once every
//! five minutes. Measured against 30 days of real recordings from one desktop —
//! 520,209 incidents — that policy would have produced **2,489 notifications**,
//! roughly one every seventeen minutes, forever. The message it produced read:
//!
//! ```text
//! com.mitchellh.ghostty froze for 405ms
//! Blocked on io for 99% of the window. (189 more since the last notice.)
//! ```
//!
//! Four things wrong with that, all fixed here.
//!
//! **"froze for 405ms" is an artifact, not a measurement.** Captures run for a
//! fixed 400ms window, so the figure is bounded by the sampling window and not
//! by the freeze. Of 520,209 recorded incidents, exactly 3 ever reported more
//! than a second. A thirty-second freeze would also have said "405ms". No
//! threshold on this number can mean anything, so none is used.
//!
//! **It named a unit, not an application.** Nobody calls it
//! `com.mitchellh.ghostty`. See [`crate::appname`].
//!
//! **It reported an instance of a chronic condition.** 189 suppressed captures
//! is the tool trying to say "this has been happening continuously for five
//! minutes" and failing. That sentence is the whole message, so it is now the
//! message.
//!
//! **It accused the victim.** The stalled unit is the casualty; the cause comes
//! from [`crate::Cause`], which is now available.
//!
//! # The rule
//!
//! Notify when the machine spent at least [`EPISODE_MIN_STALL`] of the last
//! [`EPISODE_WINDOW`] frozen — a tenth of the window — and at most once per
//! [`DEFAULT_COOLDOWN`].
//!
//! The threshold is a principle, not a curve fit: losing a tenth of your time
//! is worth being told about, and less than that is not worth interrupting for.
//! Replayed over the same 30-day corpus it fires **38 times instead of 2,489** —
//! and clusters at exact cooldown intervals, which is itself the finding: that
//! machine is not stalling occasionally, it is stalling continuously, and the
//! notification now says so instead of reporting the same condition 83 times a
//! day as though each were news.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::time::Duration;

use crate::Role;
use crate::incident::Incident;

/// How far back an episode looks.
pub const EPISODE_WINDOW: Duration = Duration::from_secs(600);

/// Total stall inside [`EPISODE_WINDOW`] before it is worth a word: a tenth of
/// the window. Below this the machine is coping; above it, a person is losing
/// meaningful time and cannot see why.
pub const EPISODE_MIN_STALL: Duration = Duration::from_secs(60);

/// Retained so existing configuration keeps parsing. Peak pressure is no longer
/// a notification gate — 70% of a 400ms capture window was cleared by 70% of
/// every stall ever recorded, which made it no filter at all.
pub const DEFAULT_MIN_PEAK: f64 = 70.0;

/// At most one notice per six hours, however bad it gets.
///
/// Five minutes was already an attempt to solve this and was two orders of
/// magnitude short: a machine with a background condition stalls for as long as
/// the condition lasts, and on the measured corpus the episode threshold is met
/// again the instant the cooldown expires. Once the message is "this is
/// chronic", repeating it hourly adds nothing and costs the user's willingness
/// to keep the tool installed.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(21_600);

/// What to say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub summary: String,
    pub body: String,
    /// Captures folded into this one notice. Reported so a caller can tell a
    /// brief episode from a relentless one; it is no longer shown to the user
    /// as a raw count, because "189 more" is a statistic, not a sentence.
    pub also_suppressed: u32,
}

/// One capture, reduced to what an episode needs.
#[derive(Clone, Copy, Debug)]
struct Beat {
    at_unix: u64,
    stalled_usec: u64,
}

/// Decides whether to speak, and holds the episode window and rate limit.
///
/// Deliberately separate from sending, so the policy is testable without a
/// desktop, a bus, or a notification daemon — which is what made it possible to
/// replay 30 days of real captures through it and count what it would have done.
#[derive(Debug)]
pub struct Notifier {
    pub enabled: bool,
    /// Kept for configuration compatibility; not a gate. See [`DEFAULT_MIN_PEAK`].
    pub min_peak: f64,
    pub cooldown: Duration,
    pub episode_window: Duration,
    pub episode_min_stall: Duration,
    last_sent_unix: Option<u64>,
    suppressed: u32,
    beats: VecDeque<Beat>,
}

impl Default for Notifier {
    fn default() -> Self {
        Self {
            enabled: true,
            min_peak: DEFAULT_MIN_PEAK,
            cooldown: DEFAULT_COOLDOWN,
            episode_window: EPISODE_WINDOW,
            episode_min_stall: EPISODE_MIN_STALL,
            last_sent_unix: None,
            suppressed: 0,
            beats: VecDeque::new(),
        }
    }
}

impl Notifier {
    /// Build one from resolved settings.
    pub fn new(enabled: bool, min_peak: f64, cooldown: Duration) -> Self {
        Self {
            enabled,
            min_peak,
            cooldown,
            ..Self::default()
        }
    }

    /// Total stall currently inside the episode window.
    fn episode_stall(&self) -> Duration {
        Duration::from_micros(self.beats.iter().map(|b| b.stalled_usec).sum())
    }

    /// Should this incident be announced, and as what?
    ///
    /// Takes `now` rather than reading the clock so the rate limit can be
    /// tested deterministically, and so a recorded corpus can be replayed
    /// through the real policy rather than an approximation of it.
    pub fn consider(&mut self, incident: &Incident, now: u64) -> Option<Notice> {
        if !self.enabled {
            return None;
        }
        let worst = incident.worst()?;

        // Say nothing when the only explanation is a condition that clears
        // itself and nobody caused.
        //
        // A notification exists to prompt a decision. "btrfs is working through
        // a discard backlog" is real, is why the machine is slow, and is not
        // actionable — the correct response is to wait. On the measured corpus
        // this alone is 70.2% of every capture.
        let kernel_side = incident.culprits.iter().all(|c| c.role != Role::Cause)
            && !incident.causes.iter().any(|c| c.is_nameable());
        let only_transient =
            !incident.warnings.is_empty() && incident.warnings.iter().all(|w| w.transient);
        if kernel_side && only_transient {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }

        // Accumulate, then judge the episode rather than this instant. A single
        // capture is 400ms of evidence about a condition that may have lasted
        // an hour; on its own it can only ever report the sampling window back.
        self.beats.push_back(Beat {
            at_unix: incident
                .at_unix
                .max(now.saturating_sub(self.episode_window.as_secs())),
            stalled_usec: worst.delta_usec,
        });
        let cutoff = now.saturating_sub(self.episode_window.as_secs());
        while self.beats.front().is_some_and(|b| b.at_unix < cutoff) {
            self.beats.pop_front();
        }

        let stalled = self.episode_stall();
        if stalled < self.episode_min_stall {
            return None;
        }

        if let Some(last) = self.last_sent_unix
            && now.saturating_sub(last) < self.cooldown.as_secs()
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }

        let also_suppressed = std::mem::take(&mut self.suppressed);
        self.last_sent_unix = Some(now);
        let captures = self.beats.len();
        let window_secs = self.episode_window.as_secs().max(1);
        let share = stalled.as_secs_f64() / window_secs as f64 * 100.0;
        self.beats.clear();

        // The summary is the finding, in the user's vocabulary: how long, how
        // much of it, and on what. Not a unit name and not a millisecond count.
        let minutes = window_secs / 60;
        let summary = format!("Your machine has been freezing for the last {minutes} minutes");

        let mut body = format!(
            "Frozen {:.0}% of that time, waiting on {}.",
            share, worst.resource
        );

        // Name the cause, not the casualty. The worst-stalled unit is what got
        // stopped; this is what stopped it.
        match incident.causes.iter().find(|c| c.is_nameable()) {
            Some(c) => {
                let _ = write!(
                    body,
                    " Most of the {} came from {} ({}).",
                    worst.resource,
                    crate::appname::human_name(&c.unit),
                    crate::bytes_phrase(c.bytes())
                );
            }
            None => {
                let _ = write!(
                    body,
                    " {} took the worst of it, but the work is kernel-side and \
                     cannot be traced to a program.",
                    crate::appname::human_name(&worst.unit)
                );
            }
        }

        // A transient condition is the difference between "do something" and
        // "wait", so it belongs in the sentence, not in a log somewhere.
        if let Some(w) = incident.warnings.iter().find(|w| w.transient) {
            let _ = write!(body, " {} is busy but clears itself.", w.source);
        }

        // Say the chronic thing as a sentence. The old "(189 more since the
        // last notice.)" was this fact, rendered as a statistic nobody can act
        // on. What matters is that it is ongoing, not how many times it ticked.
        if captures > 10 {
            let _ = write!(body, " This has been continuous, not a one-off.");
        }
        let _ = write!(body, " Run: stallwatch why");

        Some(Notice {
            summary,
            body,
            also_suppressed,
        })
    }
}

/// Send a notice to the desktop.
///
/// Shells out to `notify-send` rather than speaking D-Bus, because a D-Bus
/// client is either a dependency or a large amount of hand-rolled protocol,
/// and neither is worth it for one message. Absent on servers, which is why
/// failure here is silent by design.
pub fn send(notice: &Notice) -> bool {
    std::process::Command::new("notify-send")
        .arg("--app-name=stallwatch")
        // Normal, not critical: a critical notification on some desktops never
        // times out, and a diagnostic that requires dismissing is a diagnostic
        // people uninstall.
        .arg("--urgency=normal")
        .arg(&notice.summary)
        .arg(&notice.body)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::Culprit;
    use crate::{Cause, PsiKind, Resource, Severity, Stall, Warning};

    /// One capture: `stalled_ms` of stall inside a 400ms-ish window, at `at`.
    fn incident_at(at: u64, stalled_ms: u64) -> Incident {
        Incident {
            at_unix: at,
            window_usec: 400_000,
            woke_on: vec!["io".into()],
            stalls: vec![Stall {
                unit: "com.mitchellh.ghostty".into(),
                cgroup: "/sys/fs/cgroup/app.slice/ghostty.service".into(),
                resource: Resource::Io,
                kind: PsiKind::Full,
                delta_usec: stalled_ms * 1000,
                pressure_pct: 99.0,
                peak_pct: 99.0,
            }],
            warnings: vec![],
            culprits: vec![],
            causes: vec![],
        }
    }

    /// Feed `n` captures a second apart, each contributing `stalled_ms`.
    fn drive(n: &mut Notifier, count: u64, stalled_ms: u64, from: u64) -> Vec<Notice> {
        (0..count)
            .filter_map(|i| {
                let at = from + i;
                n.consider(&incident_at(at, stalled_ms), at)
            })
            .collect()
    }

    #[test]
    fn one_capture_says_nothing() {
        // The single most important change. A 400ms capture is evidence about a
        // condition, not the condition; the old rule shipped it as news.
        let mut n = Notifier::default();
        assert!(n.consider(&incident_at(1000, 400), 1000).is_none());
    }

    #[test]
    fn an_episode_speaks_once() {
        // 400ms per capture, one per second: 60s of stall needs 150 captures.
        let mut n = Notifier::default();
        let notices = drive(&mut n, 200, 400, 1000);
        assert_eq!(notices.len(), 1, "expected exactly one notice");
        assert!(notices[0].summary.contains("freezing"), "{:?}", notices[0]);
    }

    #[test]
    fn a_storm_produces_one_notice_not_hundreds() {
        // The measured failure: 2,489 notifications in 30 days.
        let mut n = Notifier::default();
        let notices = drive(&mut n, 3_000, 400, 1000);
        assert_eq!(
            notices.len(),
            1,
            "a six-hour cooldown must fold a 50-minute storm into one notice"
        );
    }

    #[test]
    fn the_cooldown_eventually_expires() {
        let mut n = Notifier::default();
        assert_eq!(drive(&mut n, 200, 400, 1_000).len(), 1);
        let later = 1_000 + DEFAULT_COOLDOWN.as_secs() + 10;
        assert_eq!(drive(&mut n, 200, 400, later).len(), 1);
    }

    #[test]
    fn a_brief_stall_never_reaches_the_threshold() {
        // Twenty captures is 8s of stall in a 600s window: the machine coped.
        let mut n = Notifier::default();
        assert!(drive(&mut n, 20, 400, 1000).is_empty());
    }

    #[test]
    fn stall_outside_the_window_does_not_accumulate() {
        // Captures an hour apart never form an episode, however many there are.
        let mut n = Notifier::default();
        let notices: Vec<Notice> = (0..300)
            .filter_map(|i| {
                let at = 1000 + i * 3600;
                n.consider(&incident_at(at, 400), at)
            })
            .collect();
        assert!(notices.is_empty(), "{notices:?}");
    }

    #[test]
    fn an_unactionable_transient_is_never_announced() {
        // 70.2% of the measured corpus. The right response is to wait, so
        // saying anything trains the user to dismiss the tool.
        let mut n = Notifier::default();
        let notices: Vec<Notice> = (0..500)
            .filter_map(|i| {
                let at = 1000 + i;
                let mut inc = incident_at(at, 400);
                inc.warnings = vec![Warning {
                    source: "btrfs".into(),
                    severity: Severity::Note,
                    transient: true,
                    message: "discard backlog".into(),
                }];
                n.consider(&inc, at)
            })
            .collect();
        assert!(notices.is_empty(), "{notices:?}");
    }

    #[test]
    fn a_transient_alongside_a_real_cause_still_speaks() {
        let mut n = Notifier::default();
        let notices: Vec<Notice> = (0..200)
            .filter_map(|i| {
                let at = 1000 + i;
                let mut inc = incident_at(at, 400);
                inc.warnings = vec![Warning {
                    source: "btrfs".into(),
                    severity: Severity::Note,
                    transient: true,
                    message: "discard backlog".into(),
                }];
                inc.causes = vec![Cause {
                    unit: "systemd-journald".into(),
                    cgroup: "/sys/fs/cgroup/system.slice/systemd-journald.service".into(),
                    read_bytes: 0,
                    write_bytes: 200 * 1024 * 1024,
                    discard_bytes: 0,
                    pressure_pct: 5.0,
                    role: Role::Cause,
                }];
                n.consider(&inc, at)
            })
            .collect();
        assert_eq!(notices.len(), 1);
        assert!(
            notices[0].body.contains("systemd-journald"),
            "{:?}",
            notices[0]
        );
        assert!(
            notices[0].body.contains("clears itself"),
            "{:?}",
            notices[0]
        );
    }

    #[test]
    fn the_message_names_the_cause_not_the_casualty() {
        let mut n = Notifier::default();
        let notices: Vec<Notice> = (0..200)
            .filter_map(|i| {
                let at = 1000 + i;
                let mut inc = incident_at(at, 400);
                inc.causes = vec![Cause {
                    unit: "systemd-journald".into(),
                    cgroup: "/sys/fs/cgroup/system.slice/systemd-journald.service".into(),
                    read_bytes: 0,
                    write_bytes: 2 * 1024 * 1024 * 1024,
                    discard_bytes: 0,
                    pressure_pct: 4.0,
                    role: Role::Cause,
                }];
                n.consider(&inc, at)
            })
            .collect();
        let body = &notices[0].body;
        assert!(body.contains("systemd-journald"), "{body}");
        assert!(body.contains("2.0 GiB"), "{body}");
    }

    #[test]
    fn no_message_ever_reports_the_capture_window_as_a_freeze_duration() {
        // "froze for 405ms" was the sampling window, not the freeze. Of 520,209
        // recorded incidents only 3 ever exceeded a second, so the number could
        // never have meant what it appeared to mean.
        let mut n = Notifier::default();
        let notices = drive(&mut n, 200, 400, 1000);
        let all = format!("{} {}", notices[0].summary, notices[0].body);
        assert!(!all.contains("400ms"), "{all}");
        assert!(!all.contains("405ms"), "{all}");
    }

    #[test]
    fn a_chronic_condition_is_described_as_chronic() {
        let mut n = Notifier::default();
        let notices = drive(&mut n, 400, 400, 1000);
        assert!(notices[0].body.contains("continuous"), "{:?}", notices[0]);
    }

    #[test]
    fn a_disabled_notifier_stays_quiet() {
        let mut n = Notifier::new(false, DEFAULT_MIN_PEAK, DEFAULT_COOLDOWN);
        assert!(drive(&mut n, 500, 400, 1000).is_empty());
    }

    #[test]
    fn an_empty_incident_says_nothing() {
        let mut n = Notifier::default();
        let empty = Incident {
            at_unix: 0,
            window_usec: 0,
            woke_on: vec![],
            stalls: vec![],
            warnings: vec![],
            culprits: vec![],
            causes: vec![],
        };
        assert!(n.consider(&empty, 100).is_none());
    }

    #[test]
    fn a_process_level_culprit_still_counts_as_actionable() {
        let mut n = Notifier::default();
        let notices: Vec<Notice> = (0..200)
            .filter_map(|i| {
                let at = 1000 + i;
                let mut inc = incident_at(at, 400);
                inc.warnings = vec![Warning {
                    source: "btrfs".into(),
                    severity: Severity::Note,
                    transient: true,
                    message: "discard backlog".into(),
                }];
                inc.culprits = vec![Culprit {
                    pid: 42,
                    comm: "dd".into(),
                    blocked_pct: 5.0,
                    bytes: 5 * 1024 * 1024,
                    role: Role::Cause,
                }];
                n.consider(&inc, at)
            })
            .collect();
        assert_eq!(notices.len(), 1);
    }
}
