//! Telling you at the moment it happens.
//!
//! # Why this closes the loop
//!
//! Everything else here is a thing you have to go and ask. That is not a
//! feedback loop, it is an archive. An instrument that makes an invisible
//! state perceptible only works if the signal arrives while you still care —
//! the difference between a thermometer you watch and one you read next week.
//!
//! This is the piece that turns a recorder into something that speaks.
//!
//! # The two ways to get it wrong
//!
//! **Silence.** Notifying only when a rule says so means almost nobody ever
//! sees anything, because almost nobody writes rules.
//!
//! **Noise.** A saturated disk produces a capture every couple of seconds, and
//! twenty popups about the same freeze is worse than none: the user turns the
//! whole thing off and never turns it back on.
//!
//! So: on by default, above a threshold that means *you noticed this*, with a
//! cooldown, and honest about what it held back.

use std::time::Duration;

use crate::incident::{Incident, Role};

/// Default: only speak up about something the user would have felt.
pub const DEFAULT_MIN_PEAK: f64 = 70.0;
/// Default: at most one notice per minute, however bad it gets.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// What to say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub summary: String,
    pub body: String,
    /// How many captures were suppressed by the cooldown since the last notice.
    pub also_suppressed: u32,
}

/// Decides whether to speak, and holds the rate limit.
///
/// Deliberately separate from sending, so the policy is testable without a
/// desktop, a bus, or a notification daemon.
#[derive(Debug)]
pub struct Notifier {
    pub enabled: bool,
    pub min_peak: f64,
    pub cooldown: Duration,
    last_sent_unix: Option<u64>,
    suppressed: u32,
}

impl Default for Notifier {
    fn default() -> Self {
        Self {
            enabled: true,
            min_peak: DEFAULT_MIN_PEAK,
            cooldown: DEFAULT_COOLDOWN,
            last_sent_unix: None,
            suppressed: 0,
        }
    }
}

impl Notifier {
    /// Build one from resolved settings.
    ///
    /// A constructor rather than public fields, so the rate-limit state stays
    /// owned by the type and cannot be reset by accident from outside.
    pub fn new(enabled: bool, min_peak: f64, cooldown: Duration) -> Self {
        Self {
            enabled,
            min_peak,
            cooldown,
            last_sent_unix: None,
            suppressed: 0,
        }
    }

    /// Should this incident be announced, and as what?
    ///
    /// Takes `now` rather than reading the clock so the rate limit can be
    /// tested deterministically.
    pub fn consider(&mut self, incident: &Incident, now: u64) -> Option<Notice> {
        if !self.enabled {
            return None;
        }
        let worst = incident.worst()?;
        if worst.peak_pct < self.min_peak {
            return None;
        }

        // Rate limit. Count what is held back rather than discarding it
        // silently, or the one notice that does arrive understates the problem.
        if let Some(last) = self.last_sent_unix
            && now.saturating_sub(last) < self.cooldown.as_secs()
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }

        let also_suppressed = std::mem::take(&mut self.suppressed);
        self.last_sent_unix = Some(now);

        let secs = incident.frozen_ms() / 1000.0;
        let summary = if secs >= 1.0 {
            format!("{} froze for {:.1}s", worst.unit, secs)
        } else {
            format!("{} froze for {:.0}ms", worst.unit, incident.frozen_ms())
        };

        // Name the cause when one was caught. This is the sentence that makes
        // the notification worth reading rather than merely alarming.
        let mut body = match incident.culprits.iter().find(|c| c.role == Role::Cause) {
            Some(c) => format!(
                "Blocked on {}. The cause was {} [{}].",
                worst.resource, c.comm, c.pid
            ),
            None => format!(
                "Blocked on {} for {:.0}% of the window.",
                worst.resource, worst.pressure_pct
            ),
        };

        // A transient condition is the difference between "do something" and
        // "wait", so it belongs in the sentence, not in a log somewhere.
        if let Some(w) = incident.warnings.iter().find(|w| w.transient) {
            body.push_str(&format!(" {} is busy but clears itself.", w.source));
        }

        if also_suppressed > 0 {
            body.push_str(&format!(" ({also_suppressed} more since the last notice.)"));
        }

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
    use crate::{PsiKind, Resource, Severity, Stall, Warning};

    fn incident(peak: f64, ms: u64) -> Incident {
        Incident {
            at_unix: 0,
            window_usec: 1_000_000,
            woke_on: vec!["io".into()],
            stalls: vec![Stall {
                unit: "ghostty".into(),
                cgroup: "/x".into(),
                resource: Resource::Io,
                kind: PsiKind::Full,
                delta_usec: ms * 1000,
                pressure_pct: peak,
                peak_pct: peak,
            }],
            warnings: vec![],
            culprits: vec![],
        }
    }

    #[test]
    fn stays_quiet_below_the_threshold() {
        let mut n = Notifier::default();
        assert!(n.consider(&incident(40.0, 200), 100).is_none());
    }

    #[test]
    fn speaks_above_the_threshold() {
        let mut n = Notifier::default();
        let notice = n
            .consider(&incident(91.0, 3100), 100)
            .expect("should notify");
        assert!(notice.summary.contains("ghostty"), "{}", notice.summary);
        assert!(notice.summary.contains("3.1s"), "{}", notice.summary);
    }

    #[test]
    fn a_storm_produces_one_notice_not_twenty() {
        let mut n = Notifier::default();
        assert!(n.consider(&incident(95.0, 500), 100).is_some());
        // Same minute: everything else is held back.
        for t in 101..=140 {
            assert!(
                n.consider(&incident(95.0, 500), t).is_none(),
                "spoke at {t}"
            );
        }
    }

    #[test]
    fn what_was_held_back_is_reported_rather_than_lost() {
        // A single notice after a storm must not understate it, or the user
        // reads "one stall" when there were thirty.
        let mut n = Notifier::default();
        n.consider(&incident(95.0, 500), 0).unwrap();
        for t in 1..=5 {
            n.consider(&incident(95.0, 500), t);
        }
        let next = n.consider(&incident(95.0, 500), 100).unwrap();
        assert_eq!(next.also_suppressed, 5);
        assert!(next.body.contains("5 more"), "{}", next.body);
    }

    #[test]
    fn names_the_cause_when_one_was_caught() {
        let mut n = Notifier::default();
        let mut i = incident(95.0, 900);
        i.culprits = vec![Culprit {
            pid: 4242,
            comm: "dd".into(),
            blocked_pct: 5.0,
            bytes: 5 << 30,
            role: Role::Cause,
        }];
        let notice = n.consider(&i, 100).unwrap();
        assert!(notice.body.contains("dd [4242]"), "{}", notice.body);
        assert!(notice.body.contains("cause"), "{}", notice.body);
    }

    #[test]
    fn transient_conditions_say_so_because_it_changes_what_you_do() {
        let mut n = Notifier::default();
        let mut i = incident(95.0, 900);
        i.warnings = vec![Warning {
            source: "btrfs".into(),
            severity: Severity::Note,
            transient: true,
            message: "discard backlog".into(),
        }];
        let notice = n.consider(&i, 100).unwrap();
        assert!(notice.body.contains("clears itself"), "{}", notice.body);
    }

    #[test]
    fn disabled_means_silent() {
        let mut n = Notifier {
            enabled: false,
            ..Default::default()
        };
        assert!(n.consider(&incident(99.0, 5000), 100).is_none());
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
        };
        assert!(n.consider(&empty, 100).is_none());
    }
}
