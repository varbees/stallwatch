//! What this machine actually permits, checked rather than assumed.
//!
//! # Why this exists
//!
//! For 29 days this tool recorded 520,155 incidents and named a cause in none
//! of them, because the file it read causes from was unreadable and nothing
//! said so. Every individual report looked confident and complete. The failure
//! was invisible precisely because the tool never asked whether its own
//! evidence was available.
//!
//! A diagnostic that cannot diagnose itself will eventually lie with total
//! confidence. So every capability the engine depends on is probed here, and
//! every probe states what degrades when it fails — not just that it failed.
//!
//! This is deliberately cheap and side-effect free. The trigger probes register
//! and immediately drop, which unregisters them.

use std::fmt;
use std::fs;
use std::path::Path;

use crate::cgroup;
use crate::trigger;

/// How a capability came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Present and usable.
    Ok,
    /// Usable, but something downstream is weaker than it should be.
    Degraded,
    /// Absent. Whatever depends on it cannot work at all.
    Failed,
}

impl Status {
    pub fn marker(self) -> &'static str {
        match self {
            Status::Ok => "\u{2713}",
            Status::Degraded => "!",
            Status::Failed => "\u{2717}",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Ok => "ok",
            Status::Degraded => "degraded",
            Status::Failed => "failed",
        })
    }
}

/// One probed capability.
#[derive(Clone, Debug)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    /// What was measured. Numbers, not adjectives.
    pub detail: String,
    /// What stops working, in the reader's terms, when this is not `Ok`.
    /// Empty when nothing does.
    pub consequence: &'static str,
}

/// Probe everything the engine depends on.
pub fn diagnose() -> Vec<Check> {
    vec![
        cgroup_v2(),
        psi_present(),
        per_cgroup_pressure(),
        io_stat(),
        proc_io(),
        system_trigger(),
        cgroup_trigger(),
        delayacct(),
    ]
}

fn cgroup_v2() -> Check {
    // cgroup v2 is identified by cgroup.controllers at the mount root; v1 has
    // no such file. Attribution is meaningless without it.
    let ok = Path::new(cgroup::ROOT).join("cgroup.controllers").exists();
    Check {
        name: "cgroup v2",
        status: if ok { Status::Ok } else { Status::Failed },
        detail: if ok {
            format!("mounted at {}", cgroup::ROOT)
        } else {
            "not found — cgroup v1 or an unusual mount layout".into()
        },
        consequence: "Nothing can be attributed to a unit. There is no v1 fallback.",
    }
}

fn psi_present() -> Check {
    let ok = Path::new("/proc/pressure").exists();
    Check {
        name: "kernel PSI",
        status: if ok { Status::Ok } else { Status::Failed },
        detail: if ok {
            "/proc/pressure present".into()
        } else {
            "/proc/pressure missing — CONFIG_PSI=n, or CONFIG_PSI_DEFAULT_DISABLED \
             without psi=1 on the kernel command line"
                .into()
        },
        consequence: "No stall can be detected at all.",
    }
}

fn per_cgroup_pressure() -> Check {
    // The failure this guards against is the worst one a diagnostic can have:
    // cgroup_disable=pressure removes every per-cgroup file while leaving
    // /proc/pressure intact, so the tool reports "no stalls" on a machine that
    // is on fire.
    let all = cgroup::all();
    let readable = all
        .iter()
        .filter(|cg| fs::read_to_string(cg.join("io.pressure")).is_ok())
        .count();
    let status = match readable {
        0 => Status::Failed,
        n if n * 4 < all.len() => Status::Degraded,
        _ => Status::Ok,
    };
    Check {
        name: "per-cgroup pressure",
        status,
        detail: format!("{readable} of {} cgroups expose io.pressure", all.len()),
        consequence: "Stalls are visible system-wide but cannot be blamed on a unit. \
                      Check for cgroup_disable=pressure on the kernel command line.",
    }
}

fn io_stat() -> Check {
    // This is the evidence that makes cause attribution possible at all.
    let all = cgroup::all();
    let readable = all
        .iter()
        .filter(|cg| crate::iostat::read(cg).is_some())
        .count();
    let status = match readable {
        0 => Status::Failed,
        n if n * 4 < all.len() => Status::Degraded,
        _ => Status::Ok,
    };
    Check {
        name: "per-cgroup io.stat",
        status,
        detail: format!("{readable} of {} cgroups expose io.stat", all.len()),
        consequence: "Causes cannot be named — only victims. Enable the io controller \
                      in cgroup.subtree_control, or expect unit-level attribution only.",
    }
}

fn proc_io() -> Check {
    // Reported as a RATIO on purpose. This is the file whose silent
    // unreadability produced 520,155 confident, causeless reports: it works
    // for your own processes and fails for everything else, so a spot check
    // succeeds while the tool is blind to every process that matters.
    let mut total = 0usize;
    let mut readable = 0usize;
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            total += 1;
            if fs::read_to_string(format!("/proc/{pid}/io")).is_ok() {
                readable += 1;
            }
        }
    }
    let pct = if total == 0 {
        0.0
    } else {
        readable as f64 / total as f64 * 100.0
    };
    // Never `Ok`: on any multi-user system this is partial by design, and
    // calling it healthy is what hid the original bug.
    let status = if readable == 0 {
        Status::Failed
    } else {
        Status::Degraded
    };
    Check {
        name: "/proc/<pid>/io",
        status,
        detail: format!(
            "readable for {readable} of {total} processes ({pct:.0}%) — \
                         EACCES for anything you do not own"
        ),
        consequence: "Per-process byte evidence is unavailable for kernel threads and \
                      root daemons. Cause attribution uses cgroup io.stat instead, which \
                      is unit-level. This is expected, not a fault.",
    }
}

fn system_trigger() -> Check {
    // A real registration, immediately dropped. The kernel is the only
    // authority on whether this works: the window rules are version-dependent
    // and the spec must be newline-terminated, which is easy to get wrong and
    // returns a bare EINVAL that reads like a permission problem.
    let probe = trigger::Trigger::at(
        Path::new("/proc/pressure/io"),
        crate::Resource::Io,
        crate::PsiKind::Some,
        std::time::Duration::from_millis(50),
        std::time::Duration::from_secs(2),
    );
    match probe {
        Ok(_) => Check {
            name: "PSI triggers (system)",
            status: Status::Ok,
            detail: "accepted — the daemon is event-driven and costs nothing when idle".into(),
            consequence: "",
        },
        Err(e) => Check {
            name: "PSI triggers (system)",
            status: Status::Degraded,
            detail: format!("refused: {e}"),
            consequence: "The daemon falls back to polling, which costs CPU on every tick \
                          and misses stalls shorter than the interval.",
        },
    }
}

fn cgroup_trigger() -> Check {
    // Expected to fail unprivileged, and worth stating rather than leaving as
    // a surprise: it is why capture is woken system-wide and then attributed,
    // instead of being woken by the guilty cgroup directly.
    let target = Path::new(cgroup::ROOT).join("io.pressure");
    let probe = trigger::Trigger::at(
        &target,
        crate::Resource::Io,
        crate::PsiKind::Some,
        std::time::Duration::from_millis(50),
        std::time::Duration::from_secs(2),
    );
    match probe {
        Ok(_) => Check {
            name: "PSI triggers (per-cgroup)",
            status: Status::Ok,
            detail: "accepted".into(),
            consequence: "",
        },
        Err(e) => Check {
            name: "PSI triggers (per-cgroup)",
            status: Status::Degraded,
            detail: format!("refused: {e} — normal without privileges"),
            consequence: "Capture is woken by system-wide pressure and attributed \
                          afterwards, so a stall confined to one cgroup may not wake it.",
        },
    }
}

fn delayacct() -> Check {
    let on = crate::process::delayacct_enabled();
    Check {
        name: "delay accounting",
        status: if on { Status::Ok } else { Status::Degraded },
        detail: if on {
            "enabled — exact per-process block IO wait available".into()
        } else {
            "off (kernel.task_delayacct=0, the default since 5.14)".into()
        },
        consequence: "Per-process blocking is inferred from state sampling rather than \
                      measured. Enable with: sudo sysctl -w kernel.task_delayacct=1",
    }
}

/// Render for a human.
pub fn to_text(checks: &[Check]) -> String {
    let mut o = String::new();
    o.push_str("What stallwatch can and cannot see on this machine:\n\n");
    for c in checks {
        o.push_str(&format!(
            "  {} {:<26} {}\n",
            c.status.marker(),
            c.name,
            c.detail
        ));
        if c.status != Status::Ok && !c.consequence.is_empty() {
            for line in wrap(c.consequence, 74) {
                o.push_str(&format!("      {line}\n"));
            }
        }
    }
    let failed = checks.iter().filter(|c| c.status == Status::Failed).count();
    let degraded = checks
        .iter()
        .filter(|c| c.status == Status::Degraded)
        .count();
    o.push('\n');
    let plural = |n: usize| if n == 1 { "capability" } else { "capabilities" };
    if failed > 0 {
        o.push_str(&format!(
            "  {failed} {} missing. Results will be incomplete.\n",
            plural(failed)
        ));
    } else if degraded > 0 {
        o.push_str(&format!(
            "  Working, with {degraded} reduced {} noted above.\n",
            plural(degraded)
        ));
    } else {
        o.push_str("  Everything available.\n");
    }
    o
}

/// One line for a log, naming what is degraded rather than only counting it.
///
/// The daemon logs this at startup. The original failure ran for 29 days
/// because nothing ever announced that the evidence was missing; a line in the
/// journal at every start is the cheapest possible guard against a repeat.
pub fn summary_line(checks: &[Check]) -> String {
    let bad: Vec<&str> = checks
        .iter()
        .filter(|c| c.status != Status::Ok)
        .map(|c| c.name)
        .collect();
    if bad.is_empty() {
        "all capabilities available".to_string()
    } else {
        format!(
            "reduced capability: {} (run `stallwatch doctor` for what this costs)",
            bad.join(", ")
        )
    }
}

/// Machine-readable, same field names as the human view.
pub fn to_json(checks: &[Check]) -> String {
    let items: Vec<String> = checks
        .iter()
        .map(|c| {
            format!(
                r#"{{"name":{},"status":"{}","detail":{},"consequence":{}}}"#,
                crate::json_str(c.name),
                c.status,
                crate::json_str(&c.detail),
                crate::json_str(c.consequence)
            )
        })
        .collect();
    format!(r#"{{"checks":[{}]}}"#, items.join(","))
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_check_that_is_not_ok_explains_what_breaks() {
        // The whole point: a failure the reader cannot interpret is the same
        // as no report at all.
        for c in diagnose() {
            if c.status != Status::Ok {
                assert!(
                    !c.consequence.is_empty(),
                    "{} is {} with no consequence stated",
                    c.name,
                    c.status
                );
            }
            assert!(!c.detail.is_empty(), "{} has no detail", c.name);
        }
    }

    #[test]
    fn proc_io_is_never_reported_as_healthy() {
        // It is partial by design on any multi-user system, and reporting it
        // as Ok is exactly how the original bug stayed hidden.
        let c = proc_io();
        assert_ne!(c.status, Status::Ok);
    }

    #[test]
    fn text_output_names_every_check() {
        let checks = diagnose();
        let text = to_text(&checks);
        for c in &checks {
            assert!(text.contains(c.name), "{} missing from output", c.name);
        }
    }

    #[test]
    fn json_is_wellformed_and_complete() {
        let checks = diagnose();
        let j = to_json(&checks);
        assert!(j.starts_with(r#"{"checks":["#) && j.ends_with("]}"));
        assert_eq!(j.matches(r#""name":"#).count(), checks.len());
    }

    #[test]
    fn wrapping_never_loses_a_word() {
        let s = "a diagnostic that cannot diagnose itself will eventually lie";
        assert_eq!(wrap(s, 20).join(" "), s);
    }
}
