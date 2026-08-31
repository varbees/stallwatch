//! Turning a systemd unit name into something a person recognises.
//!
//! `com.mitchellh.ghostty` is correct, addressable, and meaningless to the
//! human being told their machine froze. They call it Ghostty. A notification
//! that names the unit instead of the application is asking the reader to do a
//! translation they cannot do.
//!
//! The desktop already stores the answer: every installed application ships a
//! `.desktop` entry keyed by exactly this identifier, with a `Name=` line.
//!
//! Deliberately *not* used on the sampling path. This touches the filesystem,
//! and doing it per cgroup per sample would make a tool built to observe
//! contention a cause of it. Names are resolved when something is about to be
//! shown to a person, which is rare.

use std::fs;
use std::path::PathBuf;

/// Where desktop entries live, in the order XDG says to search.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        dirs.push(home.join(".local/share/applications"));
        dirs.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    dirs.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
    dirs.push(PathBuf::from("/usr/local/share/applications"));
    dirs.push(PathBuf::from("/usr/share/applications"));
    dirs
}

/// Read `Name=` from a desktop entry body.
///
/// Stops at the first one, and only inside `[Desktop Entry]`: actions and
/// localised sections further down carry their own `Name=` lines, and taking
/// the last match yields the name of a right-click menu item.
fn desktop_name(body: &str) -> Option<String> {
    let mut in_entry = false;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some(v) = line.strip_prefix("Name=") {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Best human name for a unit, falling back to the unit itself.
///
/// Never fails and never blocks on anything but a handful of small reads. A
/// unit with no desktop entry — `systemd-journald`, a container, a slice — is
/// already about as readable as it is going to get, so it is returned as-is.
pub fn human_name(unit: &str) -> String {
    // Strip decoration friendly_name may have added, then look up the bare id.
    let base = unit.strip_suffix(" (flatpak)").unwrap_or(unit).trim();
    if base.is_empty() {
        return unit.to_string();
    }

    for dir in search_dirs() {
        let candidate = dir.join(format!("{base}.desktop"));
        if let Ok(body) = fs::read_to_string(&candidate)
            && let Some(name) = desktop_name(&body)
        {
            return name;
        }
    }

    // A reverse-DNS id with no entry installed still reads better as its last
    // component than as the whole string: `org.videolan.VLC` -> `VLC`.
    if base.contains('.')
        && !base.contains(' ')
        && let Some(last) = base.rsplit('.').next()
        && last.len() > 1
        && last.chars().next().is_some_and(|c| c.is_alphabetic())
    {
        let mut chars = last.chars();
        let first = chars.next().unwrap().to_uppercase().to_string();
        return format!("{first}{}", chars.as_str());
    }
    unit.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_name_from_the_desktop_entry_section() {
        let body = "[Desktop Entry]\nType=Application\nName=Ghostty\nExec=ghostty\n";
        assert_eq!(desktop_name(body).as_deref(), Some("Ghostty"));
    }

    #[test]
    fn ignores_names_in_action_sections() {
        // Taking the last match here names a context-menu item, not the app.
        let body =
            "[Desktop Entry]\nName=Zen Browser\n\n[Desktop Action new-window]\nName=New Window\n";
        assert_eq!(desktop_name(body).as_deref(), Some("Zen Browser"));
    }

    #[test]
    fn a_name_before_any_section_header_is_not_used() {
        assert_eq!(
            desktop_name("Name=Stray\n[Desktop Entry]\nName=Real\n").as_deref(),
            Some("Real")
        );
    }

    #[test]
    fn falls_back_to_the_last_component_of_a_reverse_dns_id() {
        assert_eq!(
            human_name("org.videolan.SomeAppThatIsNotInstalled"),
            "SomeAppThatIsNotInstalled"
        );
    }

    #[test]
    fn leaves_a_plain_unit_name_alone() {
        assert_eq!(human_name("systemd-journald"), "systemd-journald");
        assert_eq!(human_name("all user apps"), "all user apps");
    }

    #[test]
    fn empty_input_is_returned_unchanged() {
        assert_eq!(human_name(""), "");
    }
}
