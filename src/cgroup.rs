//! Walking the cgroup v2 tree and turning kernel paths into human names.

use crate::psi::{self, Resource, Snapshot};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const ROOT: &str = "/sys/fs/cgroup";

/// Recursively collect every cgroup directory under `root`.
///
/// Unreadable subtrees are skipped rather than fatal. Cgroup namespaces,
/// delegation boundaries, and AppArmor/SELinux denials all produce EACCES on
/// entirely healthy systems — a diagnostic that aborts on the first one is
/// useless exactly where it is most needed.
pub fn walk(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        // Don't follow symlinks. cgroupfs has none today; be defensive anyway,
        // because a symlink loop here would hang the tool.
        if !matches!(entry.file_type(), Ok(ft) if ft.is_dir()) {
            continue;
        }
        let path = entry.path();
        out.push(path.clone());
        walk(&path, out);
    }
}

/// Every cgroup on the system, root included.
pub fn all() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from(ROOT)];
    walk(Path::new(ROOT), &mut v);
    v
}

/// Read PSI for every cgroup that exposes it.
///
/// Cgroups without pressure files are omitted rather than recorded as zero, so
/// a cgroup created between two samples is absent from the first map and gets
/// skipped when diffing instead of appearing as a huge bogus delta.
pub fn sample(cgroups: &[PathBuf]) -> HashMap<PathBuf, Snapshot> {
    let mut map = HashMap::with_capacity(cgroups.len());
    for cg in cgroups {
        let mut snap = Snapshot::default();
        let mut any = false;
        for res in Resource::ALL {
            if let Ok(body) = fs::read_to_string(cg.join(res.file())) {
                any = true;
                snap.set(res, psi::parse(&body));
            }
        }
        if any {
            map.insert(cg.clone(), snap);
        }
    }
    map
}

/// Decode systemd's cgroup name escaping: `\x2d` -> `-`.
pub fn unescape_systemd(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            if let Ok(b) = u8::from_str_radix(&name[i + 2..i + 4], 16) {
                out.push(b as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Turn a cgroup path into something a human recognises.
///
/// ```text
/// app-flatpak-org.mozilla.firefox-1234.scope -> firefox (flatpak)
/// app-com.mitchellh.ghostty.service          -> com.mitchellh.ghostty
/// user@1000.service                          -> user session 1000
/// app.slice                                  -> all user apps
/// ```
pub fn friendly_name(cgroup: &Path) -> String {
    if cgroup == Path::new(ROOT) {
        return "whole system (root cgroup)".to_string();
    }

    let raw = cgroup
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("<unknown>");
    let name = unescape_systemd(raw);

    // Slices are aggregates, not programs. Rendering `app.slice` as "app" reads
    // like the name of a process and is actively misleading; say plainly that
    // it is a group so nobody goes looking for a program called "app".
    if let Some(slice) = name.strip_suffix(".slice") {
        return match slice {
            "app" => "all user apps".to_string(),
            "system" => "all system services".to_string(),
            "user" => "all user sessions".to_string(),
            "background" => "background tasks".to_string(),
            "session" => "desktop session".to_string(),
            "machine" => "VMs and containers".to_string(),
            other => format!("{other} (group)"),
        };
    }

    let stem = name
        .strip_suffix(".service")
        .or_else(|| name.strip_suffix(".scope"))
        .unwrap_or(&name)
        .to_string();

    // `user@1000.service` is a session, not an instantiated unit. This must be
    // checked before the @-instance strip below, which would otherwise reduce
    // it to a bare "user".
    if let Some(uid) = stem.strip_prefix("user@") {
        return format!("user session {uid}");
    }

    let stem = match stem.rsplit_once('@') {
        Some((head, tail)) if tail.chars().all(|c| c.is_ascii_digit()) && !head.is_empty() => {
            head.to_string()
        }
        _ => stem,
    };

    if let Some(rest) = stem.strip_prefix("app-flatpak-") {
        let app = rest.rsplit_once('-').map(|(h, _)| h).unwrap_or(rest);
        let short = app.rsplit('.').next().unwrap_or(app);
        return format!("{short} (flatpak)");
    }
    if let Some(rest) = stem.strip_prefix("app-") {
        let app = rest.rsplit_once('-').map(|(h, _)| h).unwrap_or(rest);
        return app.to_string();
    }
    if stem.is_empty() {
        return "whole system (root cgroup)".to_string();
    }
    stem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_systemd_names() {
        assert_eq!(unescape_systemd(r"app\x2dfoo"), "app-foo");
        assert_eq!(unescape_systemd("plain"), "plain");
    }

    #[test]
    fn names_flatpak_apps() {
        assert_eq!(
            friendly_name(Path::new("/a/app-flatpak-org.mozilla.firefox-1234.scope")),
            "firefox (flatpak)"
        );
    }

    #[test]
    fn names_plain_services() {
        assert_eq!(
            friendly_name(Path::new("/a/app-com.mitchellh.ghostty.service")),
            "com.mitchellh.ghostty"
        );
        assert_eq!(
            friendly_name(Path::new("/a/systemd-journald.service")),
            "systemd-journald"
        );
    }

    #[test]
    fn names_user_sessions() {
        assert_eq!(
            friendly_name(Path::new("/a/user@1000.service")),
            "user session 1000"
        );
    }

    #[test]
    fn names_slices_as_groups_not_units() {
        assert_eq!(friendly_name(Path::new("/a/app.slice")), "all user apps");
        assert_eq!(
            friendly_name(Path::new("/a/system.slice")),
            "all system services"
        );
        assert_eq!(
            friendly_name(Path::new("/a/weird.slice")),
            "weird (group)"
        );
    }

    #[test]
    fn names_the_root_cgroup() {
        assert_eq!(friendly_name(Path::new(ROOT)), "whole system (root cgroup)");
    }
}
