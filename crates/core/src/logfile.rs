//! Appending to a log that cannot grow without bound.
//!
//! # Why this exists
//!
//! The incident log had no cap. On one desktop it reached **364 MB in 30 days**
//! — 520,155 records at roughly 12 MB/day — in a directory nobody looks at,
//! from a tool whose entire premise is that it must never become a burden on
//! the machine it observes.
//!
//! A diagnostic that fills the disk it is diagnosing has become the problem it
//! was installed to find.
//!
//! # The policy
//!
//! Size-triggered, one generation kept. On crossing the cap the current file is
//! renamed to `<name>.1` — replacing any previous `.1` — and a fresh file
//! starts. Worst case on disk is therefore a little over twice the cap, and it
//! is bounded regardless of how long the daemon runs.
//!
//! Deliberately not time-based: a machine that stalls constantly writes a
//! hundred times more than a healthy one, and the failure being guarded against
//! is volume, not age.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default cap for one generation of the incident log.
///
/// At the ~12 MB/day observed on a chronically stalling desktop this holds
/// roughly five days live and ten across both generations, which comfortably
/// covers "what happened to my machine last week" — the only question the log
/// exists to answer.
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The path the previous generation is rotated to.
pub fn previous_generation(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".1");
    PathBuf::from(name)
}

/// Append one line, rotating first if the file has reached `max_bytes`.
///
/// Checks size before writing rather than after, so the cap is never exceeded
/// by more than one record.
pub fn append_line(path: &Path, line: &str, max_bytes: u64) -> std::io::Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        fs::create_dir_all(dir)?;
    }

    if max_bytes > 0 && fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= max_bytes {
        // A failed rotation must not stop the append: losing a record is worse
        // than a file that is briefly over its cap, and the next attempt will
        // try again.
        let _ = fs::rename(path, previous_generation(path));
    }

    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rotation is rename-and-size logic, so any filesystem will do — unlike
    /// the ground-truth tests, this needs no block device and can use the
    /// system temp dir even when it is tmpfs.
    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("stallwatch-test-{name}"));
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(previous_generation(&p));
        p
    }

    #[test]
    fn rotation_bounds_the_total_size() {
        let p = tmp("rotate-bound.jsonl");
        let line = "x".repeat(200);
        for _ in 0..500 {
            append_line(&p, &line, 4096).unwrap();
        }
        let live = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        let old = fs::metadata(previous_generation(&p))
            .map(|m| m.len())
            .unwrap_or(0);
        // 500 * ~201 bytes is ~100 KB unbounded; the cap holds it near 2x4096.
        assert!(
            live + old < 4096 * 3,
            "unbounded growth: live={live} old={old}"
        );
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(previous_generation(&p));
    }

    #[test]
    fn the_previous_generation_is_kept_not_deleted() {
        let p = tmp("rotate-keep.jsonl");
        append_line(&p, "first", 1).unwrap();
        append_line(&p, "second", 1).unwrap();
        assert_eq!(
            fs::read_to_string(previous_generation(&p)).unwrap().trim(),
            "first"
        );
        assert_eq!(fs::read_to_string(&p).unwrap().trim(), "second");
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(previous_generation(&p));
    }

    #[test]
    fn only_one_old_generation_is_ever_retained() {
        let p = tmp("rotate-one.jsonl");
        for i in 0..5 {
            append_line(&p, &format!("line{i}"), 1).unwrap();
        }
        assert!(!previous_generation(&previous_generation(&p)).exists());
        let _ = fs::remove_file(&p);
        let _ = fs::remove_file(previous_generation(&p));
    }

    #[test]
    fn a_zero_cap_disables_rotation() {
        let p = tmp("rotate-off.jsonl");
        for i in 0..20 {
            append_line(&p, &format!("line{i}"), 0).unwrap();
        }
        assert_eq!(fs::read_to_string(&p).unwrap().lines().count(), 20);
        assert!(!previous_generation(&p).exists());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn missing_parent_directories_are_created() {
        let base = std::env::temp_dir().join("stallwatch-test-rotate-nested");
        let _ = fs::remove_dir_all(&base);
        let p = base.join("a/b/incidents.jsonl");
        append_line(&p, "hello", DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap().trim(), "hello");
        let _ = fs::remove_dir_all(&base);
    }
}
