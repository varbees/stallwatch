//! btrfs conditions that stall IO while `df` reports plenty of free space.
//!
//! Everything here is read from `/sys/fs/btrfs/<fsid>/`, unprivileged.

use super::{Severity, Warning};
use std::fs;
use std::path::Path;

const SYSFS: &str = "/sys/fs/btrfs";

/// Warn below this share of the device left unallocated.
const UNALLOCATED_FLOOR_PCT: f64 = 1.0;

/// Discard backlog large enough to be worth explaining. Below this the queue
/// drains before anyone notices.
const DISCARD_EXTENT_FLOOR: u64 = 10_000;

pub(crate) fn read_u64(p: &Path) -> Option<u64> {
    fs::read_to_string(p).ok()?.trim().parse().ok()
}

pub fn check() -> Vec<Warning> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(SYSFS) else {
        return out;
    };
    for fs_entry in entries.flatten() {
        let base = fs_entry.path();
        // /sys/fs/btrfs also contains a "features" directory that is not a
        // filesystem; the allocation subdir is what distinguishes a real fsid.
        if !base.join("allocation").is_dir() {
            continue;
        }
        let label = base
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("btrfs")
            .to_string();

        out.extend(check_discard(&base, &label));
        out.extend(check_allocation(&base, &label));
    }
    out
}

/// Async discard (TRIM) backlog.
///
/// After a large delete btrfs hands the freed extents to a rate-limited
/// background worker. That worker runs in the kernel, so the disk shows heavy
/// utilisation while **no userspace process has any IO delay at all** — a
/// combination that is genuinely baffling if you don't know to look for it, and
/// which sends people hunting for a runaway program that does not exist.
///
/// It is transient and self-clearing, which is the single most important thing
/// to tell someone staring at a busy disk.
fn check_discard(base: &Path, label: &str) -> Option<Warning> {
    let extents = read_u64(&base.join("discard/discardable_extents"))?;
    if extents < DISCARD_EXTENT_FLOOR {
        return None;
    }
    let bytes = read_u64(&base.join("discard/discardable_bytes")).unwrap_or(0);
    let iops = read_u64(&base.join("discard/iops_limit")).unwrap_or(0);
    let eta = extents
        .checked_div(iops)
        .and_then(|per_iop| per_iop.checked_div(60))
        .map(|min| format!(" At the {iops} IOPS limit that is roughly {} min.", min + 1))
        .unwrap_or_default();
    Some(Warning {
        source: "btrfs".into(),
        severity: Severity::Note,
        transient: true,
        message: format!(
            "{label} is working through an async discard (TRIM) backlog: {extents} extents \
             / {:.1} GiB still queued after a large delete. This runs in the kernel, so the \
             disk looks busy while no process shows IO delay. It clears on its own — do not \
             go hunting for a runaway program.{eta}",
            bytes as f64 / 1_073_741_824.0
        ),
    })
}

/// Block-group allocation exhaustion.
///
/// btrfs carves the device into block groups up front. Once every byte is
/// claimed, writes stall searching for room inside fragmented existing groups
/// even though `df` still reports free space, because freeing data *inside* a
/// chunk does not release the chunk.
///
/// `disk_total` is already adjusted for the replication profile (DUP, RAID1,
/// RAID10), so no ratio arithmetic is needed and this is correct on any layout.
fn check_allocation(base: &Path, label: &str) -> Option<Warning> {
    let mut allocated = 0u64;
    for kind in ["data", "metadata", "system"] {
        allocated += read_u64(&base.join("allocation").join(kind).join("disk_total"))?;
    }

    let mut device_size = 0u64;
    if let Ok(devs) = fs::read_dir(base.join("devices")) {
        for d in devs.flatten() {
            // `size` is in 512-byte sectors.
            device_size += read_u64(&d.path().join("size")).unwrap_or(0) * 512;
        }
    }
    if device_size == 0 || allocated > device_size {
        return None;
    }

    let unallocated = device_size - allocated;
    let pct = unallocated as f64 / device_size as f64 * 100.0;
    if pct >= UNALLOCATED_FLOOR_PCT {
        return None;
    }
    Some(Warning {
        source: "btrfs".into(),
        severity: Severity::Warn,
        transient: false,
        message: format!(
            "{label}: only {:.1} MiB of {:.0} GiB is unallocated ({pct:.2}%). Every block \
             group is claimed, so writes stall searching fragmented chunks even though df \
             shows free space. Deleting files alone will not fix this — freeing data inside \
             a chunk does not release the chunk. Reclaim space first, then: \
             sudo btrfs balance start -dusage=50 -musage=50 <mountpoint>",
            unallocated as f64 / 1_048_576.0,
            device_size as f64 / 1_073_741_824.0,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_is_infallible_regardless_of_host_filesystem() {
        let _ = check();
    }

    #[test]
    fn read_u64_rejects_garbage() {
        assert_eq!(read_u64(Path::new("/nonexistent/path/xyz")), None);
        assert_eq!(read_u64(Path::new("/proc/version")), None);
    }

    #[test]
    fn discard_warning_respects_the_floor() {
        // Was `assert!(DISCARD_EXTENT_FLOOR >= 10_000)` — a tautology against a
        // constant defined as 10_000, which can never fail and only looked like
        // coverage. Exercise the actual decision instead, against a synthetic
        // sysfs tree.
        let tmp = std::env::temp_dir().join(format!("sw-btrfs-test-{}", std::process::id()));
        let disc = tmp.join("discard");
        let _ = fs::create_dir_all(&disc);
        let write = |name: &str, v: &str| {
            let _ = fs::write(disc.join(name), v);
        };

        write("discardable_extents", "500");
        write("discardable_bytes", "1048576");
        write("iops_limit", "1000");
        assert!(
            check_discard(&tmp, "test").is_none(),
            "a small steady-state queue must not be reported"
        );

        write("discardable_extents", "250000");
        let w = check_discard(&tmp, "test").expect("a large backlog must be reported");
        assert!(w.transient, "a discard backlog clears on its own");
        assert!(w.message.contains("250000"), "{}", w.message);
        assert!(
            w.message.contains("kernel"),
            "must explain why no process shows IO delay: {}",
            w.message
        );

        let _ = fs::remove_dir_all(&tmp);
    }
}
