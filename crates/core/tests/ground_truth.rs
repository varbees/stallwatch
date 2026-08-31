//! Does attribution name a culprit we already know the answer for?
//!
//! Every unit test in this crate asserts against data the test itself
//! fabricated. That is how the original bug survived: `Role::Cause` was proven
//! correct against a synthetic process carrying 5 GiB of invented bytes, while
//! the kernel never supplied a single byte through that path in 29 days of real
//! use. A green suite proved self-consistency, not truth.
//!
//! This test makes the kernel supply the evidence. It generates real block IO
//! from this process, then asks the engine who did it, and fails if the answer
//! is not the cgroup this process lives in.
//!
//! # Why it self-skips
//!
//! It needs cgroup v2 with the io controller enabled on the cgroup holding the
//! test, and a writable filesystem that reaches a block device. Container CI
//! frequently has none of that. A test that cannot run must say so rather than
//! pass quietly — a silent skip is how you end up trusting a check that never
//! executed — so the skip reason is always printed.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// The cgroup this process is in, as an absolute path under the v2 mount.
fn own_cgroup() -> Option<PathBuf> {
    // cgroup v2 gives a single `0::<path>` line.
    let body = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = body
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim()
        .trim_start_matches('/');
    let path = PathBuf::from(stallwatch_core::cgroup::ROOT).join(rel);
    path.exists().then_some(path)
}

fn skip(why: &str) {
    println!("SKIP ground_truth: {why}");
}

#[test]
fn attribution_names_the_cgroup_that_actually_did_the_io() {
    let Some(cg) = own_cgroup() else {
        return skip("cannot resolve own cgroup (not cgroup v2?)");
    };
    if stallwatch_core::iostat::read(&cg).is_none() {
        return skip(&format!(
            "no io.stat at {} — the io controller is not enabled here",
            cg.display()
        ));
    }
    // Must reach a real block device. `std::env::temp_dir()` is NOT safe here:
    // /tmp is tmpfs on most current distributions, so writes land in RAM, no
    // cgroup is ever charged, and the test skips with a message blaming the
    // filesystem for a fault in the test. Cargo sets CARGO_TARGET_TMPDIR for
    // integration tests and it lives under `target/`, which is on real storage.
    let file = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("stallwatch-ground-truth.bin");

    // Write from this process for the whole observation window. It must
    // out-live the window: a transient cgroup that exits mid-window is torn
    // down and takes its io.stat with it, leaving the parent to absorb the
    // bytes. That is real behaviour, and it is why this test writes from the
    // test process itself rather than spawning a helper.
    //
    // Append to one growing file and fsync each chunk. An earlier version
    // recreated the file every pass, which counted 22 GiB of `write()` calls
    // while the truncations meant almost nothing reached the device — the test
    // measured its own API calls and believed it had generated disk IO.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let writer_path = file.clone();
    let writer = thread::spawn(move || {
        let chunk = vec![0u8; 4 * 1024 * 1024];
        let Ok(mut f) = fs::File::create(&writer_path) else {
            return;
        };
        while stop_rx.try_recv().is_err() {
            if f.write_all(&chunk).is_err() {
                break;
            }
            // Without this the bytes sit in page cache and never appear in
            // io.stat inside the window.
            if f.sync_all().is_err() {
                break;
            }
        }
    });

    // Ground truth comes from the kernel's own per-cgroup accounting, not from
    // this test's write() count. What is under test is the attribution logic —
    // de-duplication, ranking, thresholds — not whether the kernel counts
    // bytes correctly. Measuring our own io.stat delta over the same window
    // keeps the two separate.
    thread::sleep(Duration::from_millis(400));
    let before = stallwatch_core::iostat::read(&cg).unwrap_or_default();
    let report = stallwatch_core::observe(Duration::from_secs(2));
    let after = stallwatch_core::iostat::read(&cg).unwrap_or_default();
    let _ = stop_tx.send(());
    let _ = writer.join();
    let _ = fs::remove_file(&file);

    let moved = after.delta(before).total();
    if moved < stallwatch_core::MIN_CAUSE_BYTES {
        return skip(&format!(
            "only {} was charged to {} during the window — this filesystem or \
             container does not attribute writes to the writing cgroup, so there \
             is no ground truth to check against",
            stallwatch_core::bytes_phrase(moved),
            cg.display()
        ));
    }

    // io.stat is recursive, so the bytes appear at this cgroup and at every
    // ancestor. Hierarchical de-duplication should settle on one of them; any
    // of them is a correct answer, and naming none of them is the failure this
    // test exists to catch.
    let named: Vec<&str> = report
        .causes
        .iter()
        .filter(|c| c.is_nameable())
        .map(|c| c.cgroup.as_str())
        .collect();

    assert!(
        !named.is_empty(),
        "the kernel charged {} to {} but attribution named no cause at all.\ncauses: {:?}",
        stallwatch_core::bytes_phrase(moved),
        cg.display(),
        report.causes
    );

    let own = cg.to_string_lossy();
    let hit = named
        .iter()
        .any(|c| own.starts_with(*c) || c.starts_with(own.as_ref()));
    assert!(
        hit,
        "the kernel charged {} to {} but attribution blamed {:?} — none of which \
         is this cgroup or an ancestor of it",
        stallwatch_core::bytes_phrase(moved),
        own,
        named
    );
}

#[test]
fn a_quiet_system_is_not_accused_of_anything() {
    // The complement, and the cheaper half of the same guarantee: a threshold
    // low enough to name a culprit during real IO must not manufacture one when
    // nothing is happening. Only asserts about *this* cgroup, because the rest
    // of the machine is not under the test's control.
    let Some(cg) = own_cgroup() else {
        return skip("cannot resolve own cgroup");
    };
    if stallwatch_core::iostat::read(&cg).is_none() {
        return skip("no io.stat for own cgroup");
    }
    let report = stallwatch_core::observe(Duration::from_millis(700));
    let own = cg.to_string_lossy().into_owned();
    let accused_self = report
        .causes
        .iter()
        .any(|c| c.cgroup == own && c.bytes() >= stallwatch_core::MIN_CAUSE_BYTES);
    assert!(
        !accused_self,
        "idle test process was accused of moving data: {:?}",
        report.causes
    );
}
