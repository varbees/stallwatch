//! Prove the event-driven path against a real stall.
//!
//! Registers an unprivileged PSI trigger, blocks, and reports how long the
//! kernel took to wake us once load started. Run it, then in another terminal
//! do something that touches the disk.
//!
//!     cargo run --release --example wait

use std::time::{Duration, Instant};

use stallwatch::psi::{PsiKind, Resource};
use stallwatch::trigger::{Trigger, Wake};

fn main() {
    if !stallwatch::psi_available() {
        eprintln!("no /proc/pressure on this kernel");
        return;
    }

    // 50ms of "some" IO stall inside a 2s window: the smallest window an
    // unprivileged process is allowed to ask for.
    let t = match Trigger::new(
        Resource::Io,
        PsiKind::Some,
        Duration::from_millis(50),
        Duration::from_secs(2),
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("could not register: {e}");
            return;
        }
    };

    println!(
        "watching io  threshold {}ms  window {}s  (unprivileged, uid {})",
        t.threshold().as_millis(),
        t.window().as_secs(),
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| s
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_string)))
            .unwrap_or_else(|| "?".into())
    );
    println!("blocked. no polling, no CPU burned. generate disk load…\n");

    let start = Instant::now();
    for n in 1..=3 {
        match t.wait(Some(Duration::from_secs(20))) {
            Ok(Wake::Stalled) => {
                println!(
                    "  [{n}] kernel woke us at {:>6.2}s — io stalled past the threshold",
                    start.elapsed().as_secs_f64()
                );
            }
            Ok(Wake::Quiet) => {
                println!("  [{n}] 20s with no stall past the threshold");
                break;
            }
            Err(e) => {
                eprintln!("  wait failed: {e}");
                break;
            }
        }
    }
}
