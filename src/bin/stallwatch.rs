//! CLI front-end. Deliberately thin: every bit of logic lives in the library,
//! so a D-Bus daemon, a GNOME extension or a C consumer gets the same answers
//! from the same code path rather than a reimplementation.

use std::time::Duration;
use stallwatch::{Report, Severity};

const USAGE: &str = "\
stallwatch — name the unit that is stalling your Linux system

USAGE:
  stallwatch [--watch] [--json] [--window MS]

OPTIONS:
  --watch        refresh continuously until Ctrl-C
  --json         machine-readable output
  --window MS    sampling window in milliseconds (default 1000)
  -h, --help     this text

Reads /proc and /sys as the invoking user. No privileges required.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return;
    }

    let json = args.iter().any(|a| a == "--json");
    let watch = args.iter().any(|a| a == "--watch");
    let window_ms: u64 = args
        .iter()
        .position(|a| a == "--window")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);

    if !stallwatch::psi_available() {
        eprintln!(
            "stallwatch: this kernel exposes no PSI (/proc/pressure is missing).\n\
             Needs CONFIG_PSI=y. If the kernel was built with \
             CONFIG_PSI_DEFAULT_DISABLED=y, add psi=1 to the kernel command line."
        );
        std::process::exit(1);
    }

    loop {
        let report = stallwatch::observe(Duration::from_millis(window_ms));

        if watch && !json {
            // Clear screen, home cursor.
            print!("\x1b[2J\x1b[H");
        }
        if json {
            println!("{}", report.to_json());
        } else {
            print_human(&report);
        }

        if !watch {
            break;
        }
    }
}

fn print_human(r: &Report) {
    let secs = r.window_usec as f64 / 1e6;

    if r.stalls.is_empty() {
        println!("No significant stalls in the last {secs:.1}s. System is responsive.");
    } else {
        println!("Over the last {secs:.1}s, these units stalled the system:\n");
        for s in &r.stalls {
            println!(
                "  {:>6.1}%  {:<7} {}  — frozen {:.0}ms waiting on {}",
                s.pressure_pct,
                s.resource.to_string(),
                s.unit,
                s.delta_usec as f64 / 1000.0,
                s.resource
            );
        }
        println!("\n  worst cgroup: {}", r.stalls[0].cgroup);
    }

    for w in &r.warnings {
        let marker = match w.severity {
            Severity::Critical => "!!",
            Severity::Warn => " !",
            Severity::Note => " ·",
        };
        let tag = if w.transient { " [transient]" } else { "" };
        println!("\n  {marker} {}{tag}: {}", w.source, w.message);
    }
}
