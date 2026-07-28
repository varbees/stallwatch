//! CLI front-end. Deliberately thin: all logic lives in the library, so the
//! daemon, a future D-Bus service and a C consumer get the same answers from
//! the same code path rather than three implementations that drift apart.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use stallwatch::ipc::socket_path;

const USAGE: &str = "\
stallwatch — name the unit that is stalling your Linux system

USAGE:
  stallwatch [--watch] [--json] [--window MS]
  stallwatch --since SECS [--json]

OPTIONS:
  --window MS    sampling window in milliseconds (default 1000)
  --watch        refresh continuously until Ctrl-C
  --since SECS   what happened over the last SECS seconds
                 (requires stallwatchd; a freeze is over by the time you
                  can type, so live sampling cannot answer this)
  --processes    after finding the guilty cgroup, name the process inside it
  --json         machine-readable output
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
    let num = |name: &str| -> Option<u64> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
    };

    if let Some(secs) = num("--since") {
        match query_daemon(secs, json) {
            Ok(reply) => print!("{reply}"),
            Err(e) => {
                eprintln!(
                    "stallwatch: cannot reach stallwatchd ({e}).\n\
                     \n\
                     History needs the daemon running — a freeze is over by the time\n\
                     you can open a terminal, so it has to already be recording.\n\
                     \n\
                       stallwatchd &                       # try it now\n\
                       systemctl --user enable --now stallwatchd   # keep it running"
                );
                std::process::exit(1);
            }
        }
        return;
    }

    if !stallwatch::psi_available() {
        eprintln!(
            "stallwatch: this kernel exposes no PSI (/proc/pressure is missing).\n\
             Needs CONFIG_PSI=y. If the kernel was built with \
             CONFIG_PSI_DEFAULT_DISABLED=y, add psi=1 to the kernel command line."
        );
        std::process::exit(1);
    }

    let window_ms = num("--window").unwrap_or(1000);
    let processes = args.iter().any(|a| a == "--processes");

    loop {
        let report = stallwatch::observe(Duration::from_millis(window_ms));

        if watch && !json {
            // Clear screen, home cursor.
            print!("\x1b[2J\x1b[H");
        }
        if json {
            println!("{}", report.to_json());
        } else {
            print!("{}", report.to_text());
            if processes {
                print!("{}", drill_top(&report, window_ms));
            }
        }

        if !watch {
            break;
        }
    }
}

/// Ask the daemon for history.
///
/// The daemon renders both formats server-side, so this client needs no JSON
/// parser — which is what keeps the whole crate dependency-free.
fn query_daemon(secs: u64, json: bool) -> std::io::Result<String> {
    let path = socket_path();
    let stream = UnixStream::connect(&path)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let fmt = if json { "json" } else { "text" };
    {
        let mut w = &stream;
        writeln!(w, "SINCE {secs} {fmt}")?;
        w.flush()?;
    }

    let mut out = String::new();
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        out.push_str(&line);
        line.clear();
    }
    Ok(out)
}

/// Second pass: name the processes behind the stall.
///
/// Drills the top few stalling cgroups, not just the worst one, and reports
/// blocking *and* block-layer bytes. Both choices were forced by observation:
///
/// - PSI blames the cgroup whose tasks are **blocked**, which is the victim,
///   not the cause. A `dd` saturating the disk sat in a sibling cgroup with a
///   fraction of the pressure of the terminal it was starving. Looking only at
///   the worst cgroup finds the casualty and misses the culprit.
/// - D-state alone is not enough. A task throttled by dirty-page writeback is
///   counted as IO-stalled by PSI while showing state `S`, so the terminal
///   above registered 83% pressure with no process ever caught in `D`. Byte
///   counters catch what state sampling cannot.
///
/// A process with high bytes and low blocking is causing the stall; high
/// blocking with low bytes is suffering it.
fn drill_top(report: &stallwatch::Report, window_ms: u64) -> String {
    use std::path::Path;
    use std::collections::HashSet;

    // Split the budget across the cgroups we probe so the flag costs roughly
    // one extra window regardless of how many we look at.
    let targets: Vec<&stallwatch::Stall> = {
        let mut seen = HashSet::new();
        report
            .stalls
            .iter()
            .filter(|s| seen.insert(s.cgroup.clone()))
            .take(3)
            .collect()
    };
    if targets.is_empty() {
        return String::new();
    }
    let each = Duration::from_millis((window_ms / targets.len() as u64).max(200));

    let mut o = String::new();
    let mut found_any = false;
    for t in &targets {
        let culprits = stallwatch::process::drill(Path::new(&t.cgroup), each, 12);
        if culprits.is_empty() {
            continue;
        }
        found_any = true;
        o.push_str(&format!("\n  inside {}:\n", t.unit));
        for c in &culprits {
            let mb = (c.read_bytes + c.write_bytes) as f64 / 1048576.0;
            let role = if mb >= 1.0 && c.blocked_pct() < 50.0 {
                "causing"
            } else if c.blocked_pct() >= 50.0 && mb < 1.0 {
                "waiting"
            } else {
                "active "
            };
            let io = if mb >= 0.1 {
                format!("  ·  {mb:.0} MiB of disk IO")
            } else {
                String::new()
            };
            let delay = match c.blkio_delay_ms {
                Some(ms) if ms > 0 => format!("  ·  {ms}ms blocked"),
                _ => String::new(),
            };
            o.push_str(&format!(
                "    {role}  {:>3.0}% blocked  {} [{}]{}{}\n",
                c.blocked_pct(),
                c.comm,
                c.pid,
                io,
                delay
            ));
        }
    }

    if !found_any {
        return format!(
            "\n  no process caught blocking or doing disk IO in a follow-up window\n\
             \x20 (the stall may have ended, or the work is kernel-side — see any\n\
             \x20  transient warning above)\n"
        );
    }
    if !stallwatch::process::delayacct_enabled() {
        o.push_str(
            "    (exact blocking time needs delay accounting: \
             sudo sysctl -w kernel.task_delayacct=1)\n",
        );
    }
    o
}
