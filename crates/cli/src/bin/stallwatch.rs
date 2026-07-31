//! CLI front-end. Deliberately thin: all logic lives in the library, so the
//! daemon, a future D-Bus service and a C consumer get the same answers from
//! the same code path rather than three implementations that drift apart.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use stallwatch_core::ipc::socket_path;

const USAGE: &str = "\
stallwatch — name the unit that is stalling your Linux system

USAGE:
  stallwatch [--watch] [--json] [--window MS]
  stallwatch --since SECS [--json]
  stallwatch --filter EXPR
  stallwatch why [--filter EXPR] [-n COUNT]

OPTIONS:
  --window MS    sampling window in milliseconds (default 1000)
  --watch        refresh continuously until Ctrl-C
  --since SECS   what happened over the last SECS seconds
                 (requires stallwatchd; a freeze is over by the time you
                  can type, so live sampling cannot answer this)
  --processes    after finding the guilty cgroup, name the process inside it
  --json         machine-readable output
  --filter EXPR  keep only stalls matching an expression, e.g.
                   'resource == io and peak > 70'
                   'unit ~ firefox|chrome and delta_ms > 500'
  --fields       list every field a filter can name
  -n COUNT       with `why`, how many incidents to show (default 1)
  -h, --help     this text

COMMANDS:
  why            what actually stopped you, in plain words, from what
                 stallwatchd recorded while it was happening

Reads /proc and /sys as the invoking user. No privileges required.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return;
    }

    if args.iter().any(|a| a == "--fields") {
        println!("Fields available to --filter:\n");
        for (name, help) in stallwatch_core::filter::FIELDS {
            println!("  {name:<20} {help}");
        }
        println!(
            "\nOperators: == != > < >= <=  and  ~ (contains, | means or)\n\
             Combine with: and  or  not  ( )\n\
             Numbers take suffixes: 500ms  2s  100M  1GiB"
        );
        return;
    }

    // Compile before doing any sampling: a typo should fail in microseconds,
    // not after a full window has elapsed.
    let filter = match args.iter().position(|a| a == "--filter") {
        Some(i) => match args.get(i + 1) {
            Some(expr) => match stallwatch_core::filter::Filter::parse(expr) {
                Ok(f) => Some(f),
                Err(e) => {
                    eprintln!("stallwatch: bad filter: {e}");
                    eprintln!("  {expr}");
                    eprintln!("  {}^", " ".repeat(e.at));
                    eprintln!("\nRun `stallwatch --fields` to see what you can filter on.");
                    std::process::exit(2);
                }
            },
            None => {
                eprintln!("stallwatch: --filter needs an expression");
                std::process::exit(2);
            }
        },
        None => None,
    };

    if args.first().is_some_and(|a| a == "why") {
        why(&args, filter.as_ref());
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

    if !stallwatch_core::psi_available() {
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
        let mut report = stallwatch_core::observe(Duration::from_millis(window_ms));

        // Filter after sampling, never before: the attribution has to see the
        // whole tree to decide who is responsible. Narrowing the input would
        // change the answer rather than narrowing the view of it.
        if let Some(f) = &filter {
            use stallwatch_core::filter::Queryable as _;
            report.stalls.retain(|st| f.matches(st));
            report
                .warnings
                .retain(|w| f.matches(w) || w.field_str("warning.source").is_none());
        }

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
fn drill_top(report: &stallwatch_core::Report, window_ms: u64) -> String {
    use std::collections::HashSet;
    use std::path::Path;

    // Split the budget across the cgroups we probe so the flag costs roughly
    // one extra window regardless of how many we look at.
    let targets: Vec<&stallwatch_core::Stall> = {
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
        let culprits = stallwatch_core::process::drill(Path::new(&t.cgroup), each, 12);
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
        return "\n  no process caught blocking or doing disk IO in a follow-up window\n\
             \x20 (the stall may have ended, or the work is kernel-side — see any\n\
             \x20  transient warning above)\n"
            .to_string();
    }
    if !stallwatch_core::process::delayacct_enabled() {
        o.push_str(
            "    (exact blocking time needs delay accounting: \
             sudo sysctl -w kernel.task_delayacct=1)\n",
        );
    }
    o
}

/// Answer "what just happened to me" from what the daemon recorded.
///
/// Live sampling structurally cannot answer this: a freeze is over by the time
/// anyone can open a terminal and type. The daemon catches the culprit while it
/// is still running, which is the only moment it exists to be caught.
fn why(args: &[String], filter: Option<&stallwatch_core::filter::Filter>) {
    let count: usize = args
        .iter()
        .position(|a| a == "-n")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);

    let path = stallwatch_core::ipc::incident_log_path();
    let Ok(body) = std::fs::read_to_string(&path) else {
        eprintln!(
            "No incident log at {}.\n\n\
             stallwatchd records what stalled while it is happening, because a\n\
             freeze is over by the time you can type. Start it with:\n\n    \
             systemctl --user enable --now stallwatchd\n",
            path.display()
        );
        std::process::exit(1);
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Newest first: the question is always about the most recent freeze.
    let mut shown = 0;
    for line in body.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let Some(incident) = parse_incident(line) else {
            continue;
        };
        if let Some(f) = filter
            && !incident.stalls.iter().any(|st| f.matches(st))
        {
            continue;
        }
        if shown > 0 {
            println!();
        }
        print!("{}", incident.explain(now));
        shown += 1;
        if shown >= count {
            break;
        }
    }

    if shown == 0 {
        println!(
            "Nothing recorded that matches. The machine has not stalled, or the filter excluded everything."
        );
    }
}

/// Rebuild an incident from one logged line.
///
/// Only the fields `explain` needs are recovered; the log is a superset and is
/// allowed to gain fields without this having to change.
fn parse_incident(line: &str) -> Option<stallwatch_core::incident::Incident> {
    use stallwatch_core::incident::{Culprit, Incident, Role};
    use stallwatch_core::json::{self, Json};
    use stallwatch_core::{PsiKind, Resource, Severity, Stall, Warning};

    let v = json::parse(line).ok()?;
    let num = |o: &Json, k: &str| o.get(k).and_then(Json::as_u64).unwrap_or(0);
    let txt = |o: &Json, k: &str| o.get(k).and_then(Json::as_str).unwrap_or("").to_string();

    let stalls = v
        .get("stalls")
        .and_then(Json::as_array)
        .map(|arr| {
            arr.iter()
                .map(|s| Stall {
                    unit: txt(s, "unit"),
                    cgroup: txt(s, "cgroup"),
                    resource: match txt(s, "resource").as_str() {
                        "cpu" => Resource::Cpu,
                        "memory" => Resource::Memory,
                        _ => Resource::Io,
                    },
                    kind: if txt(s, "type") == "some" {
                        PsiKind::Some
                    } else {
                        PsiKind::Full
                    },
                    delta_usec: num(s, "delta_usec"),
                    pressure_pct: s.get("pressure_pct").and_then(Json::as_f64).unwrap_or(0.0),
                    peak_pct: s.get("peak_pct").and_then(Json::as_f64).unwrap_or(0.0),
                })
                .collect()
        })
        .unwrap_or_default();

    let warnings = v
        .get("warnings")
        .and_then(Json::as_array)
        .map(|arr| {
            arr.iter()
                .map(|w| Warning {
                    source: txt(w, "source"),
                    severity: match txt(w, "severity").as_str() {
                        "critical" => Severity::Critical,
                        "warn" => Severity::Warn,
                        _ => Severity::Note,
                    },
                    transient: w.get("transient").and_then(Json::as_bool).unwrap_or(false),
                    message: txt(w, "message"),
                })
                .collect()
        })
        .unwrap_or_default();

    let culprits = v
        .get("culprits")
        .and_then(Json::as_array)
        .map(|arr| {
            arr.iter()
                .map(|c| Culprit {
                    pid: num(c, "pid") as u32,
                    comm: txt(c, "comm"),
                    blocked_pct: c.get("blocked_pct").and_then(Json::as_f64).unwrap_or(0.0),
                    bytes: num(c, "bytes"),
                    role: match txt(c, "role").as_str() {
                        "cause" => Role::Cause,
                        "victim" => Role::Victim,
                        _ => Role::Active,
                    },
                })
                .collect()
        })
        .unwrap_or_default();

    Some(Incident {
        at_unix: num(&v, "at_unix"),
        window_usec: num(&v, "window_usec"),
        woke_on: Vec::new(),
        stalls,
        warnings,
        culprits,
    })
}
