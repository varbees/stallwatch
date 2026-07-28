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
