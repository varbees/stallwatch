//! stallwatchd — resident sampler, so stalls can be asked about after the fact.
//!
//! Two threads: one samples the cgroup tree on a fixed tick and pushes frames
//! into a bounded ring, the other serves queries over a Unix socket. Both share
//! the ring behind a mutex held only for the push or the read.
//!
//! Intended to run as a systemd *user* service. It needs no privileges and has
//! no business running as root.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stallwatch::ipc::{socket_path, Format, Request};
use stallwatch::ring::{Frame, Ring};

const USAGE: &str = "\
stallwatchd — resident stall recorder

USAGE:
  stallwatchd [--tick MS] [--history SECS]

OPTIONS:
  --tick MS        sampling window per frame (default 1000)
  --history SECS   how much history to retain (default 300)
  -h, --help       this text

Serves queries on $XDG_RUNTIME_DIR/stallwatch.sock:
  PING | NOW | SINCE <secs>
";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return;
    }
    let flag = |name: &str, default: u64| -> u64 {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let tick_ms = flag("--tick", 1000).max(100);
    let history_secs = flag("--history", 300).max(10);

    if !stallwatch::psi_available() {
        eprintln!("stallwatchd: no PSI on this kernel (/proc/pressure missing); refusing to start");
        std::process::exit(1);
    }

    // One frame per tick, so capacity is history divided by tick length.
    let capacity = ((history_secs * 1000) / tick_ms).max(1) as usize;
    let ring = Arc::new(Mutex::new(Ring::new(capacity)));

    let path = socket_path();
    // A socket left behind by a killed daemon would make bind() fail with
    // EADDRINUSE forever. Only remove it if nobody is actually listening.
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            eprintln!("stallwatchd: already running at {}", path.display());
            std::process::exit(1);
        }
        // Nobody is listening, so this is a socket left by a killed daemon.
        // Do NOT swallow the removal error: if the runtime dir is read-only
        // (an over-tight ProtectSystem= in a unit file, for instance) bind()
        // then fails with a bare "Address already in use", which sends people
        // hunting for a running process that does not exist.
        if let Err(e) = std::fs::remove_file(&path) {
            eprintln!(
                "stallwatchd: stale socket at {} could not be removed: {e}\n\
                 (nothing is listening on it. if running under systemd, the unit \
                 likely needs ReadWritePaths=%t so $XDG_RUNTIME_DIR stays writable)",
                path.display()
            );
            std::process::exit(1);
        }
    }

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("stallwatchd: cannot bind {}: {e}", path.display());
            std::process::exit(1);
        }
    };
    // Owner-only. The socket exposes which programs are stalling and their
    // cgroup paths — session-private information, not world-readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    eprintln!(
        "stallwatchd: listening on {} (tick {}ms, {} frames ≈ {}s history)",
        path.display(),
        tick_ms,
        capacity,
        history_secs
    );

    // Sampler thread.
    {
        let ring = Arc::clone(&ring);
        std::thread::spawn(move || {
            loop {
                let (stalls, window_usec) =
                    stallwatch::attribution::collect(Duration::from_millis(tick_ms));
                let frame = Frame {
                    at_unix: now_unix(),
                    window_usec,
                    stalls,
                };
                // Lock only to push; never hold it across sampling, which
                // blocks for a full tick and would stall every query.
                if let Ok(mut r) = ring.lock() {
                    r.push(frame);
                }
            }
        });
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let ring = Arc::clone(&ring);
                // A slow or hostile client must not block the others.
                std::thread::spawn(move || handle(s, ring));
            }
            Err(e) => eprintln!("stallwatchd: accept failed: {e}"),
        }
    }
}

fn handle(stream: UnixStream, ring: Arc<Mutex<Ring>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }

    let mut out = stream;
    let reply = match Request::parse(&line) {
        Some(Request::Ping) => "PONG".to_string(),
        Some(Request::Now(fmt)) => {
            let guard = ring.lock();
            let report = match guard.as_ref().ok().and_then(|r| r.newest()) {
                Some(f) => stallwatch::Report {
                    window_usec: f.window_usec,
                    stalls: f.stalls.clone(),
                    warnings: Vec::new(),
                },
                None => stallwatch::Report::default(),
            };
            render(&report, fmt)
        }
        Some(Request::Since(secs, fmt)) => {
            let since = now_unix().saturating_sub(secs);
            let mut report = match ring.lock() {
                Ok(r) => r.aggregate(since),
                Err(_) => stallwatch::Report::default(),
            };
            // Pathology is point-in-time state, not history — evaluate it fresh
            // on query rather than storing a stale copy in every frame.
            report.warnings = stallwatch::pathology::scan();
            render(&report, fmt)
        }
        None => "{\"error\": \"expected PING | NOW | SINCE <secs>\"}".to_string(),
    };

    let _ = writeln!(out, "{reply}");
    let _ = out.flush();
}

fn render(r: &stallwatch::Report, fmt: Format) -> String {
    match fmt {
        Format::Json => r.to_json(),
        Format::Text => r.to_text(),
    }
}
