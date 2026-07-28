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

use stallwatch::ipc::{socket_path, varlink_socket_path, Format, Request};
use stallwatch::varlink::{self, Call, CallError};
use stallwatch::ring::{Frame, Ring};

const USAGE: &str = "\
stallwatchd — resident stall recorder

USAGE:
  stallwatchd [--tick MS] [--history SECS]

OPTIONS:
  --tick MS        sampling window per frame (default 1000)
  --history SECS   how much history to retain (default 300)
  -h, --help       this text

Serves two sockets in $XDG_RUNTIME_DIR:
  stallwatch.sock      line protocol: PING | NOW | SINCE <secs> [json|text]
  stallwatch.varlink   Varlink, e.g.
    varlinkctl call $XDG_RUNTIME_DIR/stallwatch.varlink \\
        dev.stallwatch.Monitor.GetHistory '{\"seconds\":30}'
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

    let listener = bind_or_die(&socket_path());
    let vlistener = bind_or_die(&varlink_socket_path());

    let path = socket_path();
    if false {
        if UnixStream::connect(&path).is_ok() {
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

    eprintln!(
        "stallwatchd: listening on {} and {} (tick {}ms, {} frames ~ {}s history)",
        socket_path().display(),
        varlink_socket_path().display(),
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

    {
        let ring = Arc::clone(&ring);
        std::thread::spawn(move || {
            for stream in vlistener.incoming().flatten() {
                let ring = Arc::clone(&ring);
                std::thread::spawn(move || handle_varlink(stream, ring));
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

/// Bind a Unix socket, clearing a socket left by an unclean exit.
fn bind_or_die(path: &std::path::Path) -> UnixListener {
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            eprintln!("stallwatchd: already running at {}", path.display());
            std::process::exit(1);
        }
        // Never swallow this: if the runtime dir is read-only (an over-tight
        // ProtectSystem= in a unit file) bind() then fails with a bare
        // "Address already in use" and sends people hunting for a process that
        // does not exist.
        if let Err(e) = std::fs::remove_file(path) {
            eprintln!(
                "stallwatchd: stale socket at {} could not be removed: {e}\n\
                 (nothing is listening on it. under systemd the unit likely needs \
                 ReadWritePaths=%t so $XDG_RUNTIME_DIR stays writable)",
                path.display()
            );
            std::process::exit(1);
        }
    }
    match UnixListener::bind(path) {
        Ok(l) => {
            use std::os::unix::fs::PermissionsExt;
            // Owner-only: the socket reveals which programs are stalling and
            // their cgroup paths, which is session-private.
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            l
        }
        Err(e) => {
            eprintln!("stallwatchd: cannot bind {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

/// Varlink: NUL-separated JSON, one call per frame.
fn handle_varlink(stream: UnixStream, ring: Arc<Mutex<Ring>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut out = stream;

    loop {
        let mut frame = Vec::new();
        // read_until on NUL is the whole framing layer.
        match reader.read_until(0, &mut frame) {
            Ok(0) => return,
            Ok(_) => {}
            Err(_) => return,
        }
        if frame.last() == Some(&0) {
            frame.pop();
        }
        let Ok(text) = String::from_utf8(frame) else {
            let _ = write_frame(&mut out, &varlink::error_for(&CallError::Malformed("not UTF-8")));
            return;
        };
        if text.trim().is_empty() {
            return;
        }

        let reply = match varlink::parse_call(&text) {
            Ok(Call::GetInfo) => varlink::reply_info(),
            Ok(Call::GetInterfaceDescription(iface)) => {
                if iface == varlink::INTERFACE {
                    varlink::reply_interface_description()
                } else {
                    varlink::error_for(&CallError::UnknownInterface(iface))
                }
            }
            Ok(Call::GetStalls { window_ms }) => {
                let r = stallwatch::observe(Duration::from_millis(window_ms));
                varlink::reply_report(&r)
            }
            Ok(Call::GetHistory { seconds }) => {
                let since = now_unix().saturating_sub(seconds);
                let mut r = match ring.lock() {
                    Ok(g) => g.aggregate(since),
                    Err(_) => stallwatch::Report::default(),
                };
                r.warnings = stallwatch::pathology::scan();
                varlink::reply_report(&r)
            }
            Err(e) => varlink::error_for(&e),
        };

        if write_frame(&mut out, &reply).is_err() {
            return;
        }
    }
}

fn write_frame(out: &mut UnixStream, s: &str) -> std::io::Result<()> {
    out.write_all(s.as_bytes())?;
    out.write_all(&[0])?;
    out.flush()
}
