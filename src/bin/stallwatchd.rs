//! stallwatchd — resident sampler, so stalls can be asked about after the fact.
//!
//! Two threads: one samples the cgroup tree on a fixed tick and pushes frames
//! into a bounded ring, the other serves queries over a Unix socket. Both share
//! the ring behind a mutex held only for the push or the read.
//!
//! Intended to run as a systemd *user* service. It needs no privileges and has
//! no business running as root.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stallwatch::ipc::{socket_path, varlink_socket_path, Format, Request};
use stallwatch::varlink::{self, Call, CallError};
use stallwatch::attribution::Sampler;
use stallwatch::ring::{Frame, Ring};

const USAGE: &str = "\
stallwatchd — resident stall recorder

USAGE:
  stallwatchd [--tick MS] [--history SECS]

OPTIONS:
  --tick MS            minimum sampling interval (default 1000). The daemon
                       paces itself slower than this if sweeps are expensive.
  --duty PCT           share of one core sampling may use (default 2)
  --history SECS       how much history to retain (default 300)
  --metrics-listen A   serve Prometheus /metrics on A (e.g. 127.0.0.1:9836)
  --metrics-textfile P write P for node_exporter's textfile collector
  --max-series N       cardinality cap per scrape (default 500)
  -h, --help           this text

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
    let strflag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let max_series = flag("--max-series", stallwatch::metrics::DEFAULT_MAX_SERIES as u64) as usize;
    let metrics_listen = strflag("--metrics-listen");
    let metrics_textfile = strflag("--metrics-textfile");
    let tick_ms = flag("--tick", 1000).max(100);
    let duty = (flag("--duty", 2) as f64 / 100.0).clamp(0.001, 0.5);
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
    //
    // Retains the previous snapshot, so each tick costs ONE sweep of the cgroup
    // tree rather than two. On a 152-cgroup desktop a sweep is ~10ms; on a
    // 2,000-cgroup node it is over a hundred. A fixed tick that is harmless on
    // the former is ~26% of a core on the latter, which would make a tool built
    // to observe contention a cause of it. The interval is therefore derived
    // from measured sweep cost against a duty-cycle budget.
    {
        let ring = Arc::clone(&ring);
        let floor = Duration::from_millis(tick_ms);
        let ceil = Duration::from_secs(30);
        std::thread::spawn(move || {
            let mut sampler = Sampler::new();
            let mut interval = floor;
            let mut announced = Duration::ZERO;
            loop {
                std::thread::sleep(interval);
                let (stalls, window_usec) = sampler.tick();
                // Lock only to push; never across the sweep, which would block
                // every query for its duration.
                if let Ok(mut r) = ring.lock() {
                    r.push(Frame {
                        at_unix: now_unix(),
                        window_usec,
                        stalls,
                    });
                }
                interval = sampler.recommended_interval(duty, floor, ceil);
                // Say so when pacing diverges from what was asked for. Silently
                // sampling at a third of the requested rate would make every
                // number quietly wrong.
                if interval > floor
                    && interval.abs_diff(announced) > Duration::from_millis(500)
                {
                    eprintln!(
                        "stallwatchd: sweep costs {:.0}ms; pacing to {:.1}s to stay under {:.0}% of a core",
                        sampler.last_sweep().as_secs_f64() * 1000.0,
                        interval.as_secs_f64(),
                        duty * 100.0
                    );
                    announced = interval;
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

    if let Some(addr) = metrics_listen {
        match TcpListener::bind(&addr) {
            Ok(l) => {
                eprintln!("stallwatchd: serving metrics on http://{addr}/metrics");
                std::thread::spawn(move || {
                    for s in l.incoming().flatten() {
                        std::thread::spawn(move || serve_metrics(s, max_series));
                    }
                });
            }
            Err(e) => {
                eprintln!("stallwatchd: cannot bind {addr}: {e}");
                std::process::exit(1);
            }
        }
    }

    if let Some(path) = metrics_textfile {
        eprintln!("stallwatchd: writing textfile metrics to {path}");
        std::thread::spawn(move || loop {
            if let Err(e) = write_textfile(&path, max_series) {
                eprintln!("stallwatchd: textfile write failed: {e}");
            }
            std::thread::sleep(Duration::from_secs(15));
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

/// node_exporter's textfile collector.
///
/// Written to a temporary file and renamed, never written in place: the
/// collector may read at any moment and a partial document would be parsed as
/// truncated metrics rather than skipped. rename(2) within a directory is
/// atomic, so a reader sees either the old file or the new one.
fn write_textfile(path: &str, max_series: usize) -> std::io::Result<()> {
    let body = stallwatch::metrics::render(max_series);
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

/// A deliberately minimal HTTP/1.1 responder for Prometheus scrapes.
///
/// Prometheus issues `GET /metrics` and reads one response — it needs no
/// keep-alive, no chunking, no compression negotiation. Hand-rolling ~40 lines
/// keeps the zero-dependency property; pulling in an HTTP crate for this would
/// trade the property that makes the engine adoptable for nothing.
fn serve_metrics(mut stream: TcpStream, max_series: usize) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    // Drain headers so the client is not left writing into a closed pipe.
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let path = target.split('?').next().unwrap_or("");

    let (status, ctype, body) = match (method, path) {
        ("GET", "/metrics") => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            stallwatch::metrics::render(max_series),
        ),
        ("GET", "/") => (
            "200 OK",
            "text/html; charset=utf-8",
            "<html><body><a href=\"/metrics\">metrics</a></body></html>\n".to_string(),
        ),
        ("GET", _) => ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string()),
        _ => ("405 Method Not Allowed", "text/plain; charset=utf-8", "method not allowed\n".to_string()),
    };

    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}
