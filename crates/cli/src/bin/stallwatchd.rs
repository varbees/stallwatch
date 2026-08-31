//! stallwatchd — resident stall recorder, so stalls can be asked about after
//! the fact.
//!
//! Event-driven by default. A PSI trigger per resource sits blocked in the
//! kernel and nothing runs on a healthy machine; when the kernel reports a
//! stall past the threshold, one capture samples the cgroup tree and pushes a
//! frame into a bounded ring. Query threads serve that ring over Unix sockets,
//! sharing it behind a mutex held only for the push or the read.
//!
//! `--poll` restores the old fixed-interval sampler, which is also the
//! automatic fallback when a kernel or container refuses to register triggers.
//!
//! Intended to run as a systemd *user* service. It needs no privileges and has
//! no business running as root.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stallwatch_core::attribution::Sampler;
use stallwatch_core::incident::{Culprit, Incident};
use stallwatch_core::ipc::incident_log_path;
use stallwatch_core::ipc::{Format, Request, socket_path, varlink_socket_path};
use stallwatch_core::psi::Resource;
use stallwatch_core::ring::{Frame, Ring};
use stallwatch_core::trigger::{Trigger, Wake};
use stallwatch_core::varlink::{self, Call, CallError};

const USAGE: &str = "\
stallwatchd — resident stall recorder

USAGE:
  stallwatchd [--tick MS] [--history SECS]

OPTIONS:
  --threshold MS       stall inside a 2s window that wakes a capture
                       (default 50). Event-driven; costs nothing when idle.
  --no-notify          do not announce stalls on the desktop
  --poll               force the old fixed-interval sampler instead
  --capture MS         window sampled once woken (default 400)
  --tick MS            polling interval when --poll or triggers are refused
                       (default 1000); paced slower if sweeps are expensive.
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

/// Run any rule whose `when` matches something in this incident.
///
/// Each rule fires at most once per incident, on the first stall that matches,
/// so a rule written for "the browser" does not fire five times because five
/// of its cgroups stalled together.
fn fire_rules(rules: &[stallwatch_core::config::Rule], incident: &Incident) {
    use stallwatch_core::config::expand;

    for rule in rules {
        let Some(hit) = incident.stalls.iter().find(|s| rule.when.matches(*s)) else {
            continue;
        };

        if rule.action.notify {
            // notify-send is the lowest common denominator on a Linux desktop
            // and absent on a server, so a failure here is not worth a word.
            let _ = std::process::Command::new("notify-send")
                .arg(format!("stallwatch: {}", rule.name))
                .arg(expand("{unit} froze you {delta_ms}ms on {resource}", hit))
                .status();
        }

        if let Some(template) = &rule.action.run {
            let cmd = expand(template, hit);
            // Through a shell, because a rule is something the user wrote for
            // themselves and pipes and redirects are the point of it.
            match std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmd)
                .status()
            {
                Ok(st) if !st.success() => {
                    eprintln!("stallwatchd: rule `{}` exited {st}", rule.name);
                }
                Err(e) => eprintln!("stallwatchd: rule `{}` failed: {e}", rule.name),
                _ => {}
            }
        }

        if let Some(path) = &rule.action.log {
            use std::io::Write as _;
            let written = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| writeln!(f, "{}", incident.to_jsonl()));
            if let Err(e) = written {
                eprintln!(
                    "stallwatchd: rule `{}` cannot write {}: {e}",
                    rule.name,
                    path.display()
                );
            }
        }
    }
}

/// Append one incident to the log.
///
/// Best-effort by design: a diagnostic that dies because it could not write a
/// log file is worse than one that quietly keeps watching. Failures are
/// reported once rather than on every capture.
fn append_incident(incident: &Incident) {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicBool, Ordering};
    static COMPLAINED: AtomicBool = AtomicBool::new(false);

    let path = incident_log_path();
    let write = || -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(f, "{}", incident.to_jsonl())
    };
    if let Err(e) = write()
        && !COMPLAINED.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "stallwatchd: cannot write {}: {e} (still watching; `stallwatch why` will find nothing)",
            path.display()
        );
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Register a PSI trigger per resource and capture only when one fires.
///
/// Returns false if no trigger could be registered, so the caller can fall
/// back to polling rather than sit silently recording nothing — the one
/// failure mode a diagnostic must never have.
fn start_trigger_capture(
    ring: &Arc<Mutex<Ring>>,
    threshold: Duration,
    capture_window: Duration,
    rules: Arc<Vec<stallwatch_core::config::Rule>>,
    notifier: Arc<Mutex<stallwatch_core::notify::Notifier>>,
) -> bool {
    // One watcher thread per resource. Each blocks on its own descriptor, so
    // the idle cost of the whole daemon is three parked threads.
    let (tx, rx) = mpsc::channel::<Resource>();
    let mut registered = 0;

    for res in Resource::ALL {
        // The kernel exposes no `full` line for CPU, so ask for the line that
        // actually exists for each resource.
        let kind = res.primary_kind();
        match Trigger::new(res, kind, threshold, Duration::from_secs(2)) {
            Ok(trigger) => {
                registered += 1;
                let tx = tx.clone();
                std::thread::spawn(move || {
                    loop {
                        match trigger.wait(None) {
                            Ok(Wake::Stalled) => {
                                if tx.send(trigger.resource()).is_err() {
                                    return; // capture thread gone
                                }
                            }
                            Ok(Wake::Quiet) => {}
                            Err(e) => {
                                eprintln!(
                                    "stallwatchd: {} trigger stopped: {e}",
                                    trigger.resource()
                                );
                                return;
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("stallwatchd: no {res} trigger: {e}"),
        }
    }
    drop(tx); // so the capture loop ends if every watcher dies

    if registered == 0 {
        return false;
    }

    let ring = Arc::clone(ring);
    std::thread::spawn(move || {
        while let Ok(first) = rx.recv() {
            // Several resources usually breach together — an IO storm starves
            // CPU too. Drain the rest so one event produces one capture rather
            // than three overlapping sweeps of the same moment.
            let mut woke_on = vec![first];
            while let Ok(also) = rx.try_recv() {
                if !woke_on.contains(&also) {
                    woke_on.push(also);
                }
            }

            // Sample across a short window while the stall is still happening.
            // The kernel rate-limits to one notification per window, so this
            // cannot spin even on a permanently stalled machine.
            let (stalls, causes, window_usec) =
                stallwatch_core::attribution::collect(capture_window);

            // Drill while the stall is still live. This is the only moment the
            // responsible process can be caught; by the time anyone asks, it
            // has exited.
            //
            // Probe the top few cgroups, not just the worst. PSI measures who
            // is BLOCKED, so the worst-hit cgroup is the casualty; the process
            // saturating the queue sits in a sibling showing far less pressure.
            // Drilling only stalls.first() reliably finds the victim and never
            // the cause, which is the exact mistake this tool exists to stop
            // other people making.
            // One sweep of the root cgroup, whose subtree is every process on
            // the machine. Root subsumes the individual stalling cgroups, so
            // drilling those as well only splits the time budget.
            //
            // The window matters more than the breadth. During a severe stall
            // even the process causing it is blocked and moving nothing, so a
            // short sample catches it looking like a bystander; measured at
            // 120ms a dd writing 3 GiB was repeatedly recorded at 0 bytes and
            // 16% blocked. A longer sweep sees the throughput that identifies
            // it as the cause.
            let mut culprits: Vec<Culprit> = stallwatch_core::process::drill(
                std::path::Path::new(stallwatch_core::cgroup::ROOT),
                Duration::from_millis(500),
                10,
            )
            .iter()
            .map(Culprit::from_proc)
            .collect();

            // A named cause is the whole point, so rank it first.
            culprits.sort_by_key(|c| match c.role {
                stallwatch_core::incident::Role::Cause => 0,
                stallwatch_core::incident::Role::Active => 1,
                stallwatch_core::incident::Role::Victim => 2,
            });
            culprits.truncate(6);

            let incident = Incident {
                at_unix: now_unix(),
                window_usec,
                woke_on: woke_on.iter().map(ToString::to_string).collect(),
                stalls: stalls.clone(),
                warnings: stallwatch_core::pathology::scan(),
                culprits,
                causes,
            };
            append_incident(&incident);
            fire_rules(&rules, &incident);

            // Announce last, so a slow notification daemon cannot delay the
            // record of what happened.
            let notice = notifier
                .lock()
                .ok()
                .and_then(|mut n| n.consider(&incident, incident.at_unix));
            if let Some(notice) = notice {
                stallwatch_core::notify::send(&notice);
            }

            if let Ok(mut r) = ring.lock() {
                r.push(Frame {
                    at_unix: incident.at_unix,
                    window_usec,
                    stalls,
                });
            }
        }
    });
    true
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
    let max_series = flag(
        "--max-series",
        stallwatch_core::metrics::DEFAULT_MAX_SERIES as u64,
    ) as usize;
    let metrics_listen = strflag("--metrics-listen");
    let metrics_textfile = strflag("--metrics-textfile");
    // Config first, flags over it. A flag is the most specific statement of
    // intent, so it must win over any file.
    let mut cfg = match stallwatch_core::config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("stallwatchd: {e}");
            eprintln!(
                "Refusing to start with a config it cannot parse; a silently dropped rule is worse."
            );
            std::process::exit(2);
        }
    };
    for (key, name) in [
        ("threshold_ms", "--threshold"),
        ("capture_ms", "--capture"),
        ("history_secs", "--history"),
    ] {
        if args.iter().any(|a| a == name) {
            cfg.note_flag(key, name);
        }
    }

    let tick_ms = flag("--tick", 1000).max(100);
    let force_poll = args.iter().any(|a| a == "--poll");
    let threshold =
        Duration::from_millis(flag("--threshold", cfg.threshold_ms.value).clamp(1, 900));
    let capture_window =
        Duration::from_millis(flag("--capture", cfg.capture_ms.value).clamp(50, 5_000));
    let duty = (flag("--duty", 2) as f64 / 100.0).clamp(0.001, 0.5);
    let history_secs = flag("--history", cfg.history_secs.value).max(10);

    if !stallwatch_core::psi_available() {
        eprintln!("stallwatchd: no PSI on this kernel (/proc/pressure missing); refusing to start");
        std::process::exit(1);
    }

    // One frame per tick, so capacity is history divided by tick length.
    let capacity = ((history_secs * 1000) / tick_ms).max(1) as usize;
    let ring = Arc::new(Mutex::new(Ring::new(capacity)));

    let listener = bind_or_die(&socket_path());
    let vlistener = bind_or_die(&varlink_socket_path());

    eprintln!(
        "stallwatchd: listening on {} and {} (tick {}ms, {} frames ~ {}s history)",
        socket_path().display(),
        varlink_socket_path().display(),
        tick_ms,
        capacity,
        history_secs
    );

    // Capture.
    //
    // Preferred mode is event-driven: register a PSI trigger per resource and
    // block. A healthy machine costs literally nothing, because there is no
    // timer, and a stall shorter than any sane polling interval is still caught
    // because the kernel is the one doing the watching.
    //
    // Everything else in this space polls, including oomd, whose default
    // interval is five seconds. A five-second poll cannot see a two-second
    // freeze except by luck.
    //
    // Polling remains as a fallback, because a kernel can be built without
    // trigger support and a container can refuse the write.
    let rules = Arc::new(std::mem::take(&mut cfg.rules));
    if !rules.is_empty() {
        eprintln!("stallwatchd: {} rule(s) loaded", rules.len());
    }

    // On by default. Notifying only when a rule says so means almost nobody
    // ever sees anything, because almost nobody writes rules.
    let notifier = Arc::new(Mutex::new(stallwatch_core::notify::Notifier::new(
        cfg.notify_enabled.value && !args.iter().any(|a| a == "--no-notify"),
        cfg.notify_min_peak.value as f64,
        Duration::from_secs(cfg.notify_cooldown_secs.value),
    )));
    if let Ok(n) = notifier.lock()
        && n.enabled
    {
        eprintln!(
            "stallwatchd: announcing stalls above {:.0}% peak, at most one per {}s",
            n.min_peak,
            n.cooldown.as_secs()
        );
    }

    if !force_poll
        && start_trigger_capture(
            &ring,
            threshold,
            capture_window,
            Arc::clone(&rules),
            Arc::clone(&notifier),
        )
    {
        eprintln!(
            "stallwatchd: event-driven; idle until a stall exceeds {}ms, then capturing {}ms",
            threshold.as_millis(),
            capture_window.as_millis()
        );
    } else {
        if !force_poll {
            eprintln!("stallwatchd: PSI triggers unavailable, falling back to polling");
        }
        // Retains the previous snapshot, so each tick costs ONE sweep of the
        // cgroup tree rather than two. On a 152-cgroup desktop a sweep is ~10ms;
        // on a 2,000-cgroup node it is over a hundred. A fixed tick harmless on
        // the former is ~26% of a core on the latter, which would make a tool
        // built to observe contention a cause of it. The interval is therefore
        // derived from measured sweep cost against a duty-cycle budget.
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
                if interval > floor && interval.abs_diff(announced) > Duration::from_millis(500) {
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
        std::thread::spawn(move || {
            loop {
                if let Err(e) = write_textfile(&path, max_series) {
                    eprintln!("stallwatchd: textfile write failed: {e}");
                }
                std::thread::sleep(Duration::from_secs(15));
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
                Some(f) => stallwatch_core::Report {
                    window_usec: f.window_usec,
                    stalls: f.stalls.clone(),
                    causes: Vec::new(),
                    warnings: Vec::new(),
                },
                None => stallwatch_core::Report::default(),
            };
            render(&report, fmt)
        }
        Some(Request::Since(secs, fmt)) => {
            let since = now_unix().saturating_sub(secs);
            let mut report = match ring.lock() {
                Ok(r) => r.aggregate(since),
                Err(_) => stallwatch_core::Report::default(),
            };
            // Pathology is point-in-time state, not history — evaluate it fresh
            // on query rather than storing a stale copy in every frame.
            report.warnings = stallwatch_core::pathology::scan();
            render(&report, fmt)
        }
        None => "{\"error\": \"expected PING | NOW | SINCE <secs>\"}".to_string(),
    };

    let _ = writeln!(out, "{reply}");
    let _ = out.flush();
}

fn render(r: &stallwatch_core::Report, fmt: Format) -> String {
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
            let _ = write_frame(
                &mut out,
                &varlink::error_for(&CallError::Malformed("not UTF-8")),
            );
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
                let r = stallwatch_core::observe(Duration::from_millis(window_ms));
                varlink::reply_report(&r)
            }
            Ok(Call::GetHistory { seconds }) => {
                let since = now_unix().saturating_sub(seconds);
                let mut r = match ring.lock() {
                    Ok(g) => g.aggregate(since),
                    Err(_) => stallwatch_core::Report::default(),
                };
                r.warnings = stallwatch_core::pathology::scan();
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
    let body = stallwatch_core::metrics::render(max_series);
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
            stallwatch_core::metrics::render(max_series),
        ),
        ("GET", "/") => (
            "200 OK",
            "text/html; charset=utf-8",
            "<html><body><a href=\"/metrics\">metrics</a></body></html>\n".to_string(),
        ),
        ("GET", _) => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
        _ => (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".to_string(),
        ),
    };

    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.flush();
}
