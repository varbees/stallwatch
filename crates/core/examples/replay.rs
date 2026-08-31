//! Measure how often attribution actually resolves a cause.
//!
//! ```sh
//! cargo run --release --example replay -- ~/.local/state/stallwatch/incidents.jsonl
//! cargo run --release --example replay -- --live 40
//! ```
//!
//! # Why both modes
//!
//! The recorded corpus is the *before* number and it can only ever be that.
//! Incidents written before this change contain process-level culprits and no
//! `io.stat` figures at all, so there is nothing in the file to re-attribute —
//! replaying them through the new code would measure the replay, not the fix.
//! Saying so is the point: the honest before/after needs the new evidence, and
//! the only place that exists is a live kernel.
//!
//! So: `replay <file>` reports what the recorded corpus actually contains, and
//! `--live N` samples N windows through the current engine and reports how
//! often it names something. Run both; compare.

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--live") => {
            let n: usize = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(20);
            live(n);
        }
        Some(path) => corpus(path),
        None => {
            eprintln!("usage: replay <incidents.jsonl> | replay --live [WINDOWS]");
            std::process::exit(2);
        }
    }
}

/// What the recorded file contains. No re-attribution: see the module note.
fn corpus(path: &str) {
    let Ok(f) = File::open(path) else {
        eprintln!("replay: cannot open {path}");
        std::process::exit(1);
    };
    let mut total = 0u64;
    let mut with_proc_cause = 0u64;
    let mut with_recorded_causes = 0u64;
    let mut culprit_entries = 0u64;
    let mut culprits_with_bytes = 0u64;

    for line in BufReader::new(f).lines().map_while(Result::ok) {
        total += 1;
        // Deliberately substring matching rather than a JSON parser: this is a
        // measurement script over a known-shape file, and the engine has no
        // parser dependency to borrow.
        if line.contains(r#""role":"cause""#) {
            with_proc_cause += 1;
        }
        if let Some(rest) = line.split(r#""causes":["#).nth(1)
            && !rest.starts_with(']')
        {
            with_recorded_causes += 1;
        }
        let mut hay = line.as_str();
        while let Some(i) = hay.find(r#""bytes":"#) {
            culprit_entries += 1;
            hay = &hay[i + 8..];
            if !hay.starts_with('0') {
                culprits_with_bytes += 1;
            }
        }
    }

    println!("Recorded corpus: {path}");
    println!("  incidents                     {total:>12}");
    println!(
        "  with a process-level cause    {with_proc_cause:>12}  ({:.2}%)",
        pct(with_proc_cause, total)
    );
    println!(
        "  with cgroup-level causes      {with_recorded_causes:>12}  ({:.2}%)",
        pct(with_recorded_causes, total)
    );
    println!("  culprit entries               {culprit_entries:>12}");
    println!(
        "  of those, any bytes at all    {culprits_with_bytes:>12}  ({:.2}%)",
        pct(culprits_with_bytes, culprit_entries)
    );
    println!();
    if with_recorded_causes == 0 {
        println!("  These incidents predate cgroup-level attribution, so they carry no");
        println!("  io.stat evidence to re-attribute. This is the BEFORE number only.");
        println!("  Run `replay --live N` for what the current engine resolves.");
    }
}

/// Sample live windows and report how often the engine names something.
fn live(windows: usize) {
    println!("Sampling {windows} live windows of 1s each...\n");
    let mut named = 0usize;
    let mut clear_cause = 0usize;
    let mut any_stall = 0usize;
    let mut examples: Vec<String> = Vec::new();

    for _ in 0..windows {
        let r = stallwatch_core::observe(Duration::from_secs(1));
        if !r.stalls.is_empty() {
            any_stall += 1;
        }
        if let Some(top) = r.causes.iter().find(|c| c.is_nameable()) {
            named += 1;
            if top.role == stallwatch_core::Role::Cause {
                clear_cause += 1;
            }
            if examples.len() < 5 {
                examples.push(format!(
                    "{} moved {} at {:.0}% own pressure [{}]",
                    top.unit,
                    stallwatch_core::bytes_phrase(top.bytes()),
                    top.pressure_pct,
                    top.role
                ));
            }
        }
    }

    println!("  windows sampled               {windows:>12}");
    println!("  windows with any stall        {any_stall:>12}");
    println!(
        "  windows naming a unit         {named:>12}  ({:.1}%)",
        pct(named as u64, windows as u64)
    );
    println!(
        "  of those, an unambiguous cause{clear_cause:>12}  ({:.1}% of all windows)",
        pct(clear_cause as u64, windows as u64)
    );
    if !examples.is_empty() {
        println!("\n  examples:");
        for e in &examples {
            println!("    {e}");
        }
    }
    println!();
    if named == 0 {
        println!("  NOTHING was named. The fix did not work on this machine —");
        println!("  run `stallwatch doctor` and check per-cgroup io.stat.");
    }
}

fn pct(n: u64, d: u64) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64 * 100.0
    }
}
