//! Measure attribution scaling for real instead of projecting it.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use stallwatch::attribution::Responsibility;

/// Synthetic cgroup tree shaped like a busy node: slices -> services -> scopes.
fn tree(n: usize) -> HashMap<PathBuf, u64> {
    let mut d = HashMap::new();
    let services = (n / 20).max(1);
    for i in 0..n {
        let p = PathBuf::from("/sys/fs/cgroup/system.slice")
            .join(format!("svc{}.service", i % services))
            .join(format!("task{i}.scope"));
        d.insert(p, (i as u64 * 7919) % 1000);
    }
    for i in 0..services {
        d.insert(
            PathBuf::from("/sys/fs/cgroup/system.slice").join(format!("svc{i}.service")),
            500,
        );
    }
    d.insert(PathBuf::from("/sys/fs/cgroup/system.slice"), 900);
    d.insert(PathBuf::from("/sys/fs/cgroup"), 1000);
    d
}

fn main() {
    println!("{:>7}  {:>12}  {:>14}  {:>10}", "cgroups", "build (ms)", "queries (ms)", "per-cgroup");
    let mut prev: Option<(f64, f64)> = None;
    for n in [150usize, 500, 1000, 2000, 5000, 10000] {
        let d = tree(n);
        let t = Instant::now();
        let r = Responsibility::new(&d);
        let build = t.elapsed().as_secs_f64() * 1e3;

        let t = Instant::now();
        let mut kept = 0;
        for (p, &delta) in &d {
            if r.is_responsible(p, delta) { kept += 1; }
        }
        let query = t.elapsed().as_secs_f64() * 1e3;

        let total = build + query;
        let growth = prev.map(|(pn, pt)| format!("{:.2}x per {:.2}x n", total / pt, d.len() as f64 / pn));
        println!("{:>7}  {:>12.2}  {:>14.2}  {:>10.4}   {}  [{} responsible]",
                 d.len(), build, query, total / d.len() as f64,
                 growth.unwrap_or_default(), kept);
        prev = Some((d.len() as f64, total));
    }
    println!();
    println!("quadratic would show ~4x cost per 2x cgroups; linear-ish shows ~2x");
}
