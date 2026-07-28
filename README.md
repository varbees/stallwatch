# stallwatch

**Your Linux desktop freezes. `htop` says the CPU is idle and you have free RAM. So what stopped?**

```console
$ stallwatch
Over the last 1.0s, these units stalled the system:

    84.6%  io      com.mitchellh.ghostty  — frozen 858ms waiting on io
    11.2%  io      systemd-journald       — frozen 114ms waiting on io
     2.0%  cpu     zen (flatpak)          — frozen  21ms waiting on cpu

  worst cgroup: /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/
                app.slice/app-com.mitchellh.ghostty.service

   · btrfs [transient]: working through an async discard (TRIM) backlog: 131410
     extents / 3.3 GiB still queued after a large delete. This runs in the kernel,
     so the disk looks busy while no process shows IO delay. It clears on its own
     — do not go hunting for a runaway program. Roughly 3 min at the 1000 IOPS limit.
```

No privileges. No dependencies. 393 KB. The daemon is optional and only needed
for history.

---

## Why utilisation lies

Every monitor you have shows **utilisation** — what fraction of a resource is in use. That number cannot tell "working fine" from "completely jammed":

```
cpu   some avg10=1.6     ← CPU is idle
io    full avg10=51.3    ← everything is frozen half the time
```

A CPU graph reports a healthy machine here. In fact, for 51% of the last ten seconds, *every non-idle task on the system was blocked*.

Linux has measured this since 4.20 — **Pressure Stall Information**: how much time tasks spent unable to proceed. `some` means at least one task was blocked; `full` means every non-idle task was blocked at once. And crucially, the kernel writes `cpu.pressure`, `memory.pressure` and `io.pressure` into **every cgroup**, so the data to name a culprit has always been there.

Almost nothing reads it. htop, node_exporter and KDE's system monitor all surface the system-wide `/proc/pressure/*` files and stop. You learn *that* the machine stalled, never *who* stalled it.

That gap is what this fills.

## What it does that other PSI tools don't

**Names the responsible unit.** Kernel accounting is hierarchical — a stall inside `firefox.scope` also counts against `app.slice`, `user@1000.service`, `user.slice` and the root. Report that naively and the answer is always `user.slice`, which helps nobody. stallwatch walks the tree and blames a cgroup only when no single child owns ≥80% of its stall.

**Measures deltas, not averages.** `avg10/60/300` are exponentially damped, so a one-second freeze is smeared into a bump by the time you look. Each PSI file also carries `total=` — raw microseconds since boot. Sample it twice over a known monotonic window and you get the truth for exactly that window.

**Explains causes the numbers can't.** Three conditions produce identical-looking IO pressure and no desktop tool surfaces any of them:

| Condition | Why it's baffling without help |
|---|---|
| btrfs allocation exhaustion | `df` shows free space; the allocator has none. Deleting files doesn't help — freeing data inside a chunk doesn't release the chunk. |
| Async discard (TRIM) backlog | Disk 48% busy, **zero** processes with IO delay, because the work is kernel-side. Transient. |
| Drive at its thermal limit | Real mechanism — but only if the drive's throttle counters are non-zero. Usually they aren't. |

## Install

```sh
cargo install --path .
# or
cargo build --release && cp target/release/stallwatch ~/.local/bin/
```

Needs a kernel with `CONFIG_PSI=y` (near-universal). If your distribution builds with `CONFIG_PSI_DEFAULT_DISABLED=y` — openSUSE historically did — add `psi=1` to the kernel command line.

## Usage

```sh
stallwatch                    # one-second snapshot
stallwatch --watch            # refresh until Ctrl-C
stallwatch --window 3000      # three-second window
stallwatch --json             # machine-readable
stallwatch --processes        # name the process, not just the unit
```

### Naming the process, not just the unit

```console
$ stallwatch --processes
    83.5%  io      com.mitchellh.ghostty  — frozen 1015ms waiting on io

  inside ghostty-surface-transient:
    active   83% blocked  dd [214461]  ·  5 MiB of disk IO
```

Two things this had to get right, both learned by being wrong first:

**PSI blames the victim, not the cause.** It measures who is *blocked*. A `dd`
saturating the disk sat in a sibling cgroup with a fraction of the pressure of
the terminal it was starving — so drilling only the worst cgroup finds the
casualty and misses the culprit. `--processes` probes the top few.

**D-state alone is not enough.** A task throttled by dirty-page writeback is
counted as IO-stalled by PSI while showing state `S`. The terminal above
registered 83% pressure with no process ever caught in `D`. Block-layer byte
counters catch what state sampling cannot, so both are reported: high bytes with
low blocking is causing the stall, high blocking with low bytes is suffering it.

`delayacct_blkio_ticks` would give exact blocking time, but it is off by default
since 5.14 (`kernel.task_delayacct=0`) so it is used when present and never
depended on.

### "What just happened?"

A freeze is over by the time you can open a terminal and type. Live sampling
structurally cannot answer the question people actually ask, so `stallwatchd`
records continuously into a bounded ring and `--since` queries it:

```console
$ stallwatch --since 45
Over the last 45.0s, these units stalled the system:

    78.5%  io      com.mitchellh.ghostty  — frozen 22476ms waiting on io   (worst tick 91%)
    12.4%  io      systemd-journald       — frozen  3553ms waiting on io   (worst tick 17%)
     0.2%  memory  whole system           — frozen    59ms waiting on memory  (worst tick 11%)
```

That last row is why the daemon reports **peak per tick** and not just the
average. 0.2% reads as "nothing happened"; the 11% peak says there was a real
moment of memory pressure. Averaging over a long window destroys short events —
the same damping that makes the kernel's own `avg300` useless for catching
freezes. Ranking and noise-filtering are both done on the peak for this reason.

```sh
stallwatchd &                                  # foreground trial
cp systemd/stallwatchd.service ~/.config/systemd/user/
systemctl --user enable --now stallwatchd      # keep it running
```

~2.6 MB resident, one frame per second, 300 seconds of history by default.
It runs at idle IO priority and `Nice=10`: a tool that exists to observe
contention must never cause any.

The socket is `$XDG_RUNTIME_DIR/stallwatch.sock`, mode `0600`, and the protocol
is one line in and one document out — `socat` is a valid client:

```console
$ printf 'SINCE 60 text\n' | socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/stallwatch.sock
$ printf 'PING\n'          | socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/stallwatch.sock
PONG
```

## As a library

The engine is a library; the CLI is one thin client of it. The JSON above *is* the schema, and it is deliberately aligned with the vocabulary Kubernetes and cAdvisor already settled on (`container_pressure_*`, where `waiting` is PSI `some` and `stalled` is PSI `full`).

```rust
use std::time::Duration;

let report = stallwatch::observe(Duration::from_secs(1));
for stall in &report.stalls {
    println!("{} stalled {}ms on {}", stall.unit, stall.delta_usec / 1000, stall.resource);
}
for w in &report.warnings {
    println!("[{}] {}", w.severity, w.message);
}
```

## Design commitments

**No privileges.** Everything comes from `/sys` and `/proc` as the invoking user. A diagnostic that needs root is a diagnostic people don't run.

**No dependencies.** `std` only. This is load-bearing rather than aesthetic: the engine must stay reducible to a C ABI, because the projects best placed to consume it — btop, ksystemstats, GNOME's system monitor — are C and C++ and will not accept a Rust crate graph in their build.

**Never claim causation from correlation.** This one was learned expensively. An early thermal check saw a drive sensor at 97 °C and confidently reported thermal throttling as the cause of an IO stall. The drive's own counters — `Thermal Management T1/T2 Trans Count`, `Warning Temperature Time` — were all zero across 4,979 power-on hours. It had never throttled once. The sensor reading was real, the mechanism was plausible, the conclusion was wrong, and it cost hours.

That heuristic would also have fired on every healthy drive of the same family. So the rule now is: report the observation, name the command that settles it, let the human conclude. Sensors that publish no threshold are never warned on at any temperature.

**It never fixes anything.** stallwatch is read-only. It prints the command *you* might run and shows the exact `/sys` path every number came from, so you can re-read the kernel and check its arithmetic. It is an instrument, not an optimiser.

## Limitations

- **cgroup v2 and systemd only.** No v1 fallback.
- **Per-process drill-down is a second window.** `--processes` cannot know which
  cgroup is guilty until the first pass finishes, so it samples again straight
  after. For a sustained stall that is fine; a one-off spike may be gone, and it
  says so rather than implying otherwise.
- **No D-Bus yet.** The daemon speaks a Unix socket. D-Bus is the right
  integration surface — it is what lets KRunner, GNOME and waybar consume this
  without inheriting a Rust build dependency — but every Rust D-Bus crate is a
  dependency, and zero dependencies is what keeps the engine reducible to a C
  ABI. A D-Bus frontend will be another client of the same daemon.
- **Thermal checks cannot see throttle counters**, which need root. Hence the deliberate caution above.

## Roadmap

1. ~~Daemon with a ring buffer~~ — done
2. D-Bus interface, so adapters (KRunner, GNOME, waybar, Vicinae) are thin and no one inherits a Rust build dependency
3. ~~Per-process drill-down~~ — done
4. More pathologies: zram/zswap saturation, ZFS ARC pressure, dm-thin exhaustion, NVMe SMART wear

## License

MIT OR Apache-2.0
