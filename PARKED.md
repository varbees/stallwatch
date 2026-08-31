# Parked 2026-08-31 — review 2026-10-01

Shipped v0.2.2 and stopped. Not abandoned: running, recording, and left alone
deliberately so the next look is at a month of evidence rather than an opinion.

## Why it is parked rather than continued

The engineering was never the bottleneck. Research on 2026-08-30 closed the
three directions that would have justified more building:

- **Kubernetes / fleet PSI.** Kubernetes ships PSI at node, pod and container
  granularity — stable and locked since v1.36, first available in v1.33. The
  platform already does natively what an exporter here would offer.
- **The desktop notifier as a product.** `cdown/psi-notify` is the same idea by
  a Meta systemd maintainer, packaged across Debian/Fedora/EPEL/Ubuntu/Arch:
  242 stars in six years, no revenue attempt. `btop` 34k stars, `bottom` 14k,
  `htop` 8k — all $0.
- **A security pivot.** Attribution is the whole of a security product, and
  attribution without privilege is what the design commitments here forbid.
  Falco, Tetragon and Sysdig all run privileged because that is the job.

So this is a portfolio and credibility asset that now actually works, not a
revenue line. Treat it that way in October.

## What to measure on 2026-10-01

Run these. Do not reason from memory — every number below was wrong once.

```sh
stallwatch doctor                       # still healthy, daemon still up?
stallwatch why                          # does the paragraph make sense?
cargo run --release --example replay -- ~/.local/state/stallwatch/incidents.jsonl
cargo run --release --example replay -- --notify ~/.local/state/stallwatch/incidents.jsonl
```

Against the v0.2.x baselines, all measured on this machine over the 30 days to
2026-08-31:

| | before v0.2.0 | at v0.2.2 | check in October |
|---|---|---|---|
| incidents with a named cause | 4 / 521,290 (0.00%) | 76% of live windows | should stay high |
| notifications / 30 days | 2,489 | 38 | did any actually arrive? |
| incident log | 364 MB, unbounded | capped 128 MiB | is rotation holding? |
| GitHub stars | 1 | 1 | any human contact at all? |
| crates.io downloads | 18 | — | organic, or still CI? |

The pre-fix corpus is kept at
`~/.local/state/stallwatch/incidents.jsonl.pre-v0.2.0` (364 MB). Every number in
the v0.2.0 changelog was derived from it; delete it only after October.

## The questions October should answer

1. **Did a notification ever fire, and was it useful when it did?** 38 per month
   was calibrated on a chronically stalling machine. If the KWin fix below took,
   the honest expectation is close to zero — and zero notifications from a
   healthy machine is the correct outcome, not a failure.
2. **Did anyone find it?** One star and 18 downloads after a month of being live
   is the real signal, and it is not about the code.
3. **Is the daemon still worth running?** It costs ~25 min of CPU per week and
   writes continuously. If nothing has consulted `stallwatch why` in a month,
   that is the answer.

## Left deliberately undone

- **`/proc/pressure/irq` is unread.** IRQ storms freeze desktops and nothing
  here looks at them. The cheapest remaining real feature.
- **C ABI (`libstallwatch`).** The compounding play if adoption ever appears.
  Pointless before it does.
- **TUI.** Explicitly last, and still last.
- **The containerd finding.** `/proc/pressure` is not namespaced and is absent
  from containerd's `MaskedPaths`, so a resource-limited container reads the
  host's counters verbatim (verified). `/sys/devices/virtual/powercap` is on
  that list, masked for exactly this class of leak. That is a one-line upstream
  PR and a writeup — worth reputation, not a product, and independent of
  everything above.

## Machine-specific, not a stallwatch issue

This machine's chronic stalling was traced to KWin, not to anything stallwatch
does: `plasma-kwin_wayland` emitted ~100 log lines/second in a GL error loop
(348,407 records in one hour), which journald wrote to disk continuously and
which saturated IO.

Rate-limited on 2026-08-31 via
`~/.config/systemd/user/plasma-kwin_wayland.service.d/ratelimit.conf`. Takes
effect from the next login. In October, confirm it held:

```sh
journalctl --user -u plasma-kwin_wayland --since "-20min" | wc -l
```

Still outstanding and needs root: the journal is 4 GB and could not be vacuumed.

```sh
sudo journalctl --vacuum-time=7d
```
