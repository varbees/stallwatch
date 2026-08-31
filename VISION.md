# stallwatch as a full tool

Written after reading how Wireshark actually gets its power, what modern
terminal UIs are made of, and where Linux tools are expected to keep config.
Extends `DIRECTION.md`; does not replace it.

## The realisation about Wireshark

Wireshark's power is not the GUI. The GUI is a *view over a query engine*.
What actually makes it endlessly flexible is four things:

1. **Every value is a named, typed field** (`tcp.port`, `http.host`)
2. **A filter language over those fields**, composable with and/or/not
3. **A scripting hook** (Lua) so people extend it without touching C
4. **Taps** — anything can subscribe to the stream and compute on it

Copy that structure and stallwatch becomes open-ended rather than a fixed
report. A stall already has typed fields; they are just not addressable yet.

## 1. A filter language for stalls

Every field the engine already produces becomes queryable:

```
unit, cgroup, resource, kind, pct, peak, delta_ms
process.pid, process.comm, process.blocked_pct
process.read_bytes, process.write_bytes, process.role
warning.source, warning.severity, warning.transient
```

Which makes all of this expressible:

```sh
stallwatch --filter 'resource == io and peak > 70'
stallwatch --filter 'unit ~ "firefox|chrome" and delta_ms > 500'
stallwatch --filter 'process.role == cause and process.write_bytes > 100M'
stallwatch --filter 'warning.source == btrfs and not warning.transient'
```

Nothing in this space has this. htop has no query language at all; `below` has
fixed views. This is the single highest-leverage thing to build, because every
later surface (TUI, rules, alerts, exports) is a consumer of it rather than a
new feature.

## 2. Rules — where configuration becomes the product

Wireshark's taps, expressed as config. This is what makes it a tool people
live inside rather than run occasionally.

```toml
# ~/.config/stallwatch/config.toml

[capture]
threshold_ms = 50        # stall inside a 2s window that wakes a capture
capture_ms   = 400
resources    = ["io", "memory", "cpu"]

[[rule]]
name  = "the browser is eating my disk"
when  = 'resource == io and unit ~ "firefox|chrome|zen" and peak > 70'
notify = true
run   = "notify-send 'Disk stall' '{unit} froze you {delta_ms}ms'"

[[rule]]
name  = "quietly log everything else"
when  = 'peak > 40'
log   = "~/.local/state/stallwatch/incidents.jsonl"
```

`when` is the same filter language. One grammar, used by the CLI, the TUI, the
rules engine and the exporters. Learn it once.

## 3. The answer in a sentence

The Claude Code lesson is not colour or boxes, it is **refusing to make the
reader do the interpretation**. Compare what every existing tool gives you (a
table) with what this should give:

```console
$ stallwatch why
Your machine froze for 3.1s, about four minutes ago.

  ghostty was blocked on disk IO for 93% of that window, but it was the
  victim, not the cause. dd [214461] wrote 5 GiB through the same queue.

  btrfs was also working through a discard backlog at the time. That part
  clears itself.

  stallwatch why --verbose    the numbers behind this
  stallwatch why --filter …   other incidents
```

That is the product. Everything else is plumbing to make that paragraph true.

## 4. The TUI, and the dependency problem it creates

A good TUI means `ratatui`, which means dependencies, which collides head-on
with the zero-dependency property that lets the engine reduce to a C ABI.

**Resolve it by splitting the workspace rather than compromising either side:**

```
stallwatch-core   zero dependencies, std only. Engine, filter language,
                  attribution, pathology. This is what becomes libstallwatch
                  and what htop or ksystemstats could ever adopt.
stallwatch        the CLI. Zero dependencies. Thin shell over core.
stallwatch-tui    ratatui and whatever else it needs. Depends on core.
```

The claim stays honest and gets sharper: *the engine has no dependencies; the
optional TUI has the ones a TUI needs.* Nobody sensible objects to that, and
`cargo install stallwatch` still pulls nothing.

TUI surfaces, in order of worth:

- **Incident list** — what happened, when, who. The default screen.
- **Drill-down** — incident → unit → processes → pathology, one keypress each.
- **Filter bar** — `/` opens it, same grammar as everywhere else.
- **Live** — the least important view, and the one every competitor leads with.

Keyboard-first, `?` for a help overlay, and no feature that is only reachable
by knowing it exists.

## 5. Configuration, layered the way Linux expects

```
/etc/xdg/stallwatch/config.toml     packaged defaults
~/.config/stallwatch/config.toml    the user
STALLWATCH_* environment            the session
command-line flags                  this invocation
```

Later wins. `stallwatch config --explain` should print the resolved value for
every setting **and where it came from**, because the worst part of every
configurable Linux tool is not knowing which file won.

## Build order

1. ~~**Filter language.**~~ shipped
2. ~~**`stallwatch why`.**~~ shipped
3. ~~**Config file and rules engine.**~~ shipped, with `config --explain`
4. ~~**Notifications.**~~ shipped, then rebuilt — see below
5. ~~**Workspace split** into core/cli~~ shipped
6. **TUI.** Incident browser first, live view last. Not started.
7. **`libstallwatch` C ABI.** Not started.

## What the first month of real use corrected

Written after running the thing continuously on a daily driver for 30 days and
then reading its own 520,155 recorded incidents.

**The cause branch had never executed.** `Role::Cause` required bytes from
`/proc/<pid>/io`, which is unreadable for any process you do not own — and the
processes that stall a machine are kernel threads and root daemons. Zero causes
named in 29 days, while every individual report looked complete. Fixed by
reading the cgroup's own `io.stat`, which is world-readable and sits beside the
`io.pressure` already being read. Attribution is now unit-level, which is the
granularity a person acts on anyway.

**The notification policy was never tested against reality.** It would have sent
2,489 notifications over that month. It reported one 400ms capture of a
continuous condition, quoted the sampling window as though it were a freeze
duration, named a systemd unit rather than an application, and accused the
stalled unit rather than the one moving data. Rebuilt around episodes: 38
notifications over the same corpus.

**Nothing checked whether the evidence existed.** That is the failure that
allowed the other two to run for a month. `stallwatch doctor` now probes every
capability and states what each missing one costs; the daemon logs it at start.

The general lesson, which is not specific to this project: **a test suite that
only asserts against data the test itself fabricated proves self-consistency,
not truth.** 132 tests passed throughout. The bug was found by reading what the
tool had actually written to disk over a month, not by any of them.

## Directions closed by research

Recorded so they are not re-opened on a hunch.

- **Kubernetes / fleet PSI collection.** Kubernetes ships PSI at node, pod and
  container granularity, stable and locked on since v1.36 (first in v1.33). The
  platform does natively what an exporter here would offer, better placed.
- **The desktop notifier as a product.** `cdown/psi-notify` is the same idea by
  a Meta systemd maintainer, packaged across Debian/Fedora/EPEL/Ubuntu/Arch:
  242 stars after six years and no revenue attempt. Also `btop` 34k stars,
  `bottom` 14k, `htop` 8k — all $0.
- **A security pivot.** Attribution is the whole of a security product, and
  attribution without privilege is exactly what the constraints here forbid.
  Falco, Tetragon and Sysdig all run privileged because that is the job.

One finding worth publishing separately: `/proc/pressure` is not namespaced and
is absent from containerd's `MaskedPaths`, so a resource-limited container reads
the host's counters verbatim. `/sys/devices/virtual/powercap` is on that list,
masked for exactly this class of leak. That is a one-line upstream fix and a
writeup, not a product.

## What would make this half-arsed, and therefore what to refuse

- A live dashboard with no query language. That is btop with fewer features.
- A filter language that only the TUI can use.
- Config that cannot explain itself.
- Pulling dependencies into the engine for convenience, which forfeits the one
  thing that makes C and C++ adoption possible.
- Adding eBPF because it is fashionable. It needs root and kernel headers, and
  would cost the property that this runs anywhere as anyone.
