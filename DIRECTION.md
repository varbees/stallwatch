# What stallwatch should be

Written after reading the source of htop, btop, bottom, below and oomd rather
than their documentation. Evidence in `_external/ANALYSIS.md`.

## The one-line version

**They built dashboards. This is a smoke alarm and a black box.**

Every PSI-aware tool in the field samples on a timer and renders what it saw.
None of them concludes anything, and none of them is awake at the moment that
matters. stallwatch should be the tool that costs nothing until the machine
actually stalls, and then already knows the answer.

## What it is

A **stall recorder**. Silent and free while the machine is healthy. The instant
the kernel says a stall crossed a threshold, it wakes, attributes, drills to
the process, and writes an incident you can read afterwards.

Three surfaces, one engine:

### 1. The recorder (the product)

Blocks on PSI triggers. Zero CPU when nothing is wrong, because there is no
timer. On wake it captures a full incident: which unit, which process inside
it, cause or victim, plus the pathology layer explaining conditions the numbers
alone cannot.

Nothing else does this. Not even oomd, which polls at 5s.

### 2. `stallwatch why` (the question people actually ask)

Nobody sits watching a monitor when their machine freezes. They notice
afterwards. Every existing tool answers "what is happening now"; the real
question is "what just happened to me". `below` can replay, but replay shows
you data and still leaves you to reason. This should answer in a sentence.

### 3. The embeddable engine (the compounding play)

Zero dependencies exists so the engine can reduce to a C ABI. htop, btop and
ksystemstats will never take a Rust crate graph, but they might take a small C
library that turns per-cgroup PSI into "this unit is responsible". htop already
reads PSI and already parses cgroups, and joins the two nowhere. That is an
integration, not a competition.

## What it is not

- **Not another TUI dashboard.** `below` has 2.5k stars, Meta behind it, and
  packages in Fedora, Alpine and Gentoo. Competing on graphs loses.
- **Not a general system monitor.** htop owns process browsing.
- **Not a metrics product.** The Prometheus and Varlink surfaces stay because
  they are cheap and already built, but they are not the identity.

## Why this wins where the others cannot

Polling tools cannot become this. Polling costs something on every tick
forever and still misses events shorter than the interval. Switching to
triggers is an architectural change, not a feature:

- **htop** discards `total=` at the `fscanf` (`%*f`) and its process table has
  no pressure awareness at all. It has a measurement ceiling, not a gap.
- **below** keeps the right data and iterates the hierarchy, but contains no
  function that attributes, ranks or dedupes hierarchical double-counting.
- **oomd** polls at 5s by default.

Attribution plus event-driven capture is a different product, not a better
version of theirs.

## Build order

1. **Trigger-driven daemon.** Replace the sampling loop with a blocked trigger.
   Wake, capture, record, sleep. Keep polling only as a fallback when triggers
   are unavailable.
2. **Incident model.** A stall becomes a first-class record with a timestamp,
   the culprit, the drill-down and the pathology, not a row in a ring buffer.
3. **`stallwatch why`.** Read incidents back in plain language.
4. **Desktop notification on capture.** This is what makes someone tell a
   friend: their machine froze and something told them why, unprompted.
5. **C ABI.** `libstallwatch` with a header, so the C and C++ monitors can
   adopt attribution without a Rust toolchain.
6. **TUI, last.** As the browser for recorded incidents, not a live dashboard.

## Known gaps to close first

- `cgroup_disable=pressure` removes every per-cgroup file while leaving
  `/proc/pressure` intact. Today that degrades silently to "no stalls found",
  which is the one failure mode a diagnostic must never have.
- `/proc/pressure/irq` exists on recent kernels and nothing reads it, this tool
  included. IRQ storms freeze desktops.
- Triggers need a polling fallback for kernels or containers that refuse them.

## The honest risk

Every repository in this portfolio has zero stars. The engineering is not the
bottleneck; distribution is. This direction is chosen partly because it
produces a story a person will repeat, and a dashboard does not: *my laptop
froze and something already knew why.*
