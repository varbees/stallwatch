# Changelog

## v0.2.2 — 2026-08-31

Splits the two incident-log degradations that shared a status, so the report says
which one you have — the file does not exist yet, or rotation is not keeping it
under its cap. Caught by CI's clippy, which runs a newer toolchain than the
machine it was written on.

## v0.2.1 — 2026-08-31

`stallwatch doctor` also checks whether anything is actually watching: the daemon
answers on its socket, and the incident log is inside its cap. A tool that passes
every capability probe while its daemon is dead still tells you nothing, and the
question people ask is always retrospective.

The daemon's startup line no longer advertises the peak-pressure threshold it
stopped using in v0.2.0.

## v0.2.0 — 2026-08-31

The first month of continuous real use, and what reading its own output corrected.

### The cause branch had never executed

`Role::Cause` required at least 1 MiB read from `/proc/<pid>/io`. That file
returns `EACCES` for any process the invoking user does not own, and the
processes that stall a machine are kernel threads and root daemons —
`kworker/*`, `systemd-journald`, `mount.*`, `irq/*`. The rule was unreachable by
construction.

Measured across the author's own recorded incidents: **0 causes named in 520,155
incidents over 29 days**, with every report looking confident and complete.

Fixed by reading the cgroup's own `io.stat`, which is world-readable and sits in
the same directory as the `io.pressure` already being read. Attribution moves
from process to cgroup — a cgroup is a systemd unit, and a unit is what a person
acts on. Live cause resolution went from **0.00% to 76%** of sampled windows.

Two things the live test caught that the design did not anticipate:

- Ranking cannot be gated on role. A writer saturating a device is itself
  blocked once the device is saturated, so a `dd` moving 1.5 GiB classified as
  `Active` while a 21 MiB write took the headline. Ranking is now on bytes, with
  role reported as nuance.
- The root cgroup is never an accusation. It aggregates the machine, so it
  always has the largest count and can never be acted on.

### Notifications report the condition, not every symptom

Replayed over the same 30 days, the old policy would have sent **2,489**
notifications — one every seventeen minutes, indefinitely. The new one sends
**38**.

The old message was `com.mitchellh.ghostty froze for 405ms / Blocked on io for
99% of the window. (189 more since the last notice.)` Four defects, all fixed:

- `froze for 405ms` was the sampling window, not the freeze. Of 520,209
  incidents only 3 ever exceeded a second. No message quotes it now.
- It named a systemd unit. `.desktop` entries are now resolved, so it says
  Ghostty.
- It reported one instance of a chronic condition. The unit of notification is
  an episode: at least a tenth of the last ten minutes frozen, at most one
  notice per six hours.
- It accused the victim. It now names what was moving the data.

### `stallwatch doctor`

Probes every capability the engine depends on and states what each missing one
costs. On the machine where the original bug was found it says the thing that
would have exposed it on day one: `/proc/<pid>/io readable for 122 of 398
processes (31%)`. Reported as a ratio, never as a boolean, and never as healthy.
The daemon runs the same checks at startup and logs anything reduced.

### Fixed

- The incident log had no cap and had reached **364 MB in 30 days**. Now
  size-rotated with one generation kept, bounded at 128 MiB.
- `--version` and `-V` were unimplemented and silently ran the default report.
- Unknown flags were ignored — `stallwatch --pocesses` printed a plausible
  answer to a question nobody asked. Both now exit 2.
- The installer parity check in CI diffed a path that stopped existing when the
  site moved on 2026-08-04, so that job had been failing for 27 days.

### Documentation

The hero example in the README and on the landing page showed `active   83%
blocked  dd [214461]` — role `active`, not `cause`. The marketing proof shot was
itself an instance of the bug. Both regenerated from the fixed tool.

Claims withdrawn: cause attribution is unit-level, not process-level; the
Prometheus surface is not a differentiator, because Kubernetes has shipped PSI at
node, pod and container granularity since v1.36 (stable, locked) and v1.33
(first available).

### Tests

133 to 167. The new ones include a ground-truth test that generates real block IO
and asserts attribution names the cgroup that did it, taking truth from the
kernel's own accounting rather than the test's own write count. Reverting the fix
fails it. The old suite passed throughout the month the tool was wrong, because
every assertion was against data the tests themselves fabricated.

## v0.1.0 — 2026-07-31

First release. Per-cgroup PSI attribution, event-driven daemon, incident model,
`stallwatch why`, filter language, layered config with a rules engine, Varlink
and Unix socket IPC, Prometheus exporter, btrfs and thermal pathology.
