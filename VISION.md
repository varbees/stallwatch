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

1. **Filter language.** Parser plus evaluator over the existing `Stall` fields.
   Everything downstream consumes it. Zero deps, lives in core.
2. **`stallwatch why`.** The sentence. Needs the incident model from DIRECTION.
3. **Config file and rules engine.** XDG layering, `--explain` resolution.
4. **Notifications.** The moment it stops being a tool you run and becomes one
   that tells you.
5. **Workspace split** into core/cli/tui once the TUI is real work.
6. **TUI.** Incident browser first, live view last.
7. **`libstallwatch` C ABI.** The compounding play: htop already reads PSI and
   already parses cgroups and joins them nowhere.

## What would make this half-arsed, and therefore what to refuse

- A live dashboard with no query language. That is btop with fewer features.
- A filter language that only the TUI can use.
- Config that cannot explain itself.
- Pulling dependencies into the engine for convenience, which forfeits the one
  thing that makes C and C++ adoption possible.
- Adding eBPF because it is fashionable. It needs root and kernel headers, and
  would cost the property that this runs anywhere as anyone.
