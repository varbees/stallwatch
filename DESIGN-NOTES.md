# Design notes: perception, and what the tool is allowed to do

## First, honestly, what that paper is

`CIA-RDP96-00788R001700210016-5` is the US Army's 1983 *Analysis and Assessment
of Gateway Process* — an assessment of the Monroe Institute's Hemi-Sync
technique, hemisphere synchronisation, altered states, and out-of-body
experience. It is a consciousness-research document, not a human-factors or
HCI paper, and its strict left-brain/right-brain division is dated
neuroscience.

So it validates nothing about interface design, and I am not going to pretend
otherwise. But three ideas in it are genuinely useful here, and one of them
reframes what this tool is. Taking those and leaving the rest.

---

## 1. Two channels, not one (from the hemisphere model, p.3)

The paper's frame: one mode is *"verbal and linear reasoning… screening
incoming stimuli by categorizing, assessing and assigning meaning"*, the other
is *"noncritical, holistic, nonverbal and pattern-oriented."*

The strict anatomy is wrong, but the functional split is real and survives in
modern terms as verbal versus spatial processing. The design consequence is
concrete:

**A diagnostic must speak in both channels, because they answer different
questions.**

- **Pattern channel** — shape, seen pre-attentively, before reading.
  Answers *"is something wrong, and roughly when?"*
- **Verbal channel** — a sentence.
  Answers *"what exactly, and whose fault?"*

Existing tools are pattern-only. htop and btop are walls of shape with no
sentence anywhere; you supply the interpretation. `below` is the same in a
different palette. That is why they inform without concluding.

The landing page already does this by accident and it is the strongest thing
on it: the stall ribbon is the pattern channel, *"one of these instruments is
lying to you"* is the verbal one. The TUI should be built the same way — every
screen carries a shape **and** a sentence, never only one.

## 2. Lamp versus laser (p.6)

The paper's metaphor for diffuse versus focused attention: an ordinary lamp
*"diffuses its energy over a wide area of rather limited depth"*; a laser
*"produces a disciplined stream."*

That is the dashboard problem stated better than I stated it in `DIRECTION.md`.
A monitor showing forty metrics is a lamp: everything lit, nothing resolved.
The user's attention is spread exactly as thin as the display.

**stallwatch should be a laser.** One question, one answer, full depth. That is
not a stylistic preference; it is the reason the smoke-alarm shape beats the
dashboard shape, and it is now the tie-breaker for any feature argument: does
this concentrate attention or diffuse it?

## 3. Biofeedback, which is the idea worth stealing (p.5)

This is the one that changes the framing.

> *"Biofeedback teaches the left hemisphere first to visualize the desired
> result and then to recognize the feelings associated with… success. Special
> self-monitoring devices such as the digital thermometer are used to inform
> the left brain when it succeeds."*

Strip the consciousness claims and the mechanism is: **an instrument makes an
invisible internal state perceptible, and perceptibility is what makes control
possible.** You cannot warm your hand deliberately until a thermometer tells
you when you are succeeding.

That is exactly the relationship between a person and a stalling machine. The
machine's contention is real, continuous and invisible. Nobody can act on it
because nobody can perceive it. Every existing tool shows *utilisation*, which
is the wrong signal — the equivalent of a thermometer wired to the wrong hand.

**stallwatch is biofeedback for a computer.** That is not a marketing line, it
is a design instruction with consequences:

- The loop must **close**. Feedback that arrives after the freeze ended and
  requires you to go looking is not a loop. This is the argument for
  notification-on-capture, from a direction I had not considered.
- The signal must be **the one that maps to the action**, not the one that is
  easy to collect. Utilisation is easy and useless; blocked time is harder and
  actionable.
- Success must be **as legible as failure**. A biofeedback device that only
  buzzes when you fail teaches nothing. If a user sets `io.max` on a cgroup and
  the stalls stop, the tool should say so. Nothing in this space does that.

---

## 4. Modes: what the tool is permitted to do

The Claude Code analogy is exact, and it resolves a tension I had left open.

`VISION.md` and the website both promise **"it will not fix anything."** That
promise is load-bearing: it is why someone runs an unknown diagnostic on a sick
machine. But the same cgroup files that expose pressure also expose `io.max`,
`memory.high` and `cpu.weight`. Reading is a doorway; writing is the room
behind it. Refusing to look through the door forever wastes the position.

Modes are how to have both, without breaking the promise:

| Mode | What it does | Default |
|---|---|---|
| **watch** | Observe and report. Strictly read-only. | **yes** |
| **explain** | Adds causation and pathology. Still read-only. | on request |
| **advise** | Prints the exact command that would bound this, and does not run it. Read-only. | opt-in |
| **act** | Applies a bounded, reversible limit and records a receipt. | explicit, per-invocation |

The properties that make `act` defensible rather than reckless:

- **Never the default.** It cannot be reached by accident, only by flag or by
  a config file the user wrote.
- **Bounded and reversible.** Setting `io.max` on one cgroup is undoable and
  survives nothing. It never kills, never restarts, never touches sysctl.
- **Receipted.** Every action writes what it changed, the previous value, and
  the exact command to revert. An action you cannot undo is an action you
  should not have taken.
- **Proves itself.** After acting, it measures whether the stall stopped. That
  is the closed biofeedback loop from §3, and it is the difference between a
  tool that acts and a tool that guesses.

`advise` is the sweet spot and should ship first. It carries all the value of
knowing what to do with none of the risk of doing it, and it is honest about
where the expertise lives: the tool knows what is stalling, you decide whether
to bound it.

## What this settles

- The TUI ships a shape and a sentence on every screen. Never one alone.
- Any feature that diffuses attention loses to one that concentrates it.
- Notification-on-capture moves up: it is what closes the loop, not a nicety.
- "Never fixes anything" becomes "never fixes anything **unless you explicitly
  ask, and then it shows its work and how to undo it**." The default is
  unchanged, so the trust is unchanged.
