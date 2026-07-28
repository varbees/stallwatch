#!/usr/bin/env bash
# Demo script for asciinema. Generates a REAL disk stall on the real
# filesystem — nothing here is staged or replayed. Writing to /tmp would
# prove nothing, since tmpfs never touches a block device.
set -u

G=$'\033[1;32m'; D=$'\033[2m'; Y=$'\033[1;33m'; R=$'\033[0m'
TARGET="$HOME/.stallwatch_demo_load"

typeit() {
  printf '%s$%s ' "$G" "$R"
  local s="$1"
  for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.025; done
  printf '\n'
}

cleanup() { kill "${LOAD_PID:-0}" 2>/dev/null; wait 2>/dev/null; rm -f "$TARGET"; }
trap cleanup EXIT

clear
printf '%s# The desktop just went unresponsive. Nothing looks wrong.%s\n\n' "$D" "$R"
sleep 1.5

# Start real load in the background, quietly.
dd if=/dev/zero of="$TARGET" bs=64k count=40000 oflag=dsync >/dev/null 2>&1 &
LOAD_PID=$!
sleep 2

typeit "free -h | head -2"
free -h | head -2
echo; sleep 1.8

typeit "uptime"
uptime
echo
printf '%s# RAM is fine. Load average says nothing useful.%s\n\n' "$D" "$R"
sleep 2

typeit "cat /proc/pressure/io"
cat /proc/pressure/io
echo
printf '%s# %sfull%s = share of time EVERY task was blocked. The machine is stopped.%s\n' "$D" "$Y" "$D" "$R"
printf '%s# But on what? /proc/pressure is system-wide. It cannot say.%s\n\n' "$D" "$R"
sleep 3

typeit "stallwatch --processes"
stallwatch --processes
echo
sleep 3.5
printf '%s# Named the unit, then the process inside it — no root, no config.%s\n' "$D" "$R"
sleep 2.5
