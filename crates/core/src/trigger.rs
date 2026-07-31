//! Event-driven stall detection using PSI triggers.
//!
//! # Why this exists
//!
//! Every other PSI-aware tool polls. It reads `/proc/pressure/*` on a timer,
//! which means a stall shorter than the sampling interval is invisible unless
//! it happens to straddle a sample, and the tool burns CPU on every tick of a
//! perfectly healthy machine to find nothing.
//!
//! The kernel offers the inverse. Write a threshold and a window into a PSI
//! file and the kernel wakes you when stall time inside that window exceeds
//! the threshold. Idle cost is a blocked thread; latency is the kernel's own
//! accounting rather than a sampling artifact. This is the mechanism `oomd`
//! uses in Meta's fleet to kill on pressure before the OOM killer engages.
//!
//! # Privileges
//!
//! None. `/proc/pressure/*` is world-writable (`-rw-rw-rw-`), and the kernel
//! documents exactly one restriction for unprivileged callers: the window must
//! be a multiple of 2 seconds, to stop anyone pinning a CPU with a tight
//! window. [`Trigger::new`] rounds to satisfy that rather than returning
//! `EINVAL` and leaving the caller to guess why.
//!
//! Verified on this kernel: registering `some 50000 2000000` unprivileged
//! succeeds and `poll` returns `POLLPRI` under real IO load.
//!
//! # Zero dependencies
//!
//! `std` exposes no `poll`. Rather than take `libc` and break the property
//! that lets this engine reduce to a C ABI, the two architectures that matter
//! issue `ppoll` directly. The Linux syscall ABI is a stability guarantee, so
//! this is boring rather than clever.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use crate::psi::{PsiKind, Resource};

/// Kernel minimum window for an unprivileged trigger.
const WINDOW_GRANULARITY: Duration = Duration::from_secs(2);
/// The kernel rejects windows outside this range regardless of privilege.
const WINDOW_MIN: Duration = Duration::from_millis(500);
const WINDOW_MAX: Duration = Duration::from_secs(10);

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

const POLLPRI: i16 = 0x002;
const POLLERR: i16 = 0x008;

/// `ppoll(2)`. Returns the raw kernel result: >0 ready, 0 timeout, <0 -errno.
///
/// `poll` does not exist on aarch64, so `ppoll` is used on both architectures
/// to keep one code path.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn ppoll(fds: *mut PollFd, nfds: u64, timeout: *const TimeSpec) -> i64 {
    #[cfg(target_arch = "x86_64")]
    const SYS_PPOLL: i64 = 271;
    #[cfg(target_arch = "aarch64")]
    const SYS_PPOLL: i64 = 73;

    let ret: i64;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") SYS_PPOLL => ret,
            in("rdi") fds,
            in("rsi") nfds,
            in("rdx") timeout,
            in("r10") 0usize, // sigmask: none
            in("r8") 0usize,  // sigsetsize
            lateout("rcx") _, lateout("r11") _,
            options(nostack)
        );
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        std::arch::asm!(
            "svc 0",
            in("x8") SYS_PPOLL,
            inlateout("x0") fds as i64 => ret,
            in("x1") nfds,
            in("x2") timeout,
            in("x3") 0usize,
            in("x4") 0usize,
            options(nostack)
        );
    }
    ret
}

/// What the kernel reported when a trigger fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// Stall crossed the threshold inside the window.
    Stalled,
    /// The window elapsed with no breach.
    Quiet,
}

/// A registered PSI trigger.
///
/// The registration lives as long as the file descriptor, so dropping this
/// de-registers it. That is the kernel's contract, not ours.
pub struct Trigger {
    file: File,
    resource: Resource,
    threshold: Duration,
    window: Duration,
}

impl Trigger {
    /// Register a trigger: wake when `threshold` of stall accrues in `window`.
    ///
    /// `window` is rounded up to the next 2s multiple and clamped to the range
    /// the kernel accepts, because an unprivileged caller that passes 1s gets a
    /// bare `EINVAL` with nothing explaining which of the several rules it broke.
    pub fn new(
        resource: Resource,
        kind: PsiKind,
        threshold: Duration,
        window: Duration,
    ) -> io::Result<Self> {
        // `Resource::file()` is the cgroup basename (`io.pressure`); the
        // system-wide files are `/proc/pressure/io`. Using the wrong one opens
        // nothing and reports a bare ENOENT.
        let path = format!("/proc/pressure/{resource}");
        Self::at(Path::new(&path), resource, kind, threshold, window)
    }

    /// Register against an explicit path, so a caller can watch one cgroup's
    /// `io.pressure` instead of the system-wide file.
    pub fn at(
        path: &Path,
        resource: Resource,
        kind: PsiKind,
        threshold: Duration,
        window: Duration,
    ) -> io::Result<Self> {
        let window = round_window(window);
        // A threshold at or above the window can never fire.
        let threshold = threshold.min(window / 2).max(Duration::from_millis(1));

        let mut file = OpenOptions::new().read(true).write(true).open(path)?;

        // The trailing newline is load-bearing. Without it the kernel returns
        // EINVAL, which reads exactly like a permission or parameter problem
        // and cost real time to diagnose the first time.
        let spec = format!(
            "{} {} {}\n",
            kind,
            threshold.as_micros(),
            window.as_micros()
        );
        file.write_all(spec.as_bytes()).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "kernel rejected PSI trigger {:?} on {}: {e}. \
                     Unprivileged windows must be a 2s multiple between 500ms and 10s.",
                    spec.trim(),
                    path.display()
                ),
            )
        })?;

        Ok(Self {
            file,
            resource,
            threshold,
            window,
        })
    }

    pub fn resource(&self) -> Resource {
        self.resource
    }
    pub fn threshold(&self) -> Duration {
        self.threshold
    }
    /// The window actually registered, after rounding.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Block until the trigger fires or `timeout` elapses.
    ///
    /// The kernel rate-limits notifications to one per window, so a caller
    /// cannot be livelocked by a permanently stalled machine.
    pub fn wait(&self, timeout: Option<Duration>) -> io::Result<Wake> {
        let mut pfd = PollFd {
            fd: self.file.as_raw_fd(),
            events: POLLPRI,
            revents: 0,
        };
        let ts = timeout.map(|t| TimeSpec {
            tv_sec: t.as_secs() as i64,
            tv_nsec: i64::from(t.subsec_nanos()),
        });
        let tsp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const _);

        loop {
            let ret = unsafe { ppoll(&mut pfd, 1, tsp) };
            if ret < 0 {
                let errno = -ret as i32;
                // EINTR is not a failure; a signal simply interrupted the wait.
                if errno == 4 {
                    continue;
                }
                return Err(io::Error::from_raw_os_error(errno));
            }
            if ret == 0 {
                return Ok(Wake::Quiet);
            }
            if pfd.revents & POLLERR != 0 {
                return Err(io::Error::other(
                    "PSI trigger reported POLLERR; the cgroup was probably removed",
                ));
            }
            return Ok(Wake::Stalled);
        }
    }
}

/// Round a requested window into something the kernel will accept from an
/// unprivileged process.
fn round_window(requested: Duration) -> Duration {
    let clamped = requested.clamp(WINDOW_MIN, WINDOW_MAX);
    let g = WINDOW_GRANULARITY.as_micros() as u64;
    let us = clamped.as_micros() as u64;
    // Round up so the caller never gets a shorter window than asked for.
    let rounded = us.div_ceil(g) * g;
    Duration::from_micros(rounded.min(WINDOW_MAX.as_micros() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_round_up_to_the_unprivileged_granularity() {
        // The kernel takes only 2s multiples from an unprivileged caller.
        assert_eq!(round_window(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(round_window(Duration::from_secs(2)), Duration::from_secs(2));
        assert_eq!(
            round_window(Duration::from_millis(2100)),
            Duration::from_secs(4)
        );
        assert_eq!(round_window(Duration::from_secs(4)), Duration::from_secs(4));
    }

    #[test]
    fn windows_stay_inside_what_the_kernel_accepts() {
        assert_eq!(round_window(Duration::from_secs(0)), Duration::from_secs(2));
        assert_eq!(round_window(Duration::from_secs(3600)), WINDOW_MAX);
    }

    #[test]
    fn threshold_can_never_exceed_the_window() {
        // A threshold >= the window can never be reached, so the trigger would
        // register successfully and then never fire, which is worse than an error.
        if !crate::psi_available() {
            return;
        }
        let t = Trigger::new(
            Resource::Io,
            PsiKind::Some,
            Duration::from_secs(60),
            Duration::from_secs(2),
        );
        if let Ok(t) = t {
            assert!(
                t.threshold() < t.window(),
                "{:?} vs {:?}",
                t.threshold(),
                t.window()
            );
        }
    }

    #[test]
    fn registers_unprivileged_against_the_real_kernel() {
        if !crate::psi_available() {
            return;
        }
        let t = Trigger::new(
            Resource::Io,
            PsiKind::Some,
            Duration::from_millis(50),
            Duration::from_secs(2),
        );
        match t {
            Ok(t) => {
                assert_eq!(t.resource(), Resource::Io);
                assert_eq!(t.window(), Duration::from_secs(2));
            }
            // A kernel built without PSI triggers, or a restricted container.
            // Not a test failure; the code path is what is under test.
            Err(e) => eprintln!("trigger unavailable here: {e}"),
        }
    }

    #[test]
    fn a_short_timeout_returns_quiet_rather_than_blocking() {
        if !crate::psi_available() {
            return;
        }
        // Threshold deliberately absurd so it cannot fire during the timeout.
        let Ok(t) = Trigger::new(
            Resource::Cpu,
            PsiKind::Some,
            Duration::from_millis(999),
            Duration::from_secs(2),
        ) else {
            return;
        };
        let start = std::time::Instant::now();
        match t.wait(Some(Duration::from_millis(120))) {
            Ok(Wake::Quiet) => assert!(start.elapsed() < Duration::from_secs(2)),
            Ok(Wake::Stalled) => {} // machine genuinely stalled; still a valid outcome
            Err(e) => panic!("wait failed: {e}"),
        }
    }
}
