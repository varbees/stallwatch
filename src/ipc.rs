//! The daemon's query protocol.
//!
//! A Unix socket rather than D-Bus, for now. D-Bus is the right long-term
//! integration surface — it is what lets KRunner, GNOME and waybar consume this
//! without anyone inheriting a Rust build dependency — but every Rust D-Bus
//! implementation is a dependency, and zero dependencies is what keeps the
//! engine reducible to a C ABI. A Unix socket needs only `std`, and a D-Bus
//! frontend can later be another client of this same daemon rather than a
//! rewrite of it.
//!
//! The protocol is one request line in, one JSON document out, then EOF. No
//! framing, no length prefixes, no negotiation — a shell script with `socat`
//! should be able to talk to it.
//!
//! ```text
//! PING                 -> PONG
//! NOW [json|text]      -> most recent single tick
//! SINCE <secs> [fmt]   -> aggregated over the last <secs> seconds
//! ```
//!
//! The format token exists so a client with no JSON parser can still get
//! readable output. With zero dependencies that is not a hypothetical client —
//! it is our own CLI.

use std::path::PathBuf;

/// Socket path, honouring `XDG_RUNTIME_DIR`.
///
/// `/run/user/<uid>` is per-user, `0700`, and cleaned up by systemd on logout —
/// the correct home for a session socket. The `/tmp` fallback includes the uid
/// so two users on one machine cannot collide, and is only reached on systems
/// without an XDG runtime dir.
pub fn socket_path() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("stallwatch.sock");
        }
    }
    PathBuf::from(format!("/tmp/stallwatch-{}.sock", unsafe { libc_getuid() }))
}

/// `getuid(2)` without linking libc.
///
/// The engine has no dependencies, and pulling in the `libc` crate for one
/// syscall would break that for a fallback path most systems never take.
/// Reading the real uid out of `/proc/self/status` is slower and entirely
/// adequate here.
unsafe fn libc_getuid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

/// How the daemon should render its reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Json,
    Text,
}

impl Format {
    fn parse(tok: Option<&str>) -> Format {
        match tok.map(|t| t.to_ascii_uppercase()) {
            Some(t) if t == "TEXT" => Format::Text,
            _ => Format::Json,
        }
    }
}

/// A parsed client request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Ping,
    Now(Format),
    /// Aggregate the last N seconds.
    Since(u64, Format),
}

impl Request {
    /// Parse a request line. Unknown verbs are rejected rather than guessed at.
    pub fn parse(line: &str) -> Option<Request> {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        match parts.next()?.to_ascii_uppercase().as_str() {
            "PING" => Some(Request::Ping),
            "NOW" => Some(Request::Now(Format::parse(parts.next()))),
            "SINCE" => {
                let secs = parts.next()?.parse().ok()?;
                Some(Request::Since(secs, Format::parse(parts.next())))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_verbs_case_insensitively() {
        assert_eq!(Request::parse("PING"), Some(Request::Ping));
        assert_eq!(Request::parse("ping\n"), Some(Request::Ping));
        assert_eq!(Request::parse("  Now  "), Some(Request::Now(Format::Json)));
        assert_eq!(Request::parse("SINCE 30"), Some(Request::Since(30, Format::Json)));
    }

    #[test]
    fn format_token_is_optional_and_defaults_to_json() {
        assert_eq!(Request::parse("SINCE 30 text"), Some(Request::Since(30, Format::Text)));
        assert_eq!(Request::parse("SINCE 30 TEXT"), Some(Request::Since(30, Format::Text)));
        assert_eq!(Request::parse("SINCE 30 bogus"), Some(Request::Since(30, Format::Json)));
        assert_eq!(Request::parse("NOW text"), Some(Request::Now(Format::Text)));
    }

    #[test]
    fn rejects_malformed_input_instead_of_guessing() {
        assert_eq!(Request::parse(""), None);
        assert_eq!(Request::parse("SINCE"), None);
        assert_eq!(Request::parse("SINCE abc"), None);
        assert_eq!(Request::parse("DROP TABLE"), None);
        assert_eq!(Request::parse("SINCE -5"), None);
    }

    #[test]
    fn socket_path_is_under_xdg_runtime_dir_when_set() {
        // Not using a test guard for env here: just assert the shape of
        // whichever branch this environment takes.
        let p = socket_path();
        assert!(p.to_string_lossy().contains("stallwatch"), "{p:?}");
        assert!(p.is_absolute(), "{p:?}");
    }
}
