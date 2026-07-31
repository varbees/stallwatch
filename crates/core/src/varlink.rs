//! Varlink service interface.
//!
//! # Why Varlink and not D-Bus
//!
//! D-Bus was the obvious integration surface and it turned out to be the wrong
//! one. Speaking it means either taking a dependency (zbus and its crate graph)
//! or hand-rolling SASL authentication and type marshalling — the first breaks
//! the zero-dependency property that keeps this engine reducible to a C ABI,
//! the second is a large amount of security-sensitive code to own.
//!
//! Varlink is JSON objects separated by NUL bytes over a Unix socket. No auth
//! handshake, no type marshalling, no dependency. systemd 258 already ships a
//! large number of `io.systemd.*` Varlink services and `varlinkctl` is present
//! on stock Fedora, so this makes stallwatch queryable by a standard tool
//! rather than a bespoke client:
//!
//! ```text
//! varlinkctl call $XDG_RUNTIME_DIR/stallwatch.varlink \
//!     dev.stallwatch.Monitor.GetStalls '{"seconds":30}'
//! ```
//!
//! # Protocol
//!
//! Request:  `{"method":"iface.Method","parameters":{…}}\0`
//! Reply:    `{"parameters":{…}}\0`
//! Error:    `{"error":"iface.ErrorName","parameters":{…}}\0`
//!
//! `org.varlink.service.GetInfo` and `.GetInterfaceDescription` are mandatory
//! for any conforming service — that is what makes introspection work.

use crate::Report;
use crate::json::{self, Json};

pub const INTERFACE: &str = "dev.stallwatch.Monitor";

/// The interface definition, served verbatim by GetInterfaceDescription.
///
/// Field names match the JSON schema in [`crate::Report`], which in turn tracks
/// the `container_pressure_*` vocabulary cAdvisor and Kubernetes settled on.
pub const INTERFACE_DESCRIPTION: &str = r#"interface dev.stallwatch.Monitor

# One unit's stall over one observation window.
type Stall (
  unit: string,
  cgroup: string,
  resource: string,
  type: string,
  delta_usec: int,
  pressure_pct: float,
  # Worst single sampling tick in the window. On aggregated history this is
  # the signal that survives averaging; a 2s freeze inside 60s averages away.
  peak_pct: float
)

# A system condition explaining stalls the pressure numbers alone cannot.
type Warning (
  source: string,
  severity: string,
  # True when the condition clears without intervention.
  transient: bool,
  message: string
)

# Sample the system live over a window. Blocks for the duration.
method GetStalls(window_ms: ?int) -> (
  window_usec: int,
  stalls: []Stall,
  warnings: []Warning
)

# What happened over the last N seconds, from recorded history.
method GetHistory(seconds: int) -> (
  window_usec: int,
  stalls: []Stall,
  warnings: []Warning
)

# No history covering the requested window.
error NoHistory(seconds: int)

# The kernel exposes no PSI (needs CONFIG_PSI=y, possibly psi=1).
error NoPressureStallInformation()
"#;

/// A parsed Varlink request.
#[derive(Debug, PartialEq)]
pub enum Call {
    GetInfo,
    GetInterfaceDescription(String),
    GetStalls { window_ms: u64 },
    GetHistory { seconds: u64 },
}

#[derive(Debug, PartialEq)]
pub enum CallError {
    Malformed(&'static str),
    UnknownMethod(String),
    UnknownInterface(String),
}

/// Parse one Varlink request frame (NUL already stripped).
pub fn parse_call(frame: &str) -> Result<Call, CallError> {
    let v = json::parse(frame).map_err(CallError::Malformed)?;
    let method = v
        .get("method")
        .and_then(Json::as_str)
        .ok_or(CallError::Malformed("missing \"method\""))?;
    let params = v.get("parameters");

    match method {
        "org.varlink.service.GetInfo" => Ok(Call::GetInfo),
        "org.varlink.service.GetInterfaceDescription" => {
            let iface = params
                .and_then(|p| p.get("interface"))
                .and_then(Json::as_str)
                .ok_or(CallError::Malformed("missing \"interface\""))?;
            Ok(Call::GetInterfaceDescription(iface.to_string()))
        }
        "dev.stallwatch.Monitor.GetStalls" => Ok(Call::GetStalls {
            window_ms: params
                .and_then(|p| p.get("window_ms"))
                .and_then(Json::as_u64)
                .unwrap_or(1000)
                .clamp(100, 60_000),
        }),
        "dev.stallwatch.Monitor.GetHistory" => Ok(Call::GetHistory {
            seconds: params
                .and_then(|p| p.get("seconds"))
                .and_then(Json::as_u64)
                .ok_or(CallError::Malformed("missing \"seconds\""))?
                .clamp(1, 86_400),
        }),
        other => {
            // Varlink distinguishes an unknown interface from an unknown method
            // on a known interface, and clients rely on the difference.
            match other.rsplit_once('.') {
                Some((iface, _)) if iface == INTERFACE || iface == "org.varlink.service" => {
                    Err(CallError::UnknownMethod(other.to_string()))
                }
                Some((iface, _)) => Err(CallError::UnknownInterface(iface.to_string())),
                None => Err(CallError::UnknownInterface(other.to_string())),
            }
        }
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

pub fn reply_info() -> String {
    format!(
        r#"{{"parameters":{{"vendor":"stallwatch","product":"stallwatch","version":{},"url":"https://github.com/varbees/stallwatch","interfaces":["org.varlink.service","{}"]}}}}"#,
        esc(env!("CARGO_PKG_VERSION")),
        INTERFACE
    )
}

pub fn reply_interface_description() -> String {
    format!(
        r#"{{"parameters":{{"description":{}}}}}"#,
        esc(INTERFACE_DESCRIPTION)
    )
}

/// A Report as Varlink reply parameters. Reuses the same field names as the
/// JSON schema so both surfaces stay identical by construction.
pub fn reply_report(r: &Report) -> String {
    format!(r#"{{"parameters":{}}}"#, r.to_json_compact())
}

pub fn reply_error(name: &str, params: &str) -> String {
    format!(r#"{{"error":{},"parameters":{}}}"#, esc(name), params)
}

pub fn error_for(e: &CallError) -> String {
    match e {
        CallError::Malformed(why) => reply_error(
            "org.varlink.service.InvalidParameter",
            &format!(r#"{{"parameter":{}}}"#, esc(why)),
        ),
        CallError::UnknownMethod(m) => reply_error(
            "org.varlink.service.MethodNotFound",
            &format!(r#"{{"method":{}}}"#, esc(m)),
        ),
        CallError::UnknownInterface(i) => reply_error(
            "org.varlink.service.InterfaceNotFound",
            &format!(r#"{{"interface":{}}}"#, esc(i)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mandatory_service_methods() {
        assert_eq!(
            parse_call(r#"{"method":"org.varlink.service.GetInfo"}"#).unwrap(),
            Call::GetInfo
        );
        assert_eq!(
            parse_call(
                r#"{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"dev.stallwatch.Monitor"}}"#
            )
            .unwrap(),
            Call::GetInterfaceDescription("dev.stallwatch.Monitor".into())
        );
    }

    #[test]
    fn get_stalls_defaults_and_clamps() {
        assert_eq!(
            parse_call(r#"{"method":"dev.stallwatch.Monitor.GetStalls"}"#).unwrap(),
            Call::GetStalls { window_ms: 1000 }
        );
        // A hostile client must not be able to make us block for an hour.
        assert_eq!(
            parse_call(r#"{"method":"dev.stallwatch.Monitor.GetStalls","parameters":{"window_ms":99999999}}"#)
                .unwrap(),
            Call::GetStalls { window_ms: 60_000 }
        );
        assert_eq!(
            parse_call(
                r#"{"method":"dev.stallwatch.Monitor.GetStalls","parameters":{"window_ms":1}}"#
            )
            .unwrap(),
            Call::GetStalls { window_ms: 100 }
        );
    }

    #[test]
    fn get_history_requires_seconds() {
        assert!(matches!(
            parse_call(r#"{"method":"dev.stallwatch.Monitor.GetHistory"}"#),
            Err(CallError::Malformed(_))
        ));
        assert_eq!(
            parse_call(
                r#"{"method":"dev.stallwatch.Monitor.GetHistory","parameters":{"seconds":30}}"#
            )
            .unwrap(),
            Call::GetHistory { seconds: 30 }
        );
    }

    #[test]
    fn distinguishes_unknown_method_from_unknown_interface() {
        assert!(matches!(
            parse_call(r#"{"method":"dev.stallwatch.Monitor.Nope"}"#),
            Err(CallError::UnknownMethod(_))
        ));
        assert!(matches!(
            parse_call(r#"{"method":"com.example.Thing.Do"}"#),
            Err(CallError::UnknownInterface(_))
        ));
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        for bad in ["", "{", "null", r#"{"nomethod":1}"#, r#"{"method":42}"#] {
            assert!(parse_call(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn errors_are_wellformed_varlink() {
        let e = error_for(&CallError::UnknownMethod("x.Y".into()));
        assert!(
            e.contains(r#""error":"org.varlink.service.MethodNotFound""#),
            "{e}"
        );
        assert!(
            json::parse(&e).is_ok(),
            "error reply must be valid JSON: {e}"
        );
    }

    #[test]
    fn info_and_description_replies_are_valid_json() {
        assert!(json::parse(&reply_info()).is_ok());
        let d = reply_interface_description();
        assert!(json::parse(&d).is_ok(), "description must survive escaping");
        // The description is a Varlink IDL document; make sure escaping did
        // not eat the newlines that make it parseable.
        let parsed = json::parse(&d).unwrap();
        let text = parsed
            .get("parameters")
            .and_then(|p| p.get("description"))
            .and_then(Json::as_str)
            .unwrap();
        assert!(
            text.starts_with("interface dev.stallwatch.Monitor"),
            "{text}"
        );
        assert!(text.contains("method GetStalls"));
    }
}
