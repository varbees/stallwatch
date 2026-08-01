//! Configuration, layered the way Linux expects, and rules built on the same
//! filter grammar as everything else.
//!
//! # Layering
//!
//! ```text
//! /etc/xdg/stallwatch/config.toml     packaged defaults
//! ~/.config/stallwatch/config.toml    the user
//! STALLWATCH_* environment            the session
//! command-line flags                  this invocation
//! ```
//!
//! Later wins. Every resolved value remembers **where it came from**, because
//! the worst part of every configurable Linux tool is not knowing which file
//! won. [`Config::explain`] prints that, and exists for exactly that reason.
//!
//! # Rules
//!
//! ```toml
//! [[rule]]
//! name = "the browser is eating my disk"
//! when = 'resource == io and unit ~ "firefox|chrome" and peak > 70'
//! run  = "notify-send 'Disk stall' '{unit} froze you {delta_ms}ms'"
//! ```
//!
//! `when` is [`crate::filter`], the same grammar the CLI takes. One language,
//! learned once.
//!
//! ## Where a rule command can actually write
//!
//! Rules run inside the daemon's sandbox, and the packaged unit is hardened.
//! `PrivateTmp=true` gives it a private `/tmp`, so a rule redirecting to
//! `/tmp/…` writes somewhere nobody else can see and looks like it silently
//! did nothing. `ProtectHome=read-only` blocks the home directory too.
//!
//! Use `logger` to reach the journal, or `log = "…"` inside `$STATE_DIRECTORY`,
//! or loosen the unit deliberately. This cost real time to diagnose once, which
//! is why it is written down here.
//!
//! # Why a hand-written TOML subset
//!
//! The engine takes no crates. This parses tables, arrays of tables, strings,
//! integers, booleans and string arrays, which is the whole schema, and
//! nothing else. Anything it does not understand is reported with a line
//! number rather than ignored, because silently dropping a rule someone wrote
//! is worse than refusing to start.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::filter::Filter;

/// Where a setting came from. Printed by `config --explain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Default,
    File(PathBuf),
    Env(String),
    Flag(String),
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Default => f.write_str("built-in default"),
            Origin::File(p) => write!(f, "{}", p.display()),
            Origin::Env(k) => write!(f, "${k}"),
            Origin::Flag(k) => write!(f, "command line {k}"),
        }
    }
}

/// A value plus where it came from.
#[derive(Clone, Debug)]
pub struct Sourced<T> {
    pub value: T,
    pub origin: Origin,
}

impl<T> Sourced<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            origin: Origin::Default,
        }
    }
    fn set(&mut self, value: T, origin: Origin) {
        self.value = value;
        self.origin = origin;
    }
}

/// What to do when a rule matches.
#[derive(Clone, Debug, Default)]
pub struct Action {
    /// Shell command. `{unit}`, `{delta_ms}`, `{pct}`, `{peak}`, `{resource}`
    /// and `{cgroup}` are substituted from the matching stall.
    pub run: Option<String>,
    /// Append the incident to this path.
    pub log: Option<PathBuf>,
    /// Send a desktop notification.
    pub notify: bool,
}

/// One rule.
pub struct Rule {
    pub name: String,
    pub when: Filter,
    pub action: Action,
}

impl fmt::Debug for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rule")
            .field("name", &self.name)
            .field("when", &self.when.to_string())
            .field("action", &self.action)
            .finish()
    }
}

/// Resolved configuration.
#[derive(Debug)]
pub struct Config {
    /// Stall inside a 2s window that wakes a capture, in milliseconds.
    pub threshold_ms: Sourced<u64>,
    /// How long to sample once woken, in milliseconds.
    pub capture_ms: Sourced<u64>,
    /// How much history the ring retains, in seconds.
    pub history_secs: Sourced<u64>,
    /// Which resources get a trigger.
    pub resources: Sourced<Vec<String>>,
    /// Announce bad stalls on the desktop as they happen.
    pub notify_enabled: Sourced<bool>,
    /// Worst-tick percentage below which nothing is announced.
    pub notify_min_peak: Sourced<u64>,
    /// Seconds between notices, however bad it gets.
    pub notify_cooldown_secs: Sourced<u64>,
    pub rules: Vec<Rule>,
    /// Files that were actually read, in the order applied.
    pub loaded: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threshold_ms: Sourced::new(50),
            capture_ms: Sourced::new(400),
            history_secs: Sourced::new(300),
            resources: Sourced::new(vec!["cpu".into(), "memory".into(), "io".into()]),
            notify_enabled: Sourced::new(true),
            notify_min_peak: Sourced::new(crate::notify::DEFAULT_MIN_PEAK as u64),
            notify_cooldown_secs: Sourced::new(crate::notify::DEFAULT_COOLDOWN.as_secs()),
            rules: Vec::new(),
            loaded: Vec::new(),
        }
    }
}

/// Search path, lowest precedence first.
pub fn search_path() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/etc/xdg/stallwatch/config.toml")];
    let user = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        });
    if let Some(dir) = user {
        v.push(dir.join("stallwatch").join("config.toml"));
    }
    v
}

impl Config {
    /// Load the layers in order. A missing file is not an error; a malformed
    /// one is, because starting with a rule silently dropped is worse than not
    /// starting.
    pub fn load() -> Result<Self, ConfigError> {
        let mut cfg = Self::default();
        for path in search_path() {
            let Ok(body) = std::fs::read_to_string(&path) else {
                continue;
            };
            cfg.apply_toml(&body, &path)?;
            cfg.loaded.push(path);
        }
        cfg.apply_env();
        Ok(cfg)
    }

    /// Parse one file over the current values.
    pub fn apply_toml(&mut self, body: &str, from: &Path) -> Result<(), ConfigError> {
        let doc = parse_toml(body).map_err(|e| ConfigError {
            path: from.to_path_buf(),
            line: e.line,
            msg: e.msg,
        })?;

        let origin = Origin::File(from.to_path_buf());
        if let Some(t) = doc.tables.get("capture") {
            if let Some(v) = t.int("threshold_ms") {
                self.threshold_ms.set(v.max(1) as u64, origin.clone());
            }
            if let Some(v) = t.int("capture_ms") {
                self.capture_ms.set(v.max(50) as u64, origin.clone());
            }
            if let Some(v) = t.int("history_secs") {
                self.history_secs.set(v.max(10) as u64, origin.clone());
            }
            if let Some(v) = t.strings("resources") {
                self.resources.set(v, origin.clone());
            }
        }

        if let Some(t) = doc.tables.get("notify") {
            if let Some(v) = t.bool("enabled") {
                self.notify_enabled.set(v, origin.clone());
            }
            if let Some(v) = t.int("min_peak") {
                self.notify_min_peak
                    .set(v.clamp(0, 100) as u64, origin.clone());
            }
            if let Some(v) = t.int("cooldown_secs") {
                self.notify_cooldown_secs
                    .set(v.max(0) as u64, origin.clone());
            }
        }

        for (i, t) in doc.rules.iter().enumerate() {
            let name = t
                .string("name")
                .unwrap_or_else(|| format!("rule {}", i + 1));
            let Some(expr) = t.string("when") else {
                return Err(ConfigError {
                    path: from.to_path_buf(),
                    line: t.line,
                    msg: format!("rule `{name}` has no `when =` expression"),
                });
            };
            let when = Filter::parse(&expr).map_err(|e| ConfigError {
                path: from.to_path_buf(),
                line: t.line,
                msg: format!("rule `{name}`: {e}"),
            })?;
            self.rules.push(Rule {
                name,
                when,
                action: Action {
                    run: t.string("run"),
                    log: t.string("log").map(PathBuf::from),
                    notify: t.bool("notify").unwrap_or(false),
                },
            });
        }
        Ok(())
    }

    /// `STALLWATCH_THRESHOLD_MS` and friends, applied over any file.
    fn apply_env(&mut self) {
        let num = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
        if let Some(v) = num("STALLWATCH_THRESHOLD_MS") {
            self.threshold_ms
                .set(v.max(1), Origin::Env("STALLWATCH_THRESHOLD_MS".into()));
        }
        if let Some(v) = num("STALLWATCH_CAPTURE_MS") {
            self.capture_ms
                .set(v.max(50), Origin::Env("STALLWATCH_CAPTURE_MS".into()));
        }
        if let Some(v) = num("STALLWATCH_HISTORY_SECS") {
            self.history_secs
                .set(v.max(10), Origin::Env("STALLWATCH_HISTORY_SECS".into()));
        }
    }

    /// Record that a flag overrode a value, so `--explain` stays truthful.
    pub fn note_flag(&mut self, key: &str, flag: &str) {
        let o = Origin::Flag(flag.to_string());
        match key {
            "threshold_ms" => self.threshold_ms.origin = o,
            "capture_ms" => self.capture_ms.origin = o,
            "history_secs" => self.history_secs.origin = o,
            _ => {}
        }
    }

    /// Every setting, its value, and which layer won.
    pub fn explain(&self) -> String {
        use std::fmt::Write as _;
        let mut o = String::new();

        o.push_str("Searched, lowest precedence first:\n");
        for p in search_path() {
            let mark = if self.loaded.contains(&p) {
                "read"
            } else {
                "absent"
            };
            let _ = writeln!(o, "  {:<8} {}", mark, p.display());
        }
        o.push_str("\nEnvironment then command-line flags override those.\n\n");

        let _ = writeln!(o, "{:<16} {:<28} FROM", "SETTING", "VALUE");
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "threshold_ms", self.threshold_ms.value, self.threshold_ms.origin
        );
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "capture_ms", self.capture_ms.value, self.capture_ms.origin
        );
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "history_secs", self.history_secs.value, self.history_secs.origin
        );
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "resources",
            self.resources.value.join(","),
            self.resources.origin
        );
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "notify.enabled", self.notify_enabled.value, self.notify_enabled.origin
        );
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "notify.min_peak", self.notify_min_peak.value, self.notify_min_peak.origin
        );
        let _ = writeln!(
            o,
            "{:<16} {:<28} {}",
            "notify.cooldown", self.notify_cooldown_secs.value, self.notify_cooldown_secs.origin
        );

        if self.rules.is_empty() {
            o.push_str("\nNo rules defined.\n");
        } else {
            let _ = writeln!(o, "\n{} rule(s):", self.rules.len());
            for r in &self.rules {
                let _ = writeln!(o, "  {:<28} when {}", r.name, r.when);
            }
        }
        o
    }
}

#[derive(Debug)]
pub struct ConfigError {
    pub path: PathBuf,
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.path.display(), self.line, self.msg)
    }
}

impl std::error::Error for ConfigError {}

/// Substitute `{unit}` and friends in a rule command.
///
/// Deliberately not a shell: values are placed literally and the caller is
/// responsible for how it runs them. A rule is something the user wrote for
/// themselves, but a unit name still comes from the kernel.
pub fn expand(template: &str, stall: &crate::Stall) -> String {
    template
        .replace("{unit}", &stall.unit)
        .replace("{cgroup}", &stall.cgroup)
        .replace("{resource}", &stall.resource.to_string())
        .replace("{delta_ms}", &format!("{}", stall.delta_usec / 1000))
        .replace("{pct}", &format!("{:.0}", stall.pressure_pct))
        .replace("{peak}", &format!("{:.0}", stall.peak_pct))
}

// ── a very small TOML subset ───────────────────────────────────────────

#[derive(Debug, Default)]
struct Table {
    line: usize,
    keys: BTreeMap<String, Val>,
}

#[derive(Debug, Clone)]
enum Val {
    Str(String),
    Int(i64),
    Bool(bool),
    Arr(Vec<String>),
}

impl Table {
    fn string(&self, k: &str) -> Option<String> {
        match self.keys.get(k) {
            Some(Val::Str(s)) => Some(s.clone()),
            _ => None,
        }
    }
    fn int(&self, k: &str) -> Option<i64> {
        match self.keys.get(k) {
            Some(Val::Int(i)) => Some(*i),
            _ => None,
        }
    }
    fn bool(&self, k: &str) -> Option<bool> {
        match self.keys.get(k) {
            Some(Val::Bool(b)) => Some(*b),
            _ => None,
        }
    }
    fn strings(&self, k: &str) -> Option<Vec<String>> {
        match self.keys.get(k) {
            Some(Val::Arr(v)) => Some(v.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct Doc {
    tables: BTreeMap<String, Table>,
    rules: Vec<Table>,
}

struct TomlError {
    line: usize,
    msg: String,
}

fn parse_toml(body: &str) -> Result<Doc, TomlError> {
    let mut doc = Doc::default();
    let mut current: Option<String> = None;
    let mut in_rule = false;

    for (n, raw) in body.lines().enumerate() {
        let line = n + 1;
        let s = strip_comment(raw).trim();
        if s.is_empty() {
            continue;
        }

        if let Some(rest) = s.strip_prefix("[[") {
            let name = rest.trim_end_matches("]]").trim();
            if name != "rule" {
                return Err(TomlError {
                    line,
                    msg: format!("unknown array of tables `[[{name}]]`; only `[[rule]]` exists"),
                });
            }
            doc.rules.push(Table {
                line,
                ..Default::default()
            });
            in_rule = true;
            current = None;
            continue;
        }

        if let Some(rest) = s.strip_prefix('[') {
            let name = rest.trim_end_matches(']').trim().to_string();
            if name != "capture" && name != "notify" {
                return Err(TomlError {
                    line,
                    msg: format!("unknown table `[{name}]`; expected `[capture]` or `[notify]`"),
                });
            }
            doc.tables.entry(name.clone()).or_insert_with(|| Table {
                line,
                ..Default::default()
            });
            current = Some(name);
            in_rule = false;
            continue;
        }

        let Some((k, v)) = s.split_once('=') else {
            return Err(TomlError {
                line,
                msg: format!("expected `key = value`, found `{s}`"),
            });
        };
        let key = k.trim().to_string();
        let val = parse_value(v.trim(), line)?;

        if in_rule {
            if let Some(t) = doc.rules.last_mut() {
                t.keys.insert(key, val);
            }
        } else if let Some(name) = &current {
            if let Some(t) = doc.tables.get_mut(name) {
                t.keys.insert(key, val);
            }
        } else {
            return Err(TomlError {
                line,
                msg: format!("`{key}` is outside any table; it needs `[capture]` above it"),
            });
        }
    }
    Ok(doc)
}

/// Strip a `#` comment, respecting quotes so a `#` inside a filter survives.
fn strip_comment(line: &str) -> &str {
    let b = line.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &c) in b.iter().enumerate() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == b'"' || c == b'\'' => quote = Some(c),
            None if c == b'#' => return &line[..i],
            None => {}
        }
    }
    line
}

fn parse_value(s: &str, line: usize) -> Result<Val, TomlError> {
    if s == "true" {
        return Ok(Val::Bool(true));
    }
    if s == "false" {
        return Ok(Val::Bool(false));
    }
    if let Some(rest) = s.strip_prefix('[') {
        let inner = rest.trim_end_matches(']');
        let items: Vec<String> = inner
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| p.trim_matches(['"', '\'']).to_string())
            .collect();
        return Ok(Val::Arr(items));
    }
    // Basic strings honour backslash escapes; literal (single-quoted) strings
    // do not, which is what TOML specifies and also what makes single quotes
    // the sane choice for a filter expression full of double quotes.
    if let Some(rest) = s.strip_prefix('\'') {
        let Some(end) = rest.find('\'') else {
            return Err(TomlError {
                line,
                msg: "unterminated string".into(),
            });
        };
        return Ok(Val::Str(rest[..end].to_string()));
    }
    if let Some(rest) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        loop {
            match chars.next() {
                Some('"') => return Ok(Val::Str(out)),
                // Without this, `run = "echo \"hi\""` silently truncates at the
                // first escaped quote and the rule runs a broken command.
                Some('\\') => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(c) => {
                        out.push('\\');
                        out.push(c);
                    }
                    None => break,
                },
                Some(c) => out.push(c),
                None => break,
            }
        }
        return Err(TomlError {
            line,
            msg: "unterminated string".into(),
        });
    }
    s.parse::<i64>().map(Val::Int).map_err(|_| TomlError {
        line,
        msg: format!("`{s}` is not a string, number or boolean"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PsiKind, Resource, Stall};

    fn cfg_from(body: &str) -> Result<Config, ConfigError> {
        let mut c = Config::default();
        c.apply_toml(body, Path::new("/test/config.toml"))?;
        Ok(c)
    }

    #[test]
    fn capture_settings_load_and_remember_their_source() {
        let c = cfg_from("[capture]\nthreshold_ms = 25\ncapture_ms = 900\n").unwrap();
        assert_eq!(c.threshold_ms.value, 25);
        assert_eq!(c.capture_ms.value, 900);
        assert_eq!(
            c.threshold_ms.origin,
            Origin::File(PathBuf::from("/test/config.toml"))
        );
        // Untouched settings must still say they are defaults.
        assert_eq!(c.history_secs.origin, Origin::Default);
    }

    #[test]
    fn rules_parse_their_filter_with_the_same_grammar_as_the_cli() {
        let c = cfg_from(
            r#"
[[rule]]
name = "browser eating the disk"
when = 'resource == io and peak > 70'
notify = true
run = "notify-send stall {unit}"
"#,
        )
        .unwrap();
        assert_eq!(c.rules.len(), 1);
        assert_eq!(c.rules[0].name, "browser eating the disk");
        assert!(c.rules[0].action.notify);
        assert_eq!(
            c.rules[0].action.run.as_deref(),
            Some("notify-send stall {unit}")
        );
    }

    #[test]
    fn a_rule_matches_using_that_filter() {
        let c =
            cfg_from("[[rule]]\nname = \"io\"\nwhen = 'resource == io and peak > 70'\n").unwrap();
        let s = Stall {
            unit: "firefox".into(),
            cgroup: "/x".into(),
            resource: Resource::Io,
            kind: PsiKind::Full,
            delta_usec: 500_000,
            pressure_pct: 80.0,
            peak_pct: 90.0,
        };
        assert!(c.rules[0].when.matches(&s));
    }

    #[test]
    fn a_broken_filter_refuses_to_load_rather_than_dropping_the_rule() {
        // Silently ignoring a rule someone wrote is worse than not starting.
        let e = cfg_from("[[rule]]\nname = \"bad\"\nwhen = 'peak >'\n").unwrap_err();
        assert!(e.msg.contains("bad"), "{}", e.msg);
        // Points at the `[[rule]]` header, which identifies which rule block
        // failed. More useful than an arbitrary key line inside it.
        assert_eq!(e.line, 1, "should point at the rule header, got {}", e.line);
    }

    #[test]
    fn a_rule_without_when_is_an_error_with_a_line_number() {
        let e = cfg_from("[[rule]]\nname = \"no condition\"\n").unwrap_err();
        assert!(e.msg.contains("no `when"), "{}", e.msg);
    }

    #[test]
    fn unknown_tables_are_rejected_rather_than_silently_ignored() {
        let e = cfg_from("[capture]\nthreshold_ms = 10\n\n[typo]\nx = 1\n").unwrap_err();
        assert!(e.msg.contains("unknown table"), "{}", e.msg);
        assert_eq!(e.line, 4);
    }

    #[test]
    fn comments_do_not_eat_a_hash_inside_a_quoted_filter() {
        let c =
            cfg_from("[[rule]]\nname = \"hash\"\nwhen = 'unit ~ \"a#b\"'  # trailing comment\n")
                .unwrap();
        assert!(
            c.rules[0].when.to_string().contains("a#b"),
            "{}",
            c.rules[0].when
        );
    }

    #[test]
    fn escaped_quotes_survive_inside_a_basic_string() {
        // Without escape handling this truncated at the first \" and the rule
        // ran `echo \` — loaded successfully, then silently did nothing.
        let c = cfg_from(
            "[[rule]]\nname = \"esc\"\nwhen = 'peak > 1'\nrun = \"echo \\\"hi there\\\" >> /tmp/x\"\n",
        )
        .unwrap();
        assert_eq!(
            c.rules[0].action.run.as_deref(),
            Some(r#"echo "hi there" >> /tmp/x"#)
        );
    }

    #[test]
    fn arrays_and_booleans_parse() {
        let c = cfg_from("[capture]\nresources = [\"io\", \"memory\"]\n").unwrap();
        assert_eq!(c.resources.value, vec!["io", "memory"]);
    }

    #[test]
    fn a_key_outside_any_table_is_an_error_not_a_shrug() {
        let e = cfg_from("threshold_ms = 5\n").unwrap_err();
        assert!(e.msg.contains("outside any table"), "{}", e.msg);
    }

    #[test]
    fn expand_substitutes_from_the_matching_stall() {
        let s = Stall {
            unit: "firefox".into(),
            cgroup: "/sys/fs/cgroup/app".into(),
            resource: Resource::Io,
            kind: PsiKind::Full,
            delta_usec: 1_500_000,
            pressure_pct: 84.6,
            peak_pct: 93.0,
        };
        let out = expand("froze {unit} for {delta_ms}ms at {peak}% on {resource}", &s);
        assert_eq!(out, "froze firefox for 1500ms at 93% on io");
    }

    #[test]
    fn explain_names_the_layer_that_won() {
        let c = cfg_from("[capture]\nthreshold_ms = 25\n").unwrap();
        let text = c.explain();
        assert!(text.contains("threshold_ms"), "{text}");
        assert!(text.contains("/test/config.toml"), "{text}");
        assert!(text.contains("built-in default"), "{text}");
    }

    #[test]
    fn garbage_never_panics() {
        for bad in ["[", "[[", "= 5", "[capture]\nx", "[capture]\nx = ", "\u{0}"] {
            let _ = cfg_from(bad);
        }
    }
}
