//! A filter language for stalls.
//!
//! # Why this exists
//!
//! Wireshark's power is not its window, it is that every value is a named
//! typed field and there is a language over those fields. The window is a view
//! on a query engine. htop has no query language at all; `below` has fixed
//! views. A stall already has typed fields here — they were simply not
//! addressable.
//!
//! ```text
//! resource == io and peak > 70
//! unit ~ "firefox|chrome" and delta_ms > 500
//! not warning.transient and warning.source == btrfs
//! ```
//!
//! One grammar, used by the CLI, the rules engine, the exporters and
//! eventually the TUI. Learn it once.
//!
//! # Zero dependencies
//!
//! Hand-rolled, like the JSON parser next door, because the engine takes no
//! crates. A recursive-descent parser over a small grammar is a few hundred
//! lines and removes any argument about pulling in a parser generator.

use std::fmt;

use crate::{Stall, Warning};

/// Anything a filter can be evaluated against.
///
/// Implemented rather than hard-coded to `Stall` so the same expression can
/// later match a process row or a rule context without a second grammar.
pub trait Queryable {
    /// A named field as text, if this subject has it.
    fn field_str(&self, name: &str) -> Option<String>;
    /// A named field as a number, if this subject has it.
    fn field_num(&self, name: &str) -> Option<f64>;
    /// A named field as a boolean, if this subject has it.
    fn field_bool(&self, name: &str) -> Option<bool> {
        let _ = name;
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    /// Substring match, with `|` meaning alternation: `unit ~ "a|b"`.
    Match,
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::Gt => ">",
            Op::Lt => "<",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Match => "~",
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Num(f64),
    Str(String),
}

#[derive(Clone, Debug)]
enum Node {
    Compare {
        field: String,
        op: Op,
        value: Value,
    },
    /// A bare field name, true when the field exists and is truthy.
    Truthy(String),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Not(Box<Node>),
}

/// A compiled filter expression.
#[derive(Clone, Debug)]
pub struct Filter {
    root: Node,
    source: String,
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl Filter {
    /// Compile an expression.
    ///
    /// Errors carry the byte offset, because a filter typed at a prompt is
    /// wrong far more often than it is right, and "unexpected token" with no
    /// position is a hostile thing to print at somebody.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let tokens = lex(input)?;
        let mut p = Parser { tokens, pos: 0 };
        let root = p.parse_or()?;
        if let Some(t) = p.peek() {
            return Err(ParseError {
                at: t.at,
                msg: format!("unexpected `{}` after a complete expression", t.text),
            });
        }
        Ok(Self {
            root,
            source: input.trim().to_string(),
        })
    }

    /// Does this subject match?
    pub fn matches<Q: Queryable>(&self, subject: &Q) -> bool {
        eval(&self.root, subject)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the input where the problem is.
    pub at: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at character {})", self.msg, self.at + 1)
    }
}

impl std::error::Error for ParseError {}

// ── lexer ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
struct Token {
    text: String,
    kind: Kind,
    at: usize,
}

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Word,
    Str,
    Num(f64),
    Op(Op),
    LParen,
    RParen,
}

/// Suffixes accepted on numbers, so a filter can say what it means.
///
/// `write_bytes > 100M` beats `write_bytes > 104857600` for the same reason
/// `--window 3s` beats `--window 3000`.
fn suffix_scale(s: &str) -> Option<(f64, usize)> {
    let table: [(&str, f64); 10] = [
        ("ms", 1.0),
        ("s", 1000.0),
        ("m", 60_000.0),
        ("KiB", 1024.0),
        ("MiB", 1024.0 * 1024.0),
        ("GiB", 1024.0 * 1024.0 * 1024.0),
        ("K", 1000.0),
        ("M", 1_000_000.0),
        ("G", 1_000_000_000.0),
        ("%", 1.0),
    ];
    // Longest match first so "ms" is not read as "m".
    let mut best: Option<(f64, usize)> = None;
    for (suf, scale) in table {
        if s.starts_with(suf) && best.is_none_or(|(_, l)| suf.len() > l) {
            best = Some((scale, suf.len()));
        }
    }
    best
}

fn lex(input: &str) -> Result<Vec<Token>, ParseError> {
    let b = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < b.len() {
        let c = b[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let at = i;

        // strings
        if c == '"' || c == '\'' {
            let quote = c;
            i += 1;
            let start = i;
            while i < b.len() && b[i] as char != quote {
                i += 1;
            }
            if i >= b.len() {
                return Err(ParseError {
                    at,
                    msg: "unterminated string".into(),
                });
            }
            out.push(Token {
                text: input[start..i].to_string(),
                kind: Kind::Str,
                at,
            });
            i += 1;
            continue;
        }

        // operators
        let two = input.get(i..i + 2).unwrap_or("");
        let op = match two {
            "==" => Some(Op::Eq),
            "!=" => Some(Op::Ne),
            ">=" => Some(Op::Ge),
            "<=" => Some(Op::Le),
            _ => None,
        };
        if let Some(op) = op {
            out.push(Token {
                text: two.into(),
                kind: Kind::Op(op),
                at,
            });
            i += 2;
            continue;
        }
        let op = match c {
            '>' => Some(Op::Gt),
            '<' => Some(Op::Lt),
            '~' => Some(Op::Match),
            // A single `=` is the most common typo for `==`. Accept it rather
            // than making someone re-read the manual over one character.
            '=' => Some(Op::Eq),
            _ => None,
        };
        if let Some(op) = op {
            out.push(Token {
                text: c.to_string(),
                kind: Kind::Op(op),
                at,
            });
            i += 1;
            continue;
        }
        if c == '(' {
            out.push(Token {
                text: "(".into(),
                kind: Kind::LParen,
                at,
            });
            i += 1;
            continue;
        }
        if c == ')' {
            out.push(Token {
                text: ")".into(),
                kind: Kind::RParen,
                at,
            });
            i += 1;
            continue;
        }

        // numbers, with an optional unit suffix
        if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && ((b[i] as char).is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let n: f64 = input[start..i].parse().map_err(|_| ParseError {
                at: start,
                msg: format!("`{}` is not a number", &input[start..i]),
            })?;
            let mut scaled = n;
            if let Some((scale, len)) = suffix_scale(&input[i..]) {
                scaled = n * scale;
                i += len;
            }
            out.push(Token {
                text: input[start..i].to_string(),
                kind: Kind::Num(scaled),
                at: start,
            });
            continue;
        }

        // bare words: field names, and/or/not, and unquoted values
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < b.len() {
                let ch = b[i] as char;
                if ch.is_alphanumeric() || ch == '_' || ch == '.' || ch == '-' {
                    i += 1;
                } else {
                    break;
                }
            }
            out.push(Token {
                text: input[start..i].to_string(),
                kind: Kind::Word,
                at: start,
            });
            continue;
        }

        return Err(ParseError {
            at,
            msg: format!("`{c}` cannot start a term"),
        });
    }
    Ok(out)
}

// ── parser ─────────────────────────────────────────────────────────────

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn eat_word(&mut self, w: &str) -> bool {
        match self.peek() {
            Some(t) if t.kind == Kind::Word && t.text.eq_ignore_ascii_case(w) => {
                self.pos += 1;
                true
            }
            _ => false,
        }
    }

    fn end_of_input(&self) -> usize {
        self.tokens.last().map_or(0, |t| t.at + t.text.len())
    }

    // or := and ("or" and)*
    fn parse_or(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_and()?;
        while self.eat_word("or") || self.eat_symbol("||") {
            let right = self.parse_and()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    // and := not ("and" not)*
    fn parse_and(&mut self) -> Result<Node, ParseError> {
        let mut left = self.parse_not()?;
        while self.eat_word("and") || self.eat_symbol("&&") {
            let right = self.parse_not()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn eat_symbol(&mut self, s: &str) -> bool {
        // `&&` and `||` arrive as two consecutive single-char tokens only if
        // lexed that way; they are not, so this is a no-op kept for clarity of
        // intent should they be added. Deliberately does nothing today.
        let _ = s;
        false
    }

    // not := "not" not | primary
    fn parse_not(&mut self) -> Result<Node, ParseError> {
        if self.eat_word("not") {
            let inner = self.parse_not()?;
            return Ok(Node::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Node, ParseError> {
        let Some(tok) = self.peek().cloned() else {
            return Err(ParseError {
                at: self.end_of_input(),
                msg: "expected a term, found end of expression".into(),
            });
        };

        if tok.kind == Kind::LParen {
            self.pos += 1;
            let inner = self.parse_or()?;
            match self.peek() {
                Some(t) if t.kind == Kind::RParen => {
                    self.pos += 1;
                    return Ok(inner);
                }
                _ => {
                    return Err(ParseError {
                        at: tok.at,
                        msg: "unclosed `(`".into(),
                    });
                }
            }
        }

        if tok.kind != Kind::Word {
            return Err(ParseError {
                at: tok.at,
                msg: format!("expected a field name, found `{}`", tok.text),
            });
        }
        self.pos += 1;
        let field = tok.text;

        // A bare field with no operator is a truthiness test.
        let Some(next) = self.peek().cloned() else {
            return Ok(Node::Truthy(field));
        };
        let Kind::Op(op) = next.kind else {
            return Ok(Node::Truthy(field));
        };
        self.pos += 1;

        let Some(vt) = self.peek().cloned() else {
            return Err(ParseError {
                at: self.end_of_input(),
                msg: format!("`{field} {op}` needs a value"),
            });
        };
        self.pos += 1;
        let value = match vt.kind {
            Kind::Num(n) => Value::Num(n),
            Kind::Str | Kind::Word => Value::Str(vt.text),
            _ => {
                return Err(ParseError {
                    at: vt.at,
                    msg: format!("`{}` is not a value", vt.text),
                });
            }
        };
        Ok(Node::Compare { field, op, value })
    }
}

// ── evaluator ──────────────────────────────────────────────────────────

fn eval<Q: Queryable>(node: &Node, s: &Q) -> bool {
    match node {
        Node::And(a, b) => eval(a, s) && eval(b, s),
        Node::Or(a, b) => eval(a, s) || eval(b, s),
        Node::Not(a) => !eval(a, s),
        Node::Truthy(f) => s
            .field_bool(f)
            .or_else(|| s.field_num(f).map(|n| n != 0.0))
            .or_else(|| s.field_str(f).map(|t| !t.is_empty()))
            .unwrap_or(false),
        Node::Compare { field, op, value } => compare(s, field, *op, value),
    }
}

fn compare<Q: Queryable>(s: &Q, field: &str, op: Op, value: &Value) -> bool {
    // Numeric comparison when both sides are numbers.
    if let (Some(lhs), Value::Num(rhs)) = (s.field_num(field), value) {
        return match op {
            Op::Eq => (lhs - rhs).abs() < f64::EPSILON,
            Op::Ne => (lhs - rhs).abs() >= f64::EPSILON,
            Op::Gt => lhs > *rhs,
            Op::Lt => lhs < *rhs,
            Op::Ge => lhs >= *rhs,
            Op::Le => lhs <= *rhs,
            // `~` on a number is almost certainly a mistake, but reading it as
            // "contains as text" is more useful than silently returning false.
            Op::Match => lhs.to_string().contains(&rhs.to_string()),
        };
    }

    let Some(lhs) = s.field_str(field) else {
        // Unknown field never matches. It is not an error, because a filter is
        // often applied across subjects with different field sets.
        return false;
    };
    let rhs = match value {
        Value::Str(t) => t.clone(),
        Value::Num(n) => format_num(*n),
    };

    match op {
        Op::Eq => lhs.eq_ignore_ascii_case(&rhs),
        Op::Ne => !lhs.eq_ignore_ascii_case(&rhs),
        Op::Match => {
            let hay = lhs.to_ascii_lowercase();
            rhs.split('|')
                .filter(|p| !p.is_empty())
                .any(|p| hay.contains(&p.trim().to_ascii_lowercase()))
        }
        // Ordering on text is rarely what anyone means; compare lexically
        // rather than pretending the question was invalid.
        Op::Gt => lhs > rhs,
        Op::Lt => lhs < rhs,
        Op::Ge => lhs >= rhs,
        Op::Le => lhs <= rhs,
    }
}

fn format_num(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        n.to_string()
    }
}

// ── the fields a Stall exposes ─────────────────────────────────────────

impl Queryable for Stall {
    fn field_str(&self, name: &str) -> Option<String> {
        Some(match name {
            "unit" => self.unit.clone(),
            "cgroup" => self.cgroup.clone(),
            "resource" => self.resource.to_string(),
            "kind" | "type" => self.kind.to_string(),
            _ => return None,
        })
    }

    fn field_num(&self, name: &str) -> Option<f64> {
        Some(match name {
            "pct" | "pressure_pct" => self.pressure_pct,
            "peak" | "peak_pct" => self.peak_pct,
            "delta_ms" => self.delta_usec as f64 / 1000.0,
            "delta_usec" => self.delta_usec as f64,
            _ => return None,
        })
    }
}

impl Queryable for Warning {
    fn field_str(&self, name: &str) -> Option<String> {
        Some(match name {
            "warning.source" | "source" => self.source.clone(),
            "warning.severity" | "severity" => self.severity.to_string(),
            "warning.message" | "message" => self.message.clone(),
            _ => return None,
        })
    }

    fn field_num(&self, _name: &str) -> Option<f64> {
        None
    }

    fn field_bool(&self, name: &str) -> Option<bool> {
        match name {
            "warning.transient" | "transient" => Some(self.transient),
            _ => None,
        }
    }
}

/// Every field a filter can name, for `--help` and for tab completion later.
pub const FIELDS: &[(&str, &str)] = &[
    ("unit", "human name, e.g. firefox (flatpak)"),
    ("cgroup", "full cgroup path"),
    ("resource", "cpu | memory | io"),
    ("kind", "some | full"),
    ("pct", "share of the window spent stalled"),
    ("peak", "worst single tick in the window"),
    ("delta_ms", "milliseconds stalled"),
    ("warning.source", "btrfs | drive"),
    ("warning.severity", "note | warn | critical"),
    ("warning.transient", "true when it clears itself"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PsiKind, Resource};

    fn stall(unit: &str, res: Resource, pct: f64, peak: f64, ms: u64) -> Stall {
        Stall {
            unit: unit.into(),
            cgroup: format!("/sys/fs/cgroup/{unit}"),
            resource: res,
            kind: PsiKind::Full,
            delta_usec: ms * 1000,
            pressure_pct: pct,
            peak_pct: peak,
        }
    }

    fn f(s: &str) -> Filter {
        Filter::parse(s).unwrap_or_else(|e| panic!("{s:?} should parse: {e}"))
    }

    #[test]
    fn compares_numbers() {
        let s = stall("firefox", Resource::Io, 84.6, 93.0, 858);
        assert!(f("pct > 50").matches(&s));
        assert!(!f("pct > 90").matches(&s));
        assert!(f("peak >= 93").matches(&s));
        assert!(f("delta_ms > 500").matches(&s));
        assert!(f("delta_ms < 1000").matches(&s));
    }

    #[test]
    fn compares_text_case_insensitively() {
        let s = stall("Firefox", Resource::Io, 10.0, 10.0, 10);
        assert!(f("unit == firefox").matches(&s));
        assert!(f(r#"unit == "Firefox""#).matches(&s));
        assert!(f("resource == io").matches(&s));
        assert!(f("resource != cpu").matches(&s));
    }

    #[test]
    fn match_operator_supports_alternation() {
        let s = stall("com.mitchellh.ghostty", Resource::Io, 10.0, 10.0, 10);
        assert!(f(r#"unit ~ "ghostty""#).matches(&s));
        assert!(f(r#"unit ~ "firefox|ghostty|chrome""#).matches(&s));
        assert!(!f(r#"unit ~ "firefox|chrome""#).matches(&s));
    }

    #[test]
    fn boolean_operators_and_precedence() {
        let s = stall("firefox", Resource::Io, 84.0, 93.0, 858);
        assert!(f("resource == io and peak > 70").matches(&s));
        assert!(!f("resource == cpu and peak > 70").matches(&s));
        assert!(f("resource == cpu or peak > 70").matches(&s));
        assert!(f("not resource == cpu").matches(&s));
        // `and` must bind tighter than `or`: false and false, or true.
        assert!(f("resource == cpu and pct > 99 or peak > 70").matches(&s));
    }

    #[test]
    fn parentheses_override_precedence() {
        // resource == io is TRUE, peak > 70 is TRUE, pct > 50 is FALSE.
        // Chosen so the two groupings genuinely disagree; an example where
        // both give the same answer would pass while proving nothing.
        let s = stall("firefox", Resource::Io, 10.0, 93.0, 10);

        //  A or (B and C)  =>  true or (true and false)  =>  true
        assert!(f("resource == io or peak > 70 and pct > 50").matches(&s));

        // (A or B) and C   =>  (true or true) and false  =>  false
        assert!(!f("(resource == io or peak > 70) and pct > 50").matches(&s));
    }

    #[test]
    fn unit_suffixes_scale_the_number() {
        let s = stall("x", Resource::Io, 10.0, 10.0, 2_000);
        assert!(f("delta_ms > 1s").matches(&s), "1s should mean 1000ms");
        assert!(!f("delta_ms > 3s").matches(&s));
        // Longest-suffix-first: `ms` must not lex as `m`.
        assert!(f("delta_ms == 2000ms").matches(&s));
    }

    #[test]
    fn unknown_fields_never_match_and_never_error() {
        // A filter is applied across subjects with different fields, so an
        // unknown name has to be survivable rather than fatal.
        let s = stall("x", Resource::Io, 10.0, 10.0, 10);
        assert!(!f("nonsense > 1").matches(&s));
        assert!(!f("nonsense == anything").matches(&s));
        assert!(f("not nonsense == anything").matches(&s));
    }

    #[test]
    fn warnings_expose_their_own_fields() {
        let w = Warning {
            source: "btrfs".into(),
            severity: crate::Severity::Note,
            transient: true,
            message: "discard backlog".into(),
        };
        assert!(f("warning.source == btrfs").matches(&w));
        assert!(f("warning.transient").matches(&w));
        assert!(!f("not warning.transient").matches(&w));
        assert!(f(r#"warning.message ~ "discard""#).matches(&w));
    }

    #[test]
    fn errors_report_where_the_problem_is() {
        let e = Filter::parse("pct >").unwrap_err();
        assert!(e.msg.contains("needs a value"), "{}", e.msg);

        let e = Filter::parse("pct > 50 and").unwrap_err();
        assert!(e.msg.contains("end of expression"), "{}", e.msg);

        let e = Filter::parse("(pct > 50").unwrap_err();
        assert!(e.msg.contains("unclosed"), "{}", e.msg);

        let e = Filter::parse(r#"unit ~ "unterminated"#).unwrap_err();
        assert!(e.msg.contains("unterminated"), "{}", e.msg);

        let e = Filter::parse("pct > 50 pct > 60").unwrap_err();
        assert!(e.msg.contains("after a complete expression"), "{}", e.msg);
    }

    #[test]
    fn a_single_equals_is_accepted_because_everyone_types_it() {
        let s = stall("firefox", Resource::Io, 10.0, 10.0, 10);
        assert!(f("resource = io").matches(&s));
    }

    #[test]
    fn round_trips_its_own_source_for_display() {
        assert_eq!(f("  pct > 50  ").to_string(), "pct > 50");
    }

    #[test]
    fn garbage_never_panics() {
        for bad in [
            "", "and", "or", ")", "((((", "> 5", "unit ==", "~~~", "1 2 3", "not",
        ] {
            let _ = Filter::parse(bad); // must not panic
        }
    }
}
