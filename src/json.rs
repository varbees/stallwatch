//! A minimal JSON reader, because Varlink requests arrive as JSON from a socket.
//!
//! Writing a parser rather than string-matching on `"method"` is deliberate:
//! this consumes untrusted input, and a scanner that guesses will eventually
//! be handed something that makes it guess wrong. It is small because it only
//! has to handle what Varlink sends — objects, strings, numbers, bools, null,
//! arrays — not because correctness was traded away.
//!
//! Serialisation lives in `lib.rs`; this is read-only.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if *n >= 0.0 && n.is_finite() => Some(*n as u64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Json, &'static str> {
    let b = input.as_bytes();
    let mut i = 0;
    let v = value(b, &mut i)?;
    skip_ws(b, &mut i);
    if i != b.len() {
        return Err("trailing data after JSON value");
    }
    Ok(v)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
        *i += 1;
    }
}

fn value(b: &[u8], i: &mut usize) -> Result<Json, &'static str> {
    skip_ws(b, i);
    match b.get(*i) {
        None => Err("unexpected end of input"),
        Some(b'{') => object(b, i),
        Some(b'[') => array(b, i),
        Some(b'"') => string(b, i).map(Json::Str),
        Some(b't') => lit(b, i, b"true", Json::Bool(true)),
        Some(b'f') => lit(b, i, b"false", Json::Bool(false)),
        Some(b'n') => lit(b, i, b"null", Json::Null),
        Some(_) => number(b, i),
    }
}

fn lit(b: &[u8], i: &mut usize, want: &[u8], out: Json) -> Result<Json, &'static str> {
    if b.len() >= *i + want.len() && &b[*i..*i + want.len()] == want {
        *i += want.len();
        Ok(out)
    } else {
        Err("bad literal")
    }
}

fn object(b: &[u8], i: &mut usize) -> Result<Json, &'static str> {
    *i += 1; // {
    let mut m = BTreeMap::new();
    skip_ws(b, i);
    if b.get(*i) == Some(&b'}') {
        *i += 1;
        return Ok(Json::Obj(m));
    }
    loop {
        skip_ws(b, i);
        if b.get(*i) != Some(&b'"') {
            return Err("object key must be a string");
        }
        let k = string(b, i)?;
        skip_ws(b, i);
        if b.get(*i) != Some(&b':') {
            return Err("expected ':' after object key");
        }
        *i += 1;
        m.insert(k, value(b, i)?);
        skip_ws(b, i);
        match b.get(*i) {
            Some(b',') => *i += 1,
            Some(b'}') => {
                *i += 1;
                return Ok(Json::Obj(m));
            }
            _ => return Err("expected ',' or '}'"),
        }
    }
}

fn array(b: &[u8], i: &mut usize) -> Result<Json, &'static str> {
    *i += 1; // [
    let mut v = Vec::new();
    skip_ws(b, i);
    if b.get(*i) == Some(&b']') {
        *i += 1;
        return Ok(Json::Arr(v));
    }
    loop {
        v.push(value(b, i)?);
        skip_ws(b, i);
        match b.get(*i) {
            Some(b',') => *i += 1,
            Some(b']') => {
                *i += 1;
                return Ok(Json::Arr(v));
            }
            _ => return Err("expected ',' or ']'"),
        }
    }
}

fn string(b: &[u8], i: &mut usize) -> Result<String, &'static str> {
    *i += 1; // opening quote
    let mut s = String::new();
    loop {
        match b.get(*i) {
            None => return Err("unterminated string"),
            Some(b'"') => {
                *i += 1;
                return Ok(s);
            }
            Some(b'\\') => {
                *i += 1;
                match b.get(*i) {
                    Some(b'"') => s.push('"'),
                    Some(b'\\') => s.push('\\'),
                    Some(b'/') => s.push('/'),
                    Some(b'n') => s.push('\n'),
                    Some(b't') => s.push('\t'),
                    Some(b'r') => s.push('\r'),
                    Some(b'b') => s.push('\u{8}'),
                    Some(b'f') => s.push('\u{c}'),
                    Some(b'u') => {
                        // \uXXXX. Surrogate pairs are not handled: Varlink
                        // method names and our parameters are ASCII, and
                        // silently mangling astral-plane text would be worse
                        // than refusing it.
                        let hex = b.get(*i + 1..*i + 5).ok_or("truncated \\u escape")?;
                        let cp = u32::from_str_radix(
                            std::str::from_utf8(hex).map_err(|_| "bad \\u escape")?,
                            16,
                        )
                        .map_err(|_| "bad \\u escape")?;
                        s.push(char::from_u32(cp).ok_or("unsupported \\u codepoint")?);
                        *i += 4;
                    }
                    _ => return Err("bad escape"),
                }
                *i += 1;
            }
            Some(_) => {
                // Copy one whole UTF-8 sequence.
                let start = *i;
                let len = utf8_len(b[*i]);
                if start + len > b.len() {
                    return Err("truncated UTF-8");
                }
                s.push_str(std::str::from_utf8(&b[start..start + len]).map_err(|_| "bad UTF-8")?);
                *i += len;
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

fn number(b: &[u8], i: &mut usize) -> Result<Json, &'static str> {
    let start = *i;
    if b.get(*i) == Some(&b'-') {
        *i += 1;
    }
    while matches!(b.get(*i), Some(c) if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
    {
        *i += 1;
    }
    std::str::from_utf8(&b[start..*i])
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Json::Num)
        .ok_or("bad number")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_varlink_request() {
        let j =
            parse(r#"{"method":"dev.stallwatch.Monitor.GetStalls","parameters":{"seconds":30}}"#)
                .unwrap();
        assert_eq!(
            j.get("method").and_then(Json::as_str),
            Some("dev.stallwatch.Monitor.GetStalls")
        );
        assert_eq!(
            j.get("parameters")
                .and_then(|p| p.get("seconds"))
                .and_then(Json::as_u64),
            Some(30)
        );
    }

    #[test]
    fn handles_empty_and_nested_structures() {
        assert_eq!(parse("{}").unwrap(), Json::Obj(Default::default()));
        assert_eq!(parse("[]").unwrap(), Json::Arr(vec![]));
        assert!(parse(r#"{"a":{"b":[1,2,{"c":null}]}}"#).is_ok());
    }

    #[test]
    fn handles_escapes_and_unicode() {
        assert_eq!(parse(r#""a\"b""#).unwrap().as_str(), Some("a\"b"));
        assert_eq!(parse(r#""a\\x2db""#).unwrap().as_str(), Some(r"a\x2db"));
        assert_eq!(parse(r#""A""#).unwrap().as_str(), Some("A"));
        assert_eq!(parse(r#""héllo""#).unwrap().as_str(), Some("héllo"));
    }

    #[test]
    fn rejects_malformed_input_rather_than_guessing() {
        for bad in [
            "",
            "{",
            "}",
            "[",
            r#"{"a"}"#,
            r#"{"a":}"#,
            r#"{a:1}"#,
            r#""unterminated"#,
            "tru",
            r#"{} extra"#,
            r#"{"a":1,}"#,
        ] {
            assert!(parse(bad).is_err(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn negative_and_float_numbers_do_not_become_u64() {
        assert_eq!(parse("-5").unwrap().as_u64(), None);
        assert_eq!(parse("3.9").unwrap().as_u64(), Some(3));
        assert_eq!(parse("42").unwrap().as_u64(), Some(42));
    }

    #[test]
    fn deeply_nested_input_does_not_crash() {
        let deep = "[".repeat(200) + &"]".repeat(200);
        let _ = parse(&deep);
    }
}
