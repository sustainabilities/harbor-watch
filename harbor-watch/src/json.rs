//! Hand-rolled JSON: an RFC 8259 subset, parser and serializer.
//!
//! Same discipline as the recorded harbor-knowledge json module: a
//! deliberately small, depth-capped (MAX_DEPTH 128) parser that refuses
//! runaway nesting and non-finite numbers (`1e999` is refused, not
//! silently mapped to infinity).

use std::collections::BTreeMap;
use std::fmt::Write as _;

pub const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|f| f as i64)
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn str(s: &str) -> Value {
        Value::Str(s.to_string())
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let bytes: Vec<char> = input.chars().collect();
    let mut p = Parser { b: &bytes, i: 0, depth: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(format!("trailing data at offset {}", p.i));
    }
    Ok(v)
}

pub fn to_string(v: &Value) -> String {
    let mut s = String::new();
    write_value(&mut s, v);
    s
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => {
            if !n.is_finite() {
                out.push_str("null"); // never emit non-finite
            } else if *n == n.trunc() && n.abs() < 9.007_199_254_740_992e15 {
                let _ = write!(out, "{}", *n as i64);
            } else {
                let _ = write!(out, "{}", n);
            }
        }
        Value::Str(s) => write_string(out, s),
        Value::Arr(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 { out.push(','); }
                write_value(out, v);
            }
            out.push(']');
        }
        Value::Obj(m) => {
            out.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 { out.push(','); }
                write_string(out, k);
                out.push(':');
                write_value(out, v);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [char],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], ' ' | '\t' | '\n' | '\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<char> {
        self.b.get(self.i).copied()
    }

    fn value(&mut self) -> Result<Value, String> {
        if self.depth >= MAX_DEPTH {
            return Err("recursion depth exceeded".into());
        }
        self.skip_ws();
        match self.peek() {
            None => Err("unexpected end of input".into()),
            Some('n') => self.lit("null", Value::Null),
            Some('t') => self.lit("true", Value::Bool(true)),
            Some('f') => self.lit("false", Value::Bool(false)),
            Some('"') => Ok(Value::Str(self.string()?)),
            Some('[') => {
                self.depth += 1;
                self.i += 1;
                let mut arr = Vec::new();
                self.skip_ws();
                if self.peek() == Some(']') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Arr(arr));
                }
                loop {
                    arr.push(self.value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => { self.i += 1; }
                        Some(']') => { self.i += 1; break; }
                        _ => return Err("expected ',' or ']'".into()),
                    }
                }
                self.depth -= 1;
                Ok(Value::Arr(arr))
            }
            Some('{') => {
                self.depth += 1;
                self.i += 1;
                let mut m = BTreeMap::new();
                self.skip_ws();
                if self.peek() == Some('}') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Obj(m));
                }
                loop {
                    self.skip_ws();
                    let k = self.string()?;
                    self.skip_ws();
                    if self.peek() != Some(':') {
                        return Err("expected ':'".into());
                    }
                    self.i += 1;
                    let v = self.value()?;
                    m.insert(k, v);
                    self.skip_ws();
                    match self.peek() {
                        Some(',') => { self.i += 1; }
                        Some('}') => { self.i += 1; break; }
                        _ => return Err("expected ',' or '}'".into()),
                    }
                }
                self.depth -= 1;
                Ok(Value::Obj(m))
            }
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("unexpected character '{}'", c)),
        }
    }

    fn lit(&mut self, want: &str, v: Value) -> Result<Value, String> {
        for c in want.chars() {
            if self.peek() != Some(c) {
                return Err(format!("expected literal {}", want));
            }
            self.i += 1;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some('"') {
            return Err("expected string".into());
        }
        self.i += 1;
        let mut s = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                '"' => return Ok(s),
                '\\' => {
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'b' => s.push('\u{08}'),
                        'f' => s.push('\u{0C}'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'u' => {
                            let mut cp: u32 = 0;
                            for _ in 0..4 {
                                let h = self.peek().ok_or("bad \\u escape")?;
                                self.i += 1;
                                cp = cp * 16
                                    + h.to_digit(16).ok_or("bad hex digit in \\u escape")?;
                            }
                            if (0xD800..0xDC00).contains(&cp) {
                                // surrogate pair
                                if self.peek() == Some('\\') {
                                    self.i += 1;
                                    if self.peek() == Some('u') {
                                        self.i += 1;
                                        let mut lo: u32 = 0;
                                        for _ in 0..4 {
                                            let h = self.peek().ok_or("bad \\u escape")?;
                                            self.i += 1;
                                            lo = lo * 16 + h.to_digit(16)
                                                .ok_or("bad hex digit")?;
                                        }
                                        if (0xDC00..0xE000).contains(&lo) {
                                            let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                            s.push(char::from_u32(c).unwrap_or('\u{FFFD}'));
                                            continue;
                                        }
                                    }
                                }
                                s.push('\u{FFFD}');
                            } else if (0xDC00..0xE000).contains(&cp) {
                                s.push('\u{FFFD}'); // lone low surrogate
                            } else {
                                s.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c => s.push(c),
            }
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        let mut digits = 0;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
            digits += 1;
        }
        if digits == 0 {
            return Err("number with no digits".into());
        }
        if self.peek() == Some('.') {
            self.i += 1;
            let mut frac = 0;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
                frac += 1;
            }
            if frac == 0 {
                return Err("fraction with no digits".into());
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.i += 1;
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.i += 1;
            }
            let mut exp = 0;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
                exp += 1;
            }
            if exp == 0 {
                return Err("exponent with no digits".into());
            }
        }
        let text: String = self.b[start..self.i].iter().collect();
        let n: f64 = text.parse().map_err(|_| "bad number")?;
        if !n.is_finite() {
            return Err("number out of range (refused, not infinity)".into());
        }
        Ok(Value::Num(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_object() {
        let src = r#"{"name":"harbor","n":42,"pi":3.5,"ok":true,"none":null,"arr":[1,2,3]}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("name").unwrap().as_str(), Some("harbor"));
        assert_eq!(v.get("n").unwrap().as_i64(), Some(42));
        assert_eq!(v.get("arr").unwrap(), &Value::Arr(vec![
            Value::Num(1.0), Value::Num(2.0), Value::Num(3.0)]));
        let out = to_string(&v);
        let v2 = parse(&out).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn escapes_preserved() {
        let v = parse(r#""a\"b\\c\nd""#).unwrap();
        assert_eq!(v, Value::Str("a\"b\\c\nd".into()));
        assert_eq!(to_string(&v), r#""a\"b\\c\nd""#);
    }

    #[test]
    fn unicode_escaped() {
        let v = parse(r#""é""#).unwrap();
        assert_eq!(v, Value::Str("é".into()));
    }

    #[test]
    fn surrogate_pair() {
        let v = parse(r#""😀""#).unwrap();
        assert_eq!(v, Value::Str("\u{1F600}".into()));
    }

    #[test]
    fn one_e_999_refused() {
        assert!(parse("1e999").is_err());
    }

    #[test]
    fn depth_capped() {
        let deep = "[".repeat(5000) + &"]".repeat(5000);
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn trailing_data_refused() {
        assert!(parse("{} {}").is_err());
    }

    #[test]
    fn bad_literals_refused() {
        assert!(parse("tru").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\"}").is_err());
        assert!(parse("01x").is_err());
    }

    #[test]
    fn control_chars_escaped_on_output() {
        let mut m = BTreeMap::new();
        m.insert("k".into(), Value::Str("x\u{1}y".into()));
        let s = to_string(&Value::Obj(m));
        assert_eq!(s, "{\"k\":\"x\\u0001y\"}");
    }
}
