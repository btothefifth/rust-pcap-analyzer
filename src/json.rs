//! Small output-only JSON encoder. No hand-interpolated capture strings.
use std::fmt::Write;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}
impl Json {
    pub fn object(items: impl IntoIterator<Item = (&'static str, Json)>) -> Self {
        Self::Object(items.into_iter().collect())
    }
    pub fn array(items: impl IntoIterator<Item = Json>) -> Self {
        Self::Array(items.into_iter().collect())
    }
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }
    pub fn encode(&self) -> String {
        let mut out = String::new();
        self.render(&mut out);
        out
    }
    /// Check exact encoded size before allocating the serialized document.
    pub fn encode_bounded(&self, limit: usize) -> crate::Result<String> {
        if self.encoded_len().is_none_or(|size| size > limit) {
            return Err(crate::Error::limit("report_bytes"));
        }
        Ok(self.encode())
    }
    /// Encode a JSON document plus its line terminator within one exact limit.
    pub fn encode_bounded_line(&self, limit: usize) -> crate::Result<String> {
        let encoded = self.encode_bounded(
            limit
                .checked_sub(1)
                .ok_or_else(|| crate::Error::limit("report_bytes"))?,
        )?;
        let mut line = encoded;
        line.push('\n');
        Ok(line)
    }
    fn encoded_len(&self) -> Option<usize> {
        match self {
            Self::Null => Some(4),
            Self::Bool(true) => Some(4),
            Self::Bool(false) => Some(5),
            Self::Number(n) => Some(n.to_string().len()),
            Self::String(s) => quoted_len(s),
            Self::Array(items) => items
                .iter()
                .try_fold(2usize, |size, item| size.checked_add(item.encoded_len()?))?
                .checked_add(items.len().saturating_sub(1)),
            Self::Object(items) => items
                .iter()
                .try_fold(2usize, |size, (key, value)| {
                    size.checked_add(quoted_len(key)?)?
                        .checked_add(1)?
                        .checked_add(value.encoded_len()?)
                })?
                .checked_add(items.len().saturating_sub(1)),
        }
    }
    fn render(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Self::Number(v) => {
                let _ = write!(out, "{v}");
            }
            Self::String(v) => escape(v, out),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    item.render(out);
                }
                out.push(']');
            }
            Self::Object(items) => {
                out.push('{');
                for (i, (key, item)) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    escape(key, out);
                    out.push(':');
                    item.render(out);
                }
                out.push('}');
            }
        }
    }
}
fn escape(value: &str, out: &mut String) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 32 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
impl From<u64> for Json {
    fn from(v: u64) -> Self {
        Self::Number(v)
    }
}
impl From<u32> for Json {
    fn from(v: u32) -> Self {
        Self::Number(u64::from(v))
    }
}
impl From<u16> for Json {
    fn from(v: u16) -> Self {
        Self::Number(u64::from(v))
    }
}
impl From<u8> for Json {
    fn from(v: u8) -> Self {
        Self::Number(u64::from(v))
    }
}
impl From<usize> for Json {
    fn from(v: usize) -> Self {
        Self::Number(v as u64)
    }
}
impl From<bool> for Json {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<&str> for Json {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}
impl From<String> for Json {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

fn quoted_len(value: &str) -> Option<usize> {
    value.chars().try_fold(2usize, |size, c| {
        let n = match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\x08' | '\x0c' => 2,
            c if (c as u32) < 32 => 6,
            c => c.len_utf8(),
        };
        size.checked_add(n)
    })
}
