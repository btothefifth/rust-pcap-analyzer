//! A snapshot can be collected for a library caller or encoded a row at a time.
use super::{Error, Result, J};

pub(super) enum Projection<'a> {
    Value(J),
    Hex(&'a [u8]),
    Array(Box<dyn Iterator<Item = Projection<'a>> + 'a>),
    Object(Vec<(&'static str, Projection<'a>)>),
}

impl<T: Into<J>> From<T> for Projection<'_> {
    fn from(value: T) -> Self {
        Self::Value(value.into())
    }
}

impl<'a> Projection<'a> {
    pub(super) fn array<T: Into<Self> + 'a>(rows: impl Iterator<Item = T> + 'a) -> Self {
        Self::Array(Box::new(rows.map(Into::into)))
    }

    pub(super) fn object(fields: impl IntoIterator<Item = (&'static str, Self)>) -> Self {
        Self::Object(fields.into_iter().collect())
    }

    pub(super) fn into_json(self) -> J {
        match self {
            Self::Value(value) => value,
            Self::Hex(bytes) => crate::sha256::hex(bytes).into(),
            Self::Array(items) => J::array(items.map(Self::into_json)),
            Self::Object(fields) => J::object(fields.into_iter().map(|(k, v)| (k, v.into_json()))),
        }
    }

    pub(super) fn write(self, out: &mut Output) -> Result<()> {
        match self {
            Self::Value(value) => out.value(&value),
            Self::Hex(bytes) => {
                let size = bytes
                    .len()
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(2))
                    .ok_or_else(|| Error::limit("report_bytes"))?;
                out.reserve(size)?;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.text.push('"');
                for b in bytes {
                    out.text.push(HEX[usize::from(b >> 4)] as char);
                    out.text.push(HEX[usize::from(b & 15)] as char);
                }
                out.text.push('"');
                Ok(())
            }
            Self::Array(items) => {
                out.push("[")?;
                for (i, item) in items.enumerate() {
                    if i != 0 {
                        out.push(",")?;
                    }
                    item.write(out)?;
                }
                out.push("]")
            }
            Self::Object(fields) => {
                out.push("{")?;
                out.fields(fields)?;
                out.push("}")
            }
        }
    }
}

pub(super) struct Output {
    pub(super) text: String,
    pub(super) limit: usize,
}
impl Output {
    pub(super) fn fields<'a>(
        &mut self,
        fields: impl IntoIterator<Item = (&'static str, Projection<'a>)>,
    ) -> Result<()> {
        for (i, (key, item)) in fields.into_iter().enumerate() {
            if i != 0 {
                self.push(",")?;
            }
            self.value(&J::from(key))?;
            self.push(":")?;
            item.write(self)?;
        }
        Ok(())
    }
    fn reserve(&mut self, size: usize) -> Result<()> {
        if size > self.limit - self.text.len() {
            return Err(Error::limit("report_bytes"));
        }
        self.text
            .try_reserve(size)
            .map_err(|_| Error::limit("report_allocation"))
    }
    pub(super) fn push(&mut self, text: &str) -> Result<()> {
        self.reserve(text.len())?;
        self.text.push_str(text);
        Ok(())
    }
    pub(super) fn value(&mut self, value: &J) -> Result<()> {
        value.append_bounded(&mut self.text, self.limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_limit_stops_requesting_rows() {
        let mut visited = 0;
        let rows = (0..100).map(|_| {
            visited += 1;
            "abc"
        });
        let mut out = Output {
            text: String::new(),
            limit: 11,
        };
        let error = Projection::array(rows).write(&mut out).unwrap_err();
        assert_eq!(error.field, "report_bytes");
        assert_eq!(visited, 2);
    }
}
