//! A strict JSON reader: repeated member names are refused, every member
//! must be taken, and only the value kinds CEL uses are kept.

use crate::error::{Error, Result};
use crate::model::MAX_BYTES;
use std::collections::BTreeSet;

/// A JSON value that remembers member order and refuses repeated names.
/// Values no CEL field takes (null, booleans, negative and fractional
/// numbers) are kept only as their kind.
pub(crate) enum J {
    Other,
    Uint(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl<'de> serde::Deserialize<'de> for J {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = J;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_unit<E>(self) -> std::result::Result<J, E> {
                Ok(J::Other)
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<J, E> {
                Ok(J::Other)
            }
            fn visit_u64<E>(self, v: u64) -> std::result::Result<J, E> {
                Ok(J::Uint(v))
            }
            fn visit_i64<E>(self, v: i64) -> std::result::Result<J, E> {
                Ok(u64::try_from(v).map_or(J::Other, J::Uint))
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<J, E> {
                Ok(J::Other)
            }
            fn visit_str<E>(self, v: &str) -> std::result::Result<J, E> {
                Ok(J::Str(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> std::result::Result<J, E> {
                Ok(J::Str(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<J, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element()? {
                    out.push(v);
                }
                Ok(J::Arr(out))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<J, A::Error> {
                use serde::de::Error as _;
                let mut seen = BTreeSet::new();
                let mut out = Vec::new();
                while let Some(k) = map.next_key::<String>()? {
                    if !seen.insert(k.clone()) {
                        return Err(A::Error::custom(format!("repeated member name {k:?}")));
                    }
                    out.push((k, map.next_value()?));
                }
                Ok(J::Obj(out))
            }
        }
        d.deserialize_any(V)
    }
}

pub(crate) fn bad(what: &str, reason: impl std::fmt::Display) -> Error {
    Error::Json(format!("{what}: {reason}"))
}

/// The members of one object, each taken at most once; `finish` refuses the rest.
pub(crate) struct Members<'a> {
    what: String,
    items: &'a [(String, J)],
    taken: Vec<bool>,
}

impl<'a> Members<'a> {
    pub(crate) fn new(v: &'a J, what: String) -> Result<Self> {
        match v {
            J::Obj(items) => Ok(Members {
                what,
                items,
                taken: vec![false; items.len()],
            }),
            _ => Err(bad(&what, "expected an object")),
        }
    }

    pub(crate) fn take(&mut self, name: &str) -> Option<&'a J> {
        let i = self.items.iter().position(|(k, _)| k == name)?;
        self.taken[i] = true;
        Some(&self.items[i].1)
    }

    pub(crate) fn req(&mut self, name: &str) -> Result<&'a J> {
        let what = format!("{}.{name}", self.what);
        self.take(name).ok_or_else(|| bad(&what, "missing"))
    }

    pub(crate) fn finish(self) -> Result<()> {
        match self.items.iter().zip(&self.taken).find(|(_, t)| !**t) {
            Some(((k, _), _)) => Err(bad(&self.what, format!("unexpected member {k:?}"))),
            None => Ok(()),
        }
    }
}

pub(crate) fn uint(v: &J, what: &str) -> Result<u64> {
    match v {
        J::Uint(n) => Ok(*n),
        _ => Err(bad(what, "expected an unsigned integer")),
    }
}

pub(crate) fn narrow<T: TryFrom<u64>>(v: &J, what: &str) -> Result<T> {
    T::try_from(uint(v, what)?).map_err(|_| bad(what, "out of range"))
}

pub(crate) fn text<'a>(v: &'a J, what: &str) -> Result<&'a str> {
    match v {
        J::Str(s) if s.len() <= MAX_BYTES => Ok(s),
        J::Str(_) => Err(bad(what, "too long")),
        _ => Err(bad(what, "expected a string")),
    }
}

pub(crate) fn hex_bytes(v: &J, what: &str, max: usize) -> Result<Vec<u8>> {
    let s = match v {
        J::Str(s) => s,
        _ => return Err(bad(what, "expected a hex string")),
    };
    if s.len() > max.saturating_mul(2) {
        return Err(bad(what, format!("longer than {max} bytes")));
    }
    hex::decode(s).map_err(|e| bad(what, e))
}

/// Parse `data` as one JSON value.
pub(crate) fn parse(data: &[u8]) -> Result<J> {
    serde_json::from_slice(data).map_err(|e| Error::Json(e.to_string()))
}

/// A JSON string literal, escaped as RFC 8785 (JCS) escapes it: serde_json
/// escapes exactly the quote, the backslash and U+0000 to U+001F, with
/// lowercase hex, and leaves every other character as UTF-8.
pub(crate) fn string(s: &str, out: &mut String) {
    out.push_str(&serde_json::to_string(s).expect("a str always serializes"));
}
