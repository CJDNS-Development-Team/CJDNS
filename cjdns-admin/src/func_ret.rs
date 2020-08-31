//! Remote function return values.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer};
use serde::de::{Error, MapAccess, SeqAccess, Unexpected, Visitor};

/// Remote function return value. Supports json-like data types.
#[derive(Clone, PartialEq, Eq)]
pub enum ReturnValue {
    /// Integer return value.
    Int(i64),
    /// String return value.
    String(String),
    /// List return value.
    List(Vec<ReturnValue>),
    /// Map return value.
    Map(BTreeMap<String, ReturnValue>),
}

impl<'de> Deserialize<'de> for ReturnValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ReturnValueVisitor)
    }
}

struct ReturnValueVisitor;

impl<'de> Visitor<'de> for ReturnValueVisitor {
    type Value = ReturnValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "an integer, byte string, list or map")
    }

    fn visit_i64<E: Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(ReturnValue::Int(v))
    }

    fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
        if v > i64::MAX as u64 {
            return Err(Error::invalid_value(Unexpected::Unsigned(v), &"64-bit signed integer"));
        }
        Ok(ReturnValue::Int(v as i64))
    }

    fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let s = String::from_utf8(v.to_owned()).map_err(|_| Error::invalid_value(Unexpected::Bytes(v), &"cannot parse byte array as UTF-8 string"))?;
        Ok(ReturnValue::String(s))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut res = Vec::with_capacity(seq.size_hint().unwrap_or_default());

        while let Some(item) = seq.next_element()? {
            res.push(item)
        }

        Ok(ReturnValue::List(res))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut res = BTreeMap::new();

        while let Some((key, value)) = map.next_entry()? {
            res.insert(key, value);
        }

        Ok(ReturnValue::Map(res))
    }
}

impl fmt::Debug for ReturnValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReturnValue::Int(v) => write!(f, "{}", v),
            ReturnValue::String(s) => write!(f, r#""{}""#, s),
            ReturnValue::List(list) => write!(f, "{:?}", list),
            ReturnValue::Map(map) => write!(f, "{:?}", map),
        }
    }
}
