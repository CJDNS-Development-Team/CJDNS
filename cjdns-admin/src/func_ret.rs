//! Remote function return values.

use std::collections::BTreeMap;

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

impl ReturnValue {
    /// Access stored Int value.
    pub fn as_int(&self) -> Result<i64, ()> {
        match *self {
            ReturnValue::Int(value) => Ok(value),
            _ => Err(()),
        }
    }

    /// Access stored String value.
    pub fn as_str(&self) -> Result<&str, ()> {
        match self {
            ReturnValue::String(value) => Ok(value.as_str()),
            _ => Err(()),
        }
    }

    /// Access stored List value, converting each list element.
    /// Returns a new `Vec` where each element is converted from another `ReturnValue` to the appropriate type.
    pub fn as_list<'rv, T, F>(&'rv self, mut item_convert: F) -> Result<Vec<T>, ()>
    where
        F: FnMut(&'rv ReturnValue) -> Result<T, ()>,
    {
        match self {
            ReturnValue::List(list) => list.iter().map(|v| item_convert(v)).collect(),
            _ => Err(()),
        }
    }

    /// Access stored Map value, converting each entry value element.
    /// Returns a new `BTreeMap` where each key is `String` and each value is converted from another `ReturnValue` to the appropriate type.
    pub fn as_map<'rv, T, F>(&'rv self, mut value_convert: F) -> Result<BTreeMap<String, T>, ()>
    where
        F: FnMut(&'rv ReturnValue) -> Result<T, ()>,
    {
        match self {
            ReturnValue::Map(map) => map.iter().map(|(k, v)| value_convert(v).map(|v| (k.clone(), v))).collect(),
            _ => Err(()),
        }
    }

    /// Access stored List<Int> value.
    /// Returns a new `Vec` where each element is converted to `i64`.
    pub fn as_int_list(&self) -> Result<Vec<i64>, ()> {
        self.as_list(Self::as_int)
    }

    /// Access stored Map<String, Int> value.
    /// Returns a new `BTreeMap` where each key is `String` and each value is converted to `i64`.
    pub fn as_int_map(&self) -> Result<BTreeMap<String, i64>, ()> {
        self.as_map(Self::as_int)
    }
}

#[cfg(test)]
mod tests {
    use super::ReturnValue;

    macro_rules! map {
        ( $( $key:literal => $value:expr ),+ ) => {{
            let mut m = ::std::collections::BTreeMap::new();
            $( m.insert($key.to_string(), $value); )+
            m
        }}
    }

    #[test]
    fn test_return_value_convert() {
        assert_eq!(ReturnValue::Int(42).as_int(), Ok(42));
        assert_eq!(ReturnValue::String("".to_string()).as_int(), Err(()));

        assert_eq!(ReturnValue::String("foo".to_string()).as_str(), Ok("foo"));
        assert_eq!(ReturnValue::Int(42).as_str(), Err(()));

        let list_rv = ReturnValue::List(vec![ReturnValue::Int(42), ReturnValue::Int(43)]);
        assert_eq!(list_rv.as_list(ReturnValue::as_int), Ok(vec![42, 43]));
        assert_eq!(list_rv.as_list(ReturnValue::as_str), Err(()));

        let list_rv = ReturnValue::List(vec![ReturnValue::Int(42), ReturnValue::String("foo".to_string())]);
        assert_eq!(list_rv.as_list(ReturnValue::as_int), Err(()));
        assert_eq!(list_rv.as_list(ReturnValue::as_str), Err(()));

        let map_rv = ReturnValue::Map(map!["foo" => ReturnValue::Int(42), "bar" => ReturnValue::Int(43)]);
        assert_eq!(map_rv.as_map(ReturnValue::as_int), Ok(map!["foo" => 42, "bar" => 43]));
        assert_eq!(map_rv.as_map(ReturnValue::as_str), Err(()));

        let map_rv = ReturnValue::Map(map!["foo" => ReturnValue::Int(42), "bar" => ReturnValue::String("baz".to_string())]);
        assert_eq!(map_rv.as_map(ReturnValue::as_int), Err(()));
        assert_eq!(map_rv.as_map(ReturnValue::as_str), Err(()));

        let mixed_rv = ReturnValue::List(vec![ReturnValue::Map(map![ "foo" => ReturnValue::Int(42) ])]);
        assert_eq!(mixed_rv.as_list(ReturnValue::as_int_map), Ok(vec![map!["foo" => 42]]));

        let mixed_rv = ReturnValue::Map(map!["foo" => ReturnValue::List(vec![ReturnValue::Int(42)])]);
        assert_eq!(mixed_rv.as_map(ReturnValue::as_int_list), Ok(map!["foo" => vec![42]]));
    }
}

/// Deserialization using `serde`.
mod deserialize {
    use std::collections::BTreeMap;
    use std::fmt;

    use serde::de::{Error, MapAccess, SeqAccess, Unexpected, Visitor};
    use serde::{Deserialize, Deserializer};

    use super::ReturnValue;

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
}

/// Debug trait implementation.
mod debug {
    use std::fmt;

    use super::ReturnValue;

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
}
