//! RPC messages.

use std::collections::BTreeMap;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::func_ret::ReturnValue;

pub(crate) use self::internal::*;

/// Traits and their blanket implementations used internally to encode/decode RPC messages.
mod internal {
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::errors::Error;

    use super::{Args, Payload};

    /// Internal trait for the RPC request type. Implemented by `Query` and `AuthQuery`.
    pub(crate) trait Request: Sized {
        fn to_bencode(&self) -> Result<Vec<u8>, Error>;
    }

    /// Internal trait for the RPC response type. Implemented by `GenericResponse`.
    pub(crate) trait Response: Sized {
        fn from_bencode(bytes: &[u8]) -> Result<Self, Error>;
    }

    // Implements `Request` for `Query` and `QueryAuth`.
    impl<T: Serialize> Request for T {
        fn to_bencode(&self) -> Result<Vec<u8>, Error> {
            bendy::serde::to_bytes(self).map_err(|e| Error::Protocol(e))
        }
    }

    // Implements `Response` for `GenericResponse`.
    impl<T: DeserializeOwned> Response for T {
        fn from_bencode(bytes: &[u8]) -> Result<Self, Error> {
            bendy::serde::from_bytes(bytes).map_err(|e| Error::Protocol(e))
        }
    }

    /// Generic RPC query without authentication.
    #[derive(Serialize, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct Query<A: Args> {
        #[serde(rename = "txid")]
        pub(crate) txid: String,

        #[serde(rename = "q")]
        pub(crate) q: String,

        #[serde(rename = "args")]
        pub(crate) args: A,
    }

    /// Generic RPC query with authentication.
    #[derive(Serialize, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct AuthQuery<A: Args> {
        #[serde(rename = "txid")]
        pub(crate) txid: String,

        #[serde(rename = "q")]
        pub(crate) q: String,

        #[serde(rename = "aq")]
        pub(crate) aq: String,

        #[serde(rename = "args")]
        pub(crate) args: A,

        #[serde(rename = "cookie")]
        pub(crate) cookie: String,

        #[serde(rename = "hash")]
        pub(crate) hash: String,
    }

    /// Generic RPC response.
    #[derive(Deserialize, Clone, PartialEq, Eq, Debug)]
    pub(crate) struct GenericResponse<P: Payload> {
        #[serde(rename = "txid")]
        pub(crate) txid: String,

        #[serde(rename = "error", default)]
        pub(crate) error: String,

        #[serde(flatten, default)]
        #[serde(bound(deserialize = "P: DeserializeOwned"))]
        pub(crate) payload: P,
    }

    #[test]
    fn test_bencode_leading_zeroes() {
        /*
         * Bencode does not allow leading zeroes in encoded integers.
         * Alas, cjdns' original implementation violates this rule,
         * and sometimes encodes ints with leading zeroes.
         * To work around this, bencode library (bendy) should be patched
         * to support this.
         * This test checks that we use correct (patched) library.
         */
        assert_eq!(u8::from_bencode("i042e".as_bytes()).ok(), Some(42_u8));
    }
}

/// Trait for RPC query arguments. Can be any serializable type.
pub trait Args: Serialize {}

/// Trait for RPC query return value. Can be any deserializable type with `Default`.
pub trait Payload: DeserializeOwned + Default {}

// Blanket `Args` impl for any serializable type.
impl<T: Serialize> Args for T {}

// Blanket `Payload` impl for any deserializable type with `Default`.
impl<T: DeserializeOwned + Default> Payload for T {}

/// Empty payload or arguments.
#[derive(Deserialize, Serialize, Default, Clone, PartialEq, Eq, Debug)]
pub struct Empty {}

/// Generic return value with fields exposed as a map.
pub type GenericResponsePayload = BTreeMap<String, ReturnValue>;

/// Return value for `cookie` remote function.
#[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub(crate) struct CookieResponsePayload {
    #[serde(rename = "cookie")]
    pub(crate) cookie: String
}

/// Arguments for `Admin_availableFunctions` remote function.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct AvailableFnsQueryArg {
    #[serde(rename = "page")]
    pub(crate) page: usize
}

/// Return value for `Admin_availableFunctions` remote function.
#[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub(crate) struct AvailableFnsResponsePayload {
    #[serde(rename = "availableFunctions", default)]
    pub(crate) available_fns: RemoteFnDescrs
}

/// Map of remote function names to map of arguments.
pub(crate) type RemoteFnDescrs = BTreeMap<String, RemoteFnArgsDescr>;

/// Map of function argument names to argument descriptions.
pub(crate) type RemoteFnArgsDescr = BTreeMap<String, RemoteFnArgDescr>;

/// Remote function argument description.
#[derive(Deserialize, Default, Clone, PartialEq, Eq, Debug)]
pub(crate) struct RemoteFnArgDescr {
    #[serde(rename = "required")]
    pub(crate) required: u8,

    #[serde(rename = "type")]
    pub(crate) typ: String,
}
