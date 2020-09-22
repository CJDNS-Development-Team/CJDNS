//! CJDNS private key

use std::convert::TryFrom;

use regex::Regex;
use sodiumoxide::crypto::scalarmult;
use sodiumoxide::randombytes::randombytes;

use crate::{
    errors::{KeyError, Result},
    BytesRepr,
};

lazy_static! {
    static ref PRIVATE_KEY_RE: Regex = Regex::new("^[0-9a-fA-F]{64}$").expect("bad regexp");
}

/// CJDNS private key type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNSPrivateKey {
    k: String,
}

impl TryFrom<String> for CJDNSPrivateKey {
    type Error = KeyError;

    fn try_from(value: String) -> Result<Self> {
        if PRIVATE_KEY_RE.is_match(&value) {
            return Ok(CJDNSPrivateKey { k: value });
        }
        Err(KeyError::CannotCreateFromString)
    }
}

impl From<[u8; 32]> for CJDNSPrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        CJDNSPrivateKey { k: hex::encode(bytes) }
    }
}

impl BytesRepr for CJDNSPrivateKey {
    fn bytes(&self) -> Vec<u8> {
        hex::decode(&self.k).expect("broken invariant")
    }
}

impl CJDNSPrivateKey {
    pub(crate) fn new() -> Self {
        let random_bytes_for_key = randombytes(32);
        CJDNSPrivateKey {
            k: hex::encode(random_bytes_for_key),
        }
    }

    pub(crate) fn to_scalar(&self) -> scalarmult::Scalar {
        scalarmult::Scalar(self.bytes_32())
    }

    fn bytes_32(&self) -> [u8; 32] {
        let mut private_key_bytes_array = [0u8; 32];
        private_key_bytes_array.copy_from_slice(&self.bytes());
        private_key_bytes_array
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_key_r(s: &'static str) -> Result<CJDNSPrivateKey> {
        CJDNSPrivateKey::try_from(s.to_string())
    }

    fn priv_key(s: &'static str) -> CJDNSPrivateKey {
        priv_key_r(s).expect("bad test private key")
    }

    #[test]
    fn test_private_key_from_string() {
        // Valid cases
        assert!(priv_key_r("90a66780a0dc2ca735bc0c161d3e92c876935981e8658c32a846f79947a923bd").is_ok());
        assert!(priv_key_r("378813dfecc62185ffab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03").is_ok());
        assert!(priv_key_r("378813dfecc62185ffAb4d00030b55f50b54e515bfceA8b41f2bd1c2511Bae03").is_ok());

        // Invalid cases
        assert!(priv_key_r("378813HfIcc62185jfab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03").is_err()); // wrong alphabet
        assert!(priv_key_r("378813dfecc62185ffab4d00030b55f50ba8b41f2bd1c2511bae03").is_err()); // wrong len - too small
        assert!(priv_key_r("378813dfecc62185ffAb4d00030b55f50b54e515bfceA8b41f2bd1c2511Bae0").is_err());
        // wrong len - too big
    }

    #[test]
    fn test_to_from_bytes() {
        let priv_key = priv_key("90a66780a0dc2ca735bc0c161d3e92c876935981e8658c32a846f79947a923bd");

        let mut private_key_bytes_array = [0u8; 32];
        private_key_bytes_array.copy_from_slice(&priv_key.bytes());
        assert_eq!(priv_key, CJDNSPrivateKey::from(private_key_bytes_array));
    }
}
