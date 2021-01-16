//! CJDNS private key

use std::convert::TryFrom;
use std::ops::Deref;

use regex::Regex;

use cjdns_crypto::randombytes::randombytes;
use cjdns_crypto::scalarmult;

use crate::{
    errors::{KeyCreationError, Result},
    utils::{debug_fmt, vec_to_array32},
};

lazy_static! {
    static ref PRIVATE_KEY_RE: Regex = Regex::new("^[0-9a-fA-F]{64}$").expect("bad regexp");
}

/// CJDNS private key type
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CJDNSPrivateKey {
    k: [u8; 32],
}

impl CJDNSPrivateKey {
    /// Size in bytes of the private key
    pub const SIZE: usize = 32;
}

impl TryFrom<&str> for CJDNSPrivateKey {
    type Error = KeyCreationError;

    fn try_from(value: &str) -> Result<Self> {
        if PRIVATE_KEY_RE.is_match(value) {
            let bytes = hex::decode(value).expect("invalid hex string");
            return Ok(CJDNSPrivateKey { k: vec_to_array32(bytes) });
        }
        Err(KeyCreationError::BadString)
    }
}

impl From<[u8; 32]> for CJDNSPrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        CJDNSPrivateKey { k: bytes }
    }
}

impl Deref for CJDNSPrivateKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.k
    }
}

impl std::fmt::Debug for CJDNSPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        debug_fmt(self.k, f)
    }
}

impl CJDNSPrivateKey {
    pub fn new_random() -> Self {
        let bytes = randombytes(32);
        CJDNSPrivateKey { k: vec_to_array32(bytes) }
    }

    pub fn to_scalar(&self) -> scalarmult::Scalar {
        scalarmult::Scalar(self.k)
    }

    pub fn is_zero(&self) -> bool {
        self.k == [0; 32]
    }

    pub fn raw(&self) -> &[u8; Self::SIZE] {
        &self.k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_key_r(s: &'static str) -> Result<CJDNSPrivateKey> {
        CJDNSPrivateKey::try_from(s)
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
        // wrong len - too small
    }

    #[test]
    fn test_to_from_bytes() {
        let priv_key = priv_key("90a66780a0dc2ca735bc0c161d3e92c876935981e8658c32a846f79947a923bd");
        let priv_key_bytes = priv_key.k;
        assert_eq!(&(*priv_key), &priv_key_bytes);
        assert_eq!(CJDNSPrivateKey::from(priv_key_bytes), priv_key);
    }

    #[test]
    fn test_zero_priv_key() {
        let zeroes = [0_u8; 32];
        let zero = CJDNSPrivateKey::from(zeroes);
        assert!(zero.is_zero());
        assert!(!priv_key("90a66780a0dc2ca735bc0c161d3e92c876935981e8658c32a846f79947a923bd").is_zero());
    }
}
