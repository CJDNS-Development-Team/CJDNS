//! CJDNS public key

use std::convert::TryFrom;
use std::ops::Deref;

use data_encoding::BASE32_DNSCURVE;
use regex::Regex;

use cjdns_crypto::scalarmult;

use crate::{
    CJDNSPrivateKey,
    errors::{KeyCreationError, Result},
    utils::{debug_fmt, vec_to_array32},
};

lazy_static! {
    static ref PUBLIC_KEY_RE: Regex = Regex::new(r"[a-z0-9]{52}\.k").expect("bad regexp");
}

// Pub key len is 54, where last two characters are `.k`. So first 52 are the encoded ones.
const BASE32_ENCODED_STRING_LEN: usize = 52;

/// CJDNS public key type
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CJDNSPublicKey {
    k: [u8; 32],
}

impl CJDNSPublicKey {
    /// Size in bytes of the public key
    pub const SIZE: usize = 32;
}

impl TryFrom<&str> for CJDNSPublicKey {
    type Error = KeyCreationError;

    fn try_from(value: &str) -> Result<Self> {
        if PUBLIC_KEY_RE.is_match(value) {
            let bytes = BASE32_DNSCURVE
                .decode(value[..BASE32_ENCODED_STRING_LEN].as_bytes())
                .or(Err(KeyCreationError::NotDecodableString))?;
            return Ok(CJDNSPublicKey { k: vec_to_array32(bytes) });
        }
        Err(KeyCreationError::BadString)
    }
}

impl From<&CJDNSPrivateKey> for CJDNSPublicKey {
    fn from(value: &CJDNSPrivateKey) -> Self {
        let pub_key_bytes = scalarmult::scalarmult_base(&value.to_scalar()).0;
        CJDNSPublicKey::from(pub_key_bytes)
    }
}

impl From<[u8; 32]> for CJDNSPublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        CJDNSPublicKey { k: bytes }
    }
}

impl Deref for CJDNSPublicKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.k
    }
}

impl std::fmt::Display for CJDNSPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", BASE32_DNSCURVE.encode(&self.k) + ".k")
    }
}

impl std::fmt::Debug for CJDNSPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        debug_fmt(self.k, f)
    }
}

impl CJDNSPublicKey {
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

    fn pub_key_r(s: &'static str) -> Result<CJDNSPublicKey> {
        CJDNSPublicKey::try_from(s)
    }

    fn pub_key(s: &'static str) -> CJDNSPublicKey {
        pub_key_r(s).expect("bad test public key")
    }

    #[test]
    fn test_public_key_from_string() {
        // Valid cases
        assert!(pub_key_r("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k").is_ok());

        // Invalid cases
        let invalid_pub_keys = vec![
            // wrong len
            pub_key_r("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0"),
            pub_key_r("xpr2z2s3hnr0qzpkc5p840yy0.k"),
            // wrong alphabet
            pub_key_r("XPR2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k"),
            pub_key_r("aer2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k"),
            // can not be decoded
            pub_key_r("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.k"),
            // can not be decoded, takes lots of bytes - last char = 8
            pub_key_r("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy8.k"),
        ];
        for err_res in invalid_pub_keys {
            assert!(err_res.is_err())
        }
    }

    #[test]
    fn test_to_from_bytes() {
        let pub_key = pub_key("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k");
        let pub_key_bytes = pub_key.k;
        assert_eq!(&*pub_key, &pub_key_bytes);
        assert_eq!(CJDNSPublicKey::from(pub_key_bytes), pub_key);
        assert_eq!(pub_key.to_string(), "xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k".to_string());
    }

    #[test]
    fn test_zero_pub_key() {
        let zeroes = [0_u8; 32];
        let zero = CJDNSPublicKey::from(zeroes);
        assert!(zero.is_zero());
        assert!(!pub_key("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k").is_zero());
    }
}
