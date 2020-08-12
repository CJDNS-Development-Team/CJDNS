//! Public and private key types.

#[macro_use]
extern crate lazy_static;

use std::convert::TryFrom;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Once,
};

use regex::Regex;
use sodiumoxide::crypto::hash::sha512::hash;
use sodiumoxide::crypto::scalarmult;
use sodiumoxide::init;
use sodiumoxide::randombytes::randombytes;

use base_32::{base32_decode, base32_encode, BASE32_ENCODED_STRING_LEN};
use cjdns_entities::RoutingLabel;
use errors::Error;

mod base_32;
mod errors;

lazy_static! {
    static ref IP6_RE: Regex = Regex::new("^fc[0-9a-f]{2}:(?:[0-9a-f]{4}:){6}[0-9a-f]{4}$").expect("bad regexp");
    static ref PRIVATE_KEY_RE: Regex = Regex::new("^[0-9a-fA-F]{64}$").expect("bad regexp");
    static ref PUBLIC_KEY_RE: Regex = Regex::new(r"[a-z0-9]{52}\.k").expect("bad regexp");
    static ref NODE_NAME_RE: Regex = Regex::new(
        "^v([0-9]+)\\.\
        ([[:xdigit:]]{4}\\.[[:xdigit:]]{4}\\.[[:xdigit:]]{4}\\.[[:xdigit:]]{4})\\.\
        ([a-z0-9]{52}\\.k)"
    ).expect("bad regexp");
}

/// Vec<u8> representation for type instance. Implemented for `CJDNSPrivateKey`, `CJDNSPublicKey`, `CJDNS_IP6`.
pub trait BytesRepr {
    fn bytes(&self) -> Vec<u8>;
}

// Type that encapsulates library functions making it safer its users: ensures thread-safety in runtime
#[derive(Debug, Clone, Copy)]
pub struct CJDNSKeysApi;

/// CJDNS public key type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNSPublicKey {
    k: String,
}

/// CJDNS private key type
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNSPrivateKey {
    k: String,
}

/// CJDNS IP6 type
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNS_IP6 {
    k: String,
}

/// Convenience type for managing all CJDNS key types in one variable. Allows simple keys generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNSKeys {
    pub private_key: CJDNSPrivateKey,
    pub public_key: CJDNSPublicKey,
    pub ip6: CJDNS_IP6,
}

impl CJDNSKeysApi {
    pub fn new() -> Result<Self, ()> {
        if Self::init_sodiumoxide() {
            return Ok(Self);
        }
        Err(())
    }

    /// for thread safety: https://docs.rs/sodiumoxide/0.2.5/sodiumoxide/randombytes/fn.randombytes.html
    fn init_sodiumoxide() -> bool {
        static INIT_SODIUMOXIDE: Once = Once::new();
        static INITIALIZED: AtomicBool = AtomicBool::new(false);

        INIT_SODIUMOXIDE.call_once(|| {
            // if any thread reached `store`, which will be executed thread safely and only once, it does not need any strict order for this op.
            INITIALIZED.store(init().is_ok(), Ordering::Relaxed);
        });

        // `Ordering::Relaxed` is used because there can't be any `stores` after it.
        // Explanation: `store` happens in `Once` closure, so no `store` ops will be executed after it.
        INITIALIZED.load(Ordering::Relaxed)
    }

    /// Convenience function that generates valid private, public keys and ip6. Returns `CJDNSKeys` struct with corresponding keys as its fields.
    pub fn key_pair(&self) -> CJDNSKeys {
        loop {
            let private_key = self.gen_private_key();
            let public_key = CJDNSPublicKey::from(&private_key);
            let ip6_candidate = CJDNS_IP6::try_from(&public_key);

            if let Ok(ip6) = ip6_candidate {
                return CJDNSKeys { private_key, public_key, ip6 };
            }
        }
    }

    pub fn gen_private_key(&self) -> CJDNSPrivateKey {
        CJDNSPrivateKey::new()
    }

    /// Gets version, label and public key all together in tuple from `name` argument, if it has valid structure. Otherwise returns error.
    pub fn parse_node_name(name: String) -> Result<(u32, RoutingLabel<u64>, CJDNSPublicKey), Error> {
        if let Some(c) = NODE_NAME_RE.captures(&name) {
            let str_from_captured_group = |group_num: usize| -> &str { c.get(group_num).expect("bad group index").as_str() };
            let version = str_from_captured_group(1).parse::<u32>().expect("bad regexp - version");
            let label = RoutingLabel::try_from(str_from_captured_group(2)).expect("bad regexp - label");
            let public_key = CJDNSPublicKey::try_from(str_from_captured_group(3).to_string())?;
            Ok((version, label, public_key))
        } else {
            Err(Error::CannotParseNodeName)
        }
    }
}

impl TryFrom<String> for CJDNSPrivateKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if PRIVATE_KEY_RE.is_match(&value) {
            return Ok(CJDNSPrivateKey { k: value });
        }
        Err(Error::CannotCreateFromString)
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
    fn new() -> Self {
        let random_bytes_for_key = randombytes(32);
        CJDNSPrivateKey {
            k: hex::encode(random_bytes_for_key),
        }
    }

    fn to_scalar(&self) -> scalarmult::Scalar {
        scalarmult::Scalar(self.bytes_32())
    }

    fn bytes_32(&self) -> [u8; 32] {
        let mut private_key_bytes_array = [0u8; 32];
        private_key_bytes_array.copy_from_slice(&self.bytes());
        private_key_bytes_array
    }
}

impl TryFrom<String> for CJDNSPublicKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if PUBLIC_KEY_RE.is_match(&value) && base32_decode(&value[..BASE32_ENCODED_STRING_LEN]).is_ok() {
            return Ok(CJDNSPublicKey { k: value });
        }
        Err(Error::CannotCreateFromString)
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
        let pub_key = base32_encode(bytes) + ".k";
        CJDNSPublicKey { k: pub_key }
    }
}

impl BytesRepr for CJDNSPublicKey {
    fn bytes(&self) -> Vec<u8> {
        base32_decode(&self.k[..BASE32_ENCODED_STRING_LEN]).expect("broken invariant")
    }
}

impl TryFrom<&CJDNSPublicKey> for CJDNS_IP6 {
    type Error = Error;

    fn try_from(value: &CJDNSPublicKey) -> Result<Self, Self::Error> {
        let pub_key_double_hash = hash(&hash(&value.bytes()).0);
        let ip6_candidate = Self::try_from(pub_key_double_hash.0.to_vec());
        if ip6_candidate.is_ok() {
            return ip6_candidate;
        }
        Err(Error::CannotCreateFromPublicKey)
    }
}

impl TryFrom<Vec<u8>> for CJDNS_IP6 {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let mut ip6_template = hex::encode(bytes)[..32].to_string();
        ip6_template = ip6_template
            .chars()
            .collect::<Vec<char>>()
            .chunks(4)
            .map(|x| x.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(":");

        if IP6_RE.is_match(&ip6_template) {
            return Ok(CJDNS_IP6 { k: ip6_template });
        }

        Err(Error::CannotCreateFromBytes)
    }
}

impl TryFrom<String> for CJDNS_IP6 {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if IP6_RE.is_match(&value) {
            return Ok(CJDNS_IP6 { k: value });
        }
        Err(Error::CannotCreateFromString)
    }
}

impl BytesRepr for CJDNS_IP6 {
    fn bytes(&self) -> Vec<u8> {
        let ip6_joined = self.k.split(":").collect::<String>();
        hex::decode(ip6_joined).expect("broken invariant")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_key_r(s: &'static str) -> Result<CJDNSPrivateKey, Error> {
        CJDNSPrivateKey::try_from(s.to_string())
    }

    fn pub_key_r(s: &'static str) -> Result<CJDNSPublicKey, Error> {
        CJDNSPublicKey::try_from(s.to_string())
    }

    fn ipv6_r(s: &'static str) -> Result<CJDNS_IP6, Error> {
        CJDNS_IP6::try_from(s.to_string())
    }

    fn priv_key(s: &'static str) -> CJDNSPrivateKey {
        priv_key_r(s).expect("bad test private key")
    }

    fn pub_key(s: &'static str) -> CJDNSPublicKey {
        pub_key_r(s).expect("bad test public key")
    }

    fn ipv6(s: &'static str) -> CJDNS_IP6 {
        ipv6_r(s).expect("bad test ipv6")
    }

    #[test]
    fn test_base() {
        let key_pair = CJDNSKeys {
            private_key: priv_key("378813dfecc62185ffab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03"),
            public_key: pub_key("qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k"),
            ip6: ipv6("fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0"),
        };

        let pub_key_bytes = key_pair.public_key.bytes();
        let mut pub_key_bytes_array = [0u8; 32];
        pub_key_bytes_array.copy_from_slice(&pub_key_bytes);
        assert_eq!(CJDNSPublicKey::from(pub_key_bytes_array), key_pair.public_key);

        let ip6_bytes = key_pair.ip6.bytes();
        assert_eq!(CJDNS_IP6::try_from(ip6_bytes).expect("broken bytes()"), key_pair.ip6);
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
        assert!(priv_key_r("378813dfecc62185ffAb4d00030b55f50b54e515bfceA8b41f2bd1c2511Bae0").is_err()); // wrong len - too big
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
            pub_key_r("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy8.k.k"),
        ];
        for err_res in invalid_pub_keys {
            assert!(err_res.is_err())
        }
    }

    #[test]
    fn test_ip6_from_string() {
        // Valid cases
        assert!(ipv6_r("fc32:6a5d:e235:7057:e990:6398:5d7a:aa58").is_ok());

        // Invalid cases
        let invalid_ips = vec![
            // wrong len
            ipv6_r("fc32:6a5d7057:e990:6398:5d7a:aa58"),
            // wrong format
            ipv6_r("fc32:6a5de:235:7057:e990:6398:5d7a:aa58"),
            ipv6_r("fc326a5de2357057e99063985d7aaa58"),
            ipv6_r("ac32:6a5d:e235:7057:e990:6398:5d7a:aa58"),
            ipv6_r("FC32:6a5d:e235:7057:e990:6398:5D7a:Aa58"),
            ipv6_r("6a5d:fc32:e235:e990:7057:6398:5d7a:aa58"),
        ];
        for err_res in invalid_ips {
            assert!(err_res.is_err());
        }
    }

    #[test]
    fn test_to_from_bytes_keys() {
        let priv_key = priv_key("90a66780a0dc2ca735bc0c161d3e92c876935981e8658c32a846f79947a923bd");

        let mut private_key_bytes_array = [0u8; 32];
        private_key_bytes_array.copy_from_slice(&priv_key.bytes());
        assert_eq!(priv_key, CJDNSPrivateKey::from(private_key_bytes_array));

        let pub_key = pub_key("xpr2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k");

        let mut public_key_bytes_array = [0u8; 32];
        public_key_bytes_array.copy_from_slice(&pub_key.bytes());
        assert_eq!(pub_key, CJDNSPublicKey::from(public_key_bytes_array));
    }

    #[test]
    fn to_from_bytes_ip6() {
        let ip6 = ipv6("fc32:6a5d:e235:7057:e990:6398:5d7a:aa58");
        let ip6_bytes = ip6.bytes();
        assert_eq!(ip6_bytes.len(), 16);
        assert_eq!(Ok(ip6), CJDNS_IP6::try_from(ip6_bytes));

        // `notice`, that such key creation is impossible for library users
        let invalid_ip6_bytes = vec![
            CJDNS_IP6 {
                k: "e4c5:3a4a:a8f2:9325:b94a:74c3:26fd:40de".to_string(),
            }.bytes(),
            CJDNS_IP6 {
                k: "7e41:3a71:c767:573f:6127:7956:b69a:b700".to_string(),
            }.bytes(),
        ];

        for i in invalid_ip6_bytes {
            assert!(CJDNS_IP6::try_from(i).is_err())
        }
    }

    #[test]
    fn test_parse_node_name() {
        let valid_node_names = vec![
            "v19.0000.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
            "v10.0a20.00ff.00e0.9901.qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k",
        ];
        for valid_node_name in valid_node_names {
            let valid_node_name = valid_node_name.to_string();
            assert!(CJDNSKeysApi::parse_node_name(valid_node_name).is_ok());
        }

        let invalid_node_names = vec![
            "12foo",
            "",
            "19.0000.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
            "v1234123123.0000.00000.000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
            "v19.0000.0000.0000.0863.2v6dt6f841hZhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
            "v19.0ffe.1200.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtpy50.k",
            "v19.gh00.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",
            "v10.0000.0000.0000.0001.aer2z2s3hnr0qzpk2u121uqjv15dc335v54pccqlqj6c5p840yy0.k",
            "v10.0a20.00ff.00e0.9901.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.k)",
        ];
        for invalid_node_name in invalid_node_names {
            let invalid_node_name = invalid_node_name.to_string();
            assert!(CJDNSKeysApi::parse_node_name(invalid_node_name).is_err());
        }
    }
}