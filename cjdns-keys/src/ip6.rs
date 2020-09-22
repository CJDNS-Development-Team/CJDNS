//! CJDNS IP6

use std::convert::TryFrom;

use regex::Regex;
use sodiumoxide::crypto::hash::sha512::hash;

use crate::{
    errors::{KeyError, Result},
    BytesRepr, CJDNSPublicKey,
};

lazy_static! {
    static ref IP6_RE: Regex = Regex::new("^fc[0-9a-f]{2}:(?:[0-9a-f]{4}:){6}[0-9a-f]{4}$").expect("bad regexp");
}

/// CJDNS IP6 type
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNS_IP6 {
    k: String,
}

impl TryFrom<&CJDNSPublicKey> for CJDNS_IP6 {
    type Error = KeyError;

    fn try_from(value: &CJDNSPublicKey) -> Result<Self> {
        let pub_key_double_hash = hash(&hash(&value.bytes()).0);
        let ip6_candidate = Self::try_from(pub_key_double_hash.0.to_vec());
        if ip6_candidate.is_ok() {
            return ip6_candidate;
        }
        Err(KeyError::CannotCreateFromPublicKey)
    }
}

impl TryFrom<Vec<u8>> for CJDNS_IP6 {
    type Error = KeyError;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
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

        Err(KeyError::CannotCreateFromBytes)
    }
}

impl TryFrom<String> for CJDNS_IP6 {
    type Error = KeyError;

    fn try_from(value: String) -> Result<Self> {
        if IP6_RE.is_match(&value) {
            return Ok(CJDNS_IP6 { k: value });
        }
        Err(KeyError::CannotCreateFromString)
    }
}

impl std::fmt::Display for CJDNS_IP6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.k)
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

    fn ipv6_r(s: &'static str) -> Result<CJDNS_IP6> {
        CJDNS_IP6::try_from(s.to_string())
    }

    fn ipv6(s: &'static str) -> CJDNS_IP6 {
        ipv6_r(s).expect("bad test ipv6")
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
    fn to_from_bytes_ip6() {
        let ip6 = ipv6("fc32:6a5d:e235:7057:e990:6398:5d7a:aa58");
        let ip6_bytes = ip6.bytes();
        assert_eq!(ip6_bytes.len(), 16);
        assert_eq!(Ok(ip6), CJDNS_IP6::try_from(ip6_bytes));

        // notice, that such key creation is impossible for library users
        let invalid_ip6_bytes = vec![
            CJDNS_IP6 {
                k: "e4c5:3a4a:a8f2:9325:b94a:74c3:26fd:40de".to_string(),
            }
            .bytes(),
            CJDNS_IP6 {
                k: "7e41:3a71:c767:573f:6127:7956:b69a:b700".to_string(),
            }
            .bytes(),
        ];

        for i in invalid_ip6_bytes {
            assert!(CJDNS_IP6::try_from(i).is_err())
        }
    }
}
