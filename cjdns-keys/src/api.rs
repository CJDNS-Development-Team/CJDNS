//! CJDNS API. Used for easy, fast and safe initialization of random key pair.

use std::convert::TryFrom;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Once,
};

use sodiumoxide::init;

use crate::{CJDNSPrivateKey, CJDNSPublicKey, CJDNS_IP6};

// Type that encapsulates library functions making it safer for its users: ensures thread-safety in runtime and meeting keys invariants.
#[derive(Debug, Clone, Copy)]
pub struct CJDNSKeysApi;

/// Convenience type for managing all CJDNS key types in one variable. Fields of the struct are public, so
/// it's possible to create invalid key pair. For safe key pair initialization use `CJDNSKeysApi` struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNSKeys {
    pub private_key: CJDNSPrivateKey,
    pub public_key: CJDNSPublicKey,
    pub ip6: CJDNS_IP6,
}

impl CJDNSKeysApi {
    pub fn new() -> std::result::Result<Self, ()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BytesRepr;

    fn priv_key(s: &'static str) -> CJDNSPrivateKey {
        CJDNSPrivateKey::try_from(s.to_string()).expect("bad test private key")
    }

    fn pub_key(s: &'static str) -> CJDNSPublicKey {
        CJDNSPublicKey::try_from(s.to_string()).expect("bad test public key")
    }

    fn ipv6(s: &'static str) -> CJDNS_IP6 {
        CJDNS_IP6::try_from(s.to_string()).expect("bad test ipv6")
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
}
