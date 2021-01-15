//! CJDNS API. Used for easy, fast and safe creation of random key pair.

use std::convert::TryFrom;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Once,
};

use sodiumoxide::init;

use crate::{CJDNSPrivateKey, CJDNSPublicKey, CJDNS_IP6};

/// Type that encapsulates some crate functions making it safer for its users to work with randomly created keys.
///
/// The struct initialization ensures thread-safety in runtime. If you don't need to work with randomly created keys, you can use appropriate key types directly.
#[derive(Debug, Clone, Copy)]
pub struct CJDNSKeysApi;

/// Convenience type for managing all CJDNS key types in one variable.
///
/// Fields of the struct are public, so it's possible to create invalid key pair. For example: there is a contract between ip6 and public key, which requires successful initialization of ip6 from public key.
/// `CJDNSKeys` doesn't control the contract, so it's possible to have valid keys on their own, but invalid in "pair". So if you wrap your keys with `CJDNSKeys`,
/// make sure that the contract requirements are met. For safe random keys initialization use `CJDNSKeysApi` struct methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CJDNSKeys {
    /// CJDNS private key.
    pub private_key: CJDNSPrivateKey,

    /// CJDNS public key
    pub public_key: CJDNSPublicKey,

    /// CJDNS ip6
    pub ip6: CJDNS_IP6,
}

impl CJDNSKeysApi {
    /// Initialization function, which guarantees on success that it will be safe to call methods, which use "randomize" logic (i.e. `key_pair`, `gen_private_key`).
    ///
    /// If you want to work with randomly created cjdns keys, it's recommended to first initialize `CJDNSKeysApi`.
    /// For example:
    /// ```rust
    /// use cjdns_keys::CJDNSKeysApi;
    ///
    /// let keys_api = CJDNSKeysApi::new().expect("thread-safe initialization failed");
    /// // valid random key pair
    /// let keys = keys_api.key_pair();
    /// ```
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

    /// Convenience method that generates safely valid key "pair". Returns `CJDNSKeys` struct with corresponding keys as its fields.
    ///
    /// `CJDNSKeys` doc states presence of a contract between ip6 and public key. The contract is met within the method.
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

    /// Safely generates private key.
    ///
    /// Considered safe, because the method takes immutable reference of the successfully initialized api type instance.
    pub fn gen_private_key(&self) -> CJDNSPrivateKey {
        CJDNSPrivateKey::new_random()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn priv_key(s: &'static str) -> CJDNSPrivateKey {
        CJDNSPrivateKey::try_from(s).expect("bad test private key")
    }

    fn pub_key(s: &'static str) -> CJDNSPublicKey {
        CJDNSPublicKey::try_from(s).expect("bad test public key")
    }

    fn ipv6(s: &'static str) -> CJDNS_IP6 {
        CJDNS_IP6::try_from(s).expect("bad test ipv6")
    }

    #[test]
    fn test_base() {
        let key_pair = CJDNSKeys {
            private_key: priv_key("378813dfecc62185ffab4d00030b55f50b54e515bfcea8b41f2bd1c2511bae03"),
            public_key: pub_key("qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k"),
            ip6: ipv6("fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0"),
        };

        let pub_key_bytes = &*key_pair.public_key;
        let mut pub_key_bytes_array = [0u8; 32];
        pub_key_bytes_array.copy_from_slice(&pub_key_bytes);
        assert_eq!(CJDNSPublicKey::from(pub_key_bytes_array), key_pair.public_key);

        assert_eq!(CJDNS_IP6::try_from(&*key_pair.ip6).expect("broken bytes()"), key_pair.ip6);
    }
}
