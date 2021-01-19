//! CJDNS Crypto library.
//! Wraps sodiumoxide so that the same version is used everywhere.

pub use sodiumoxide::crypto::hash;
pub use sodiumoxide::crypto::scalarmult;
pub use sodiumoxide::crypto::sign;

pub mod sign_ext {
    use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;
    use sodiumoxide::crypto::sign::ed25519;

    pub const SIGN_KEY_SIZE: usize = 32;

    pub fn sign_ed25519_pk_to_curve25519(public_key: ed25519::PublicKey) -> Result<[u8; SIGN_KEY_SIZE], ()> {
        let mut res = [0_u8; SIGN_KEY_SIZE];
        let err_code = unsafe {
            crypto_sign_ed25519_pk_to_curve25519(res.as_mut_ptr(), public_key.0.as_ptr())
        };

        if err_code == 0 {
            Ok(res)
        } else {
            Err(())
        }
    }
}

pub mod random {
    use parking_lot::Once;

    pub trait Random {
        fn random_bytes(&self, dest: &mut [u8]);
    }

    /// Default `Random` implementation which uses sodiumoxide as backend.
    // Use a dummy private field so it cannot be instantiated
    // without call to `new()`
    pub struct DefaultRandom(());

    impl DefaultRandom {
        pub fn new() -> Result<Self, ()> {
            if Self::init_sodiumoxide() {
                Ok(DefaultRandom(()))
            } else {
                Err(())
            }
        }

        fn init_sodiumoxide() -> bool {
            static INIT_SODIUMOXIDE: Once = Once::new();
            static mut INITIALIZED: bool = false;

            INIT_SODIUMOXIDE.call_once(|| {
                let success = sodiumoxide::init().is_ok();
                unsafe {
                    // Safe because of `call_once()` guarantees
                    INITIALIZED = success;
                }
            });

            // Safe because of `call_once()` guarantees
            unsafe { INITIALIZED }
        }
    }

    impl Random for DefaultRandom {
        #[inline(always)]
        fn random_bytes(&self, dest: &mut [u8]) {
            sodiumoxide::randombytes::randombytes_into(dest);
        }
    }
}