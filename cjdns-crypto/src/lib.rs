//! CJDNS Crypto library.
//! Wraps sodiumoxide so that the same version is used everywhere.

pub use sodiumoxide::crypto::hash;
pub use sodiumoxide::crypto::scalarmult;
pub use sodiumoxide::crypto::sign;
pub use sodiumoxide::init;
pub use sodiumoxide::randombytes;

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