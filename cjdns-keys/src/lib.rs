//! CJDNS keys types.

#[macro_use]
extern crate lazy_static;

pub use api::{CJDNSKeys, CJDNSKeysApi};
pub use ip6::CJDNS_IP6;
pub use priv_key::CJDNSPrivateKey;
pub use pub_key::CJDNSPublicKey;

mod api;
mod errors;
mod ip6;
mod priv_key;
mod pub_key;
mod utils;

/// CJDNS private key type
pub type PrivateKey = CJDNSPrivateKey;

/// CJDNS public key type
pub type PublicKey = CJDNSPublicKey;

/// CJDNS IPv6 type
pub type IpV6 = CJDNS_IP6;
