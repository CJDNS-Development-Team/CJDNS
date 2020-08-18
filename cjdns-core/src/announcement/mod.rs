//! Announcement message
//! `Ann` or `ann` are shorthands for `Announcement` and `announcement`.

use std::convert::{TryFrom, TryInto};

use hex;
use sodiumoxide::crypto::hash::sha512;
use sodiumoxide::crypto::sign::ed25519::{verify_detached, PublicKey, Signature};
// use sodiumoxide::crypto::generichash::Digest;

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    DefaultRoutingLabel, EncodingScheme,
};

#[derive(Debug, Clone, Copy)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: Vec<AnnouncementEntities>,

    // Sender keys
    pub node_pub_key: CJDNSPublicKey,
    pub node_ip: CJDNS_IP6,

    // Announcement Meta
    pub binary: Vec<u8>,
    pub binary_hash: String,
}

#[derive(Debug, Clone, Copy)]
pub struct AnnouncementHeader {
    pub signature: String,
    pub pub_signing_key: String,
    pub snode_ip: CJDNS_IP6,
    pub ver: u8,
    pub is_reset: bool,
    pub timestamp: u64, // u32 is until 2038
}

#[derive(Debug, PartialEq)]
pub enum AnnouncementEntities {
    Version(u8),
    EncodingScheme {
        hex: String,
        scheme: EncodingScheme,
    },
    Peer {
        ipv6: CJDNS_IP6,
        label: DefaultRoutingLabel,
        mtu: u32,      // size?
        peer_num: u32, // size?
        unused: u32,
        encoding_form_number: u8, // size?
    },
}

impl Announcement {
    const MIN_SIZE: usize = 120usize;

    /// Parses announcement message `announcement_msg` and creates `Announcement` struct. Always checks message signature.
    pub fn parse(ann_msg: Vec<u8>) -> Result<Self, &str> {
        Self::parse_with_check_opt(ann_msg, true)
    }

    /// Does the same as `Announcement::parse`, but does not check message signature.
    pub fn parse_no_check(ann_msg: Vec<u8>) -> Result<Self, &str> {
        Self::parse_with_check_opt(ann_msg, false)
    }

    /// The reason for API splitting (into `parse` and `parse_no_check`) is that parse with checking is used almost always.
    fn parse_with_check_opt(ann_msg: Vec<u8>, sig_check_flag: bool) -> Result<Self, &str> {
        if ann_msg.len() < Self::MIN_SIZE {
            return Err("Announcement message size is too small");
        }
        let header = AnnouncementHeader::parse_msg(&ann_msg[..AnnouncementHeader::SIZE])?;
        if sig_check_flag {
            Self::check_sig(&header, &ann_msg[header.signature.len()..])?;
        }
        let (node_pub_key, node_ip) = header.get_sender_key();
        let entities = AnnouncementEntities::parse(&ann_msg)?;

        let binary_hash = hex::encode(sha512::hash(&ann_msg));

        Ok(Announcement {
            header,
            entities,
            node_ip,
            node_pub_key,
            binary_hash,
            binary: ann_msg,
        })
    }

    fn check_sig(ann_header: &AnnouncementHeader, ann_msg: &[u8]) -> Result<(), &str> {
        let (sig, pk) = ann_header.get_sodium_compliant_sig_key();
        if verify_detached(&sig, ann_msg, &pk) == true {
            return Ok(());
        }
        Err("failed sig check")
    }
}

impl AnnouncementHeader {
    const SIZE: usize = 120usize;
    const SIG_SIZE: usize = 64usize;
    const SIGN_KEY_SIZE: usize = 32usize;
    const IP_SIZE: usize = 16usize;

    fn parse_msg(ann_msg: &[u8]) -> Result<Self, Box::new(dyn std::error::Error)> {
        let (signature, rest_msg) = ann_msg.split_at(Self::SIG_SIZE);
        let signature = hex::encode(signature);

        let (pub_signing_key, mut rest_msg) = rest_msg.split_at(Self::SIGN_KEY_SIZE);
        let pub_signing_key = hex::encode(pub_signing_key);

        let (snode_ip, mut rest_msg) = rest_msg.split_at_mut(Self::IP_SIZE);
        let snode_ip = CJDNS_IP6::try_from(snode_ip.to_vec())?;

        assert_eq!(rest_msg.len(), 8, "Header size is gt 120 bytes");
        let ver = rest_msg[7] & 7;
        let is_reset = 1 == ((rest_msg[7] >> 3) & 1);
        rest_msg[7] &= 0xf0;
        let mut timestamp = u64::from_be_bytes(rest_msg.try_into().expect("timestamp bytes size is gt 8 bytes"));
        timestamp >>= 4;

        Ok(AnnouncementHeader {
            signature,
            pub_signing_key,
            snode_ip,
            ver,
            is_reset,
            timestamp,
        })
    }

    // should use unsafe ffi func libsodium_sys::crypto_sign_ed25519_pk_to_curve25519
    // an example https://github.com/sunrise-choir/ssb-crypto/blob/c0aea19a417baca6f64b9cb034da319a9a646867/src/sodium/ephemeral.rs#L34
    fn get_sender_keys(&self) -> (CJDNSPublicKey, CJDNS_IP6) {
        // Mocks
        let pk = CJDNSPublicKey::try_from("qgkjd0stfvk9r3j28s4gh8rgslbgx2r5xgxzxkgm5vdxqwn8xsu0.k".to_string()).expect("from crate::keys tests");
        let ip6 = CJDNS_IP6::try_from("fcf5:c1ec:be67:9ad5:1f6c:f31b:5d74:37b0".to_string()).expect("from crate::keys tests");
        (pk, ip6)
    }

    fn get_sodium_compliant_sig_key(&self) -> (Signature, PublicKey) {
        let decoded_sig = hex::decode(&self.signature).expect("hex sig string was build from bytes");
        let sig = Signature(decoded_sig.try_into().expect("sig size is 64")); // may fail init?

        let decoded_key = hex::decode(&self.pub_signing_key).expect("hex key string was build from bytes");
        let key = PublicKey(decoded_key.try_into().expect("key size is 32")); //may fail init

        (sig, key)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn base() {}
}
