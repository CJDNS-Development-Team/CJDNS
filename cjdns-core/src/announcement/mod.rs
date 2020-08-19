//! Announcement message
//! `Ann` or `ann` are shorthands for `Announcement` and `announcement`.

use std::convert::TryFrom;

use hex;
use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;
use sodiumoxide::crypto::hash::sha512::{self, Digest};
use sodiumoxide::crypto::sign::ed25519::{verify_detached, PublicKey, Signature};

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    DefaultRoutingLabel, EncodingScheme,
};

#[derive(Debug, Clone)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: AnnouncementEntities,

    // Sender keys
    pub node_pub_key: CJDNSPublicKey,
    pub node_ip: CJDNS_IP6,

    // Announcement Meta
    pub binary: Vec<u8>,
    pub binary_hash: Digest,
}

#[derive(Debug, Clone)]
pub struct AnnouncementHeader {
    pub signature: String,
    pub pub_signing_key: String,
    pub snode_ip: CJDNS_IP6,
    pub ver: u8,
    pub is_reset: bool,
    pub timestamp: u64, // u32 is until 2038
}

#[derive(Debug, Clone)]
pub struct AnnouncementEntities(Vec<Entities>);

#[derive(Debug, Clone, PartialEq)]
pub enum Entities {
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
    pub fn parse(ann_msg: Vec<u8>) -> Result<Self, &'static str> {
        Self::parse_with_check_opt(ann_msg, true)
    }

    /// Does the same as `Announcement::parse`, but does not check message signature.
    pub fn parse_no_check(ann_msg: Vec<u8>) -> Result<Self, &'static str> {
        Self::parse_with_check_opt(ann_msg, false)
    }

    /// The reason for API splitting (into `parse` and `parse_no_check`) is that parse with checking is used almost always.
    fn parse_with_check_opt(ann_msg: Vec<u8>, sig_check_flag: bool) -> Result<Self, &'static str> {
        if ann_msg.len() < Self::MIN_SIZE {
            return Err("Announcement message size is too small");
        }
        let header = AnnouncementHeader::parse_ann(&ann_msg[..AnnouncementHeader::SIZE]).or(Err("TODO"))?;
        if sig_check_flag {
            Self::check_sig(&header, &ann_msg[AnnouncementHeader::SIG_SIZE..])?;
        }
        let (node_pub_key, node_ip) = header.get_sender_keys().or(Err("todo"))?;
        let entities = AnnouncementEntities::parse_ann(&ann_msg);

        let binary_hash = sha512::hash(&ann_msg);

        Ok(Announcement {
            header,
            entities,
            node_ip,
            node_pub_key,
            binary_hash,
            binary: ann_msg,
        })
    }

    fn check_sig(ann_header: &AnnouncementHeader, ann_msg: &[u8]) -> Result<(), &'static str> {
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

    fn parse_ann(ann_msg: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let (signature, rest_msg) = ann_msg.split_at(Self::SIG_SIZE);
        let signature = hex::encode(signature);

        let (pub_signing_key, rest_msg) = rest_msg.split_at(Self::SIGN_KEY_SIZE);
        let pub_signing_key = hex::encode(pub_signing_key);

        let (snode_ip, rest_msg) = rest_msg.split_at(Self::IP_SIZE);
        let snode_ip = CJDNS_IP6::try_from(snode_ip.to_vec())?;

        assert_eq!(rest_msg.len(), 8, "Header size is gt 120 bytes");
        let ver = rest_msg[7] & 7;
        let is_reset = 1 == ((rest_msg[7] >> 3) & 1);

        let mut timestamp_bytes_array = [0u8; 8];
        timestamp_bytes_array.clone_from_slice(rest_msg);
        timestamp_bytes_array[7] &= 0xf0;
        let mut timestamp = u64::from_be_bytes(timestamp_bytes_array);
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
    fn get_sender_keys(&self) -> Result<(CJDNSPublicKey, CJDNS_IP6), &'static str> {
        let mut curve25519_key_bytes = [0u8; 32];
        let (_, pk) = self.get_sodium_compliant_sig_key();
        let ok = unsafe { crypto_sign_ed25519_pk_to_curve25519(curve25519_key_bytes.as_mut_ptr(), pk.0.as_ptr()) == 0 };
        if !ok {
            return Err("todo");
        }
        let sender_node_pub_key = CJDNSPublicKey::from(curve25519_key_bytes);
        let sender_node_ip = CJDNS_IP6::try_from(&sender_node_pub_key).or(Err("todo"))?;
        Ok((sender_node_pub_key, sender_node_ip))
    }

    fn get_sodium_compliant_sig_key(&self) -> (Signature, PublicKey) {
        let mut sig_bytes_array = [0u8; Self::SIG_SIZE];
        let decoded_sig = hex::decode(&self.signature).expect("hex sig string was build from bytes");
        sig_bytes_array.copy_from_slice(&decoded_sig);

        let mut key_bytes_array = [0u8; Self::SIGN_KEY_SIZE];
        let decoded_key = hex::decode(&self.pub_signing_key).expect("hex key string was build from bytes");
        key_bytes_array.copy_from_slice(&decoded_key);

        (Signature(sig_bytes_array), PublicKey(key_bytes_array))
    }
}

impl AnnouncementEntities {
    fn parse_ann(_ann_msg: &[u8]) -> Self {
        // Mock
        AnnouncementEntities(vec![Entities::Version(10)])
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn announcement_base() {
        let hexed_header = String::from("3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2fc928136dc1fe6e04ef6a6dd7187b85f00001576462f6f69");
        let hexed_version_entity = String::from("04020012");
        let hexed_pad = String::from("01");
        let hexed_enc_entity = String::from("07006114458100");
        let hexed_peer_entity = String::from("200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015");
        let test_data = format!("{}{}{}{}{}", hexed_header, hexed_version_entity, hexed_pad, hexed_enc_entity, hexed_peer_entity);
        let byte_header = hex::decode(test_data).expect("test bytes from https://github.com/cjdelisle/cjdnsann/blob/master/test.js#L30"); //expect
        let res = Announcement::parse(byte_header);
        assert!(res.is_ok())
    }
}
