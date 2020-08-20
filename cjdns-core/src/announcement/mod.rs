//! Announcement message
//! `Ann` or `ann` are shorthands for `Announcement` and `announcement`.

use std::convert::TryFrom;

use hex;
use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;
use sodiumoxide::crypto::hash::sha512::{self, Digest};
use sodiumoxide::crypto::sign::ed25519::{verify_detached, PublicKey, Signature};

use crate::{deserialize_forms, keys::{CJDNSPublicKey, CJDNS_IP6}, DefaultRoutingLabel, EncodingSchemeForm};
use crate::Entities::Peer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: AnnouncementEntities,
    pub node_pub_key: CJDNSPublicKey,
    pub node_ip: CJDNS_IP6,
    pub binary: Vec<u8>,
    pub binary_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementHeader {
    pub signature: String,
    pub pub_signing_key: String,
    pub snode_ip: CJDNS_IP6,
    pub ver: u8,
    pub is_reset: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementEntities(Vec<Entities>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entities {
    Version(u16),
    EncodingScheme {
        hex: String,
        scheme: Vec<EncodingSchemeForm>,
    },
    Peer {
        ipv6: CJDNS_IP6,
        label: DefaultRoutingLabel,
        mtu: u32,      // size?
        peer_num: u32, // size?
        unused: u32,
        encoding_form_number: u8,
        flags: u8
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

    /// The reason for API splitting into `parse` and `parse_no_check` is that parse with checking is used almost always.
    fn parse_with_check_opt(ann_msg: Vec<u8>, sig_check_flag: bool) -> Result<Self, &'static str> {
        if ann_msg.len() < Self::MIN_SIZE {
            return Err("Announcement message size is too small");
        }
        let header = AnnouncementHeader::parse_ann(&ann_msg[..AnnouncementHeader::SIZE]).or(Err("TODO"))?;
        if sig_check_flag {
            Self::check_sig(&header, &ann_msg[AnnouncementHeader::SIG_SIZE..])?;
        }
        let (node_pub_key, node_ip) = header.get_sender_keys().or(Err("todo"))?;
        let entities = AnnouncementEntities::parse_ann(&ann_msg[AnnouncementHeader::SIZE..])?;

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

impl Entities {
    const VERSION_TYPE: u8 = 2u8;
    const ENCODING_SCHEME_TYPE: u8 = 0u8;
    const PEER_TYPE: u8 = 1u8;
}

impl AnnouncementEntities {
    // very dirty impl
    fn parse_ann(ann_msg: &[u8]) -> Result<Self, &'static str> {
        let mut out_vec = vec![];
        let mut ann_msg_idx = 0usize;
        while ann_msg_idx < ann_msg.len() {
            if ann_msg[ann_msg_idx] == 0 { return Err("0 length entity in message"); }
            if ann_msg[ann_msg_idx] == 1 { ann_msg_idx += 1; continue; }
            // consider match
            if ann_msg[ann_msg_idx + 1] == Entities::VERSION_TYPE {
                out_vec.push(AnnouncementEntities::parse_version(&ann_msg[ann_msg_idx..ann_msg_idx+(ann_msg[ann_msg_idx]as usize)]));
                ann_msg_idx += ann_msg[ann_msg_idx] as usize;
            } else if ann_msg[ann_msg_idx + 1] == Entities::ENCODING_SCHEME_TYPE {
                out_vec.push(AnnouncementEntities::parse_enc_scheme(&ann_msg[ann_msg_idx..ann_msg_idx+(ann_msg[ann_msg_idx]as usize)]));
                ann_msg_idx += ann_msg[ann_msg_idx] as usize;
            } else if ann_msg[ann_msg_idx + 1] == Entities::PEER_TYPE {
                out_vec.push(AnnouncementEntities::parse_peer(&ann_msg[ann_msg_idx..ann_msg_idx+(ann_msg[ann_msg_idx]as usize)]));
                ann_msg_idx += ann_msg[ann_msg_idx] as usize;
            } else {
                // unrecognized staff
                ann_msg_idx += ann_msg[ann_msg_idx] as usize;
            }
        }
        if ann_msg_idx != ann_msg.len() { return Err("garbage after the last announcement entity"); }
        Ok(AnnouncementEntities(out_vec))
    }

    fn parse_version(version_bytes: &[u8]) -> Entities {
        let x = 0;
        let _len = version_bytes[x];
        let _entity_type = version_bytes[x+1];
        // check len/entity
        assert_eq!((&version_bytes[x+2..]).len(), 2);
        let mut version_bytes_array = [0u8; 2];
        version_bytes_array.copy_from_slice(&version_bytes[x+2..]);
        let version = u16::from_be_bytes(version_bytes_array);
        Entities::Version(version)
    }

    // dirty as...
    fn parse_enc_scheme(enc_scheme_bytes: &[u8]) -> Entities {
        let x = 0;
        let len = enc_scheme_bytes[x];
        let scheme_slice = &enc_scheme_bytes[x+2..len as usize];
        let hex = hex::encode(scheme_slice);
        let scheme = deserialize_forms(&scheme_slice.to_vec()).expect("TODO");
        Entities::EncodingScheme { hex, scheme }
    }

    fn parse_peer(peer_bytes: &[u8]) -> Entities {
        let mut x = 0;
        let _peer_len_data = peer_bytes[x];
        x+=1;
        let _peer_type = peer_bytes[x];
        x+=1;
        let encoding_form_number = peer_bytes[x];
        x+=1;
        let flags = peer_bytes[x];
        x+=1;

        let mtu8 = {
            let mtu_bytes_slice = &peer_bytes[x..x+2];
            let mut mtu_bytes_array = [0u8; 2];
            mtu_bytes_array.copy_from_slice(mtu_bytes_slice);
            u16::from_be_bytes(mtu_bytes_array)
        };
        x+=2;

        let peer_num = {
            let peer_num_bytes_slice = &peer_bytes[x..x+2];
            let mut peer_num_bytes_array = [0u8; 2];
            peer_num_bytes_array.copy_from_slice(peer_num_bytes_slice);
            u16::from_be_bytes(peer_num_bytes_array)
        };
        x+=2;

        let unused = {
            let unused_bytes_slice = &peer_bytes[x..x+4];
            let mut unused_bytes_array = [0u8; 4];
            unused_bytes_array.copy_from_slice(unused_bytes_slice);
            u32::from_be_bytes(unused_bytes_array)
        };
        x+=4;

        let ipv6bytes = &peer_bytes[x..x+16];
        x+=16;
        let label_bytes = &peer_bytes[x..x+4];
        x+=4;

        let mtu = (mtu8 * 8) as u32;
        let ipv6 = CJDNS_IP6::try_from(ipv6bytes.to_vec()).expect("TODO");
        let label_string = {
            let a = label_bytes
                .chunks(2)
                .map(|x| hex::encode(x))
                .collect::<Vec<String>>()
                .join(".");
            format!("{}{}", "0000.0000.", a)
        };
        let label = DefaultRoutingLabel::try_from(label_string.as_str()).expect("TODO");
        Peer {
            ipv6,
            label,
            mtu,
            peer_num: peer_num as u32,
            unused,
            encoding_form_number,
            flags
        }
    }

}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_announcement_base() {
        let hexed_header = String::from("3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2fc928136dc1fe6e04ef6a6dd7187b85f00001576462f6f69");
        let hexed_version_entity = String::from("04020012");
        let hexed_pad = String::from("01");
        let hexed_enc_entity = String::from("07006114458100");
        let hexed_peer_entity = String::from("200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015");
        let test_data = format!("{}{}{}{}{}", hexed_header, hexed_version_entity, hexed_pad, hexed_enc_entity, hexed_peer_entity);
        let test_bytes = hex::decode(test_data).expect("test bytes from https://github.com/cjdelisle/cjdnsann/blob/master/test.js#L30");
        let test_bytes_hash = sha512::hash(&test_bytes);
        let res = Announcement::parse(test_bytes.clone());
        assert_eq!(
            res.unwrap(),
            Announcement {
                header: AnnouncementHeader {
                    signature: "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09".to_string(),
                    pub_signing_key: "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2".to_string(),
                    snode_ip: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("cjdns base test example failed"),
                    ver: 1,
                    is_reset: true,
                    timestamp: 1474857989878
                },
                entities: AnnouncementEntities(vec![
                    Entities::Version(18),
                    Entities::EncodingScheme {
                        hex: "6114458100".to_string(),
                        scheme: vec![
                            EncodingSchemeForm { bit_count: 3, prefix_len: 1, prefix: 1 },
                            EncodingSchemeForm { bit_count: 5, prefix_len: 2, prefix: 2 },
                            EncodingSchemeForm { bit_count: 8, prefix_len: 2, prefix: 0 },
                        ]
                    },
                    Entities::Peer {
                        ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("cjdns base test example failed"),
                        label: DefaultRoutingLabel::try_from("0000.0000.0000.0015").expect("cjdns base test example failed"),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0
                    }
                ]),
                node_pub_key: CJDNSPublicKey::try_from("z15pzyd9wgzs2g5np7d3swrqc1533yb7xx9dq0pvrqrqs42uwgq0.k".to_string()).expect("cjdns base test example failed"),
                node_ip: CJDNS_IP6::try_from("fc49:11cb:38c2:8d42:9865:7b8e:0d67:11b3".to_string()).expect("cjdns base test example failed"),
                binary: test_bytes,
                binary_hash: test_bytes_hash
            }
        )
    }
}

// todo
// 1. consider using EncodingScheme, not Vec<EncodingSchemeForm>
