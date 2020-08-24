//! Announcement message
//! `Ann` or `ann` are shorthands for `Announcement` and `announcement`.
use sodiumoxide::crypto::hash::sha512::Digest;

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    DefaultRoutingLabel, EncodingSchemeForm,
};

pub mod ser_announcement;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: AnnouncementEntities,
    pub node_encryption_key: CJDNSPublicKey,
    pub node_ip6: CJDNS_IP6,
    pub binary: ser_announcement::AnnouncementPacket,
    pub binary_hash: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementHeader {
    pub signature: String,
    pub pub_signing_key: String,
    pub super_node_ip: CJDNS_IP6,
    pub version: u8,
    pub is_reset: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementEntities(pub Vec<Entity>); // todo wat

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entity {
    Version(u16),
    EncodingScheme {
        hex: String,
        scheme: Vec<EncodingSchemeForm>,
    },
    Peer {
        ipv6: CJDNS_IP6,
        label: DefaultRoutingLabel,
        mtu: u32,      // size?
        peer_num: u16, // size?
        unused: u32,
        encoding_form_number: u8,
        flags: u8,
    },
}

#[cfg(test)]
mod tests {

    use std::convert::TryFrom;

    use sodiumoxide::crypto::hash::sha512::hash;

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
        let test_bytes_hash = hash(&test_bytes);
        let a = super::ser_announcement::AnnouncementPacket::try_new(test_bytes.clone()).unwrap();
        let res = a.parse();
        assert_eq!(
            res.unwrap(),
            Announcement {
                header: AnnouncementHeader {
                    signature:
                        "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09"
                            .to_string(),
                    pub_signing_key: "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2".to_string(),
                    super_node_ip: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("cjdns base test example failed"),
                    version: 1,
                    is_reset: true,
                    timestamp: 1474857989878
                },
                entities: AnnouncementEntities(vec![
                    Entity::Version(18),
                    Entity::EncodingScheme {
                        hex: "6114458100".to_string(),
                        scheme: vec![
                            EncodingSchemeForm {
                                bit_count: 3,
                                prefix_len: 1,
                                prefix: 1
                            },
                            EncodingSchemeForm {
                                bit_count: 5,
                                prefix_len: 2,
                                prefix: 2
                            },
                            EncodingSchemeForm {
                                bit_count: 8,
                                prefix_len: 2,
                                prefix: 0
                            },
                        ]
                    },
                    Entity::Peer {
                        ipv6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("cjdns base test example failed"),
                        label: DefaultRoutingLabel::try_from("0000.0000.0000.0015").expect("cjdns base test example failed"),
                        mtu: 0,
                        peer_num: 65535,
                        unused: 4294967295,
                        encoding_form_number: 0,
                        flags: 0
                    }
                ]),
                node_encryption_key: CJDNSPublicKey::try_from("z15pzyd9wgzs2g5np7d3swrqc1533yb7xx9dq0pvrqrqs42uwgq0.k".to_string())
                    .expect("cjdns base test example failed"),
                node_ip6: CJDNS_IP6::try_from("fc49:11cb:38c2:8d42:9865:7b8e:0d67:11b3".to_string()).expect("cjdns base test example failed"),
                binary: super::ser_announcement::AnnouncementPacket(test_bytes),
                binary_hash: test_bytes_hash
            }
        )
    }
}

// todo
// 1. consider using EncodingScheme, not Vec<EncodingSchemeForm>
// 2. Having Announcement node_pub_key and node_ip as parts of header
// 3. Difference between Entity::Version and AnnouncementHeader.ver?
// 4. Resolve pub/mod/pub use/pub mod problems
// 5. parse_header - seems a lot of copy/paste. May be implement own iterator, that iterates over chunks size N, that after each next are divided by D (64-32-16)
// 6. is there always
