use sodiumoxide::crypto::hash::sha512::Digest;

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    DefaultRoutingLabel, EncodingSchemeForm,
    AnnouncementPacket
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: AnnouncementEntities,
    pub node_encryption_key: CJDNSPublicKey,
    pub node_ip6: CJDNS_IP6,
    pub binary: AnnouncementPacket,
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

pub type AnnouncementEntities = Vec<Entity>;

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
        mtu: u32,
        peer_num: u16,
        unused: u32,
        encoding_form_number: u8,
        flags: u8,
    },
}
