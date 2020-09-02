use sodiumoxide::crypto::hash::sha512::Digest;

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    AnnouncementPacket, EncodingScheme, RoutingLabel,
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
    pub super_node_ip6: CJDNS_IP6,
    pub version: u8,
    pub is_reset: bool,
    pub timestamp: u64,
}

pub type AnnouncementEntities = Vec<Entity>;
pub type SlotsArray = [u8; 18];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entity {
    NodeProtocolVersion(u16),
    EncodingScheme {
        hex: String,
        scheme: EncodingScheme,
    },
    Peer {
        ip6: CJDNS_IP6,
        label: Option<RoutingLabel<u32>>,
        mtu: u32,
        peer_num: u16,
        unused: u32,
        encoding_form_number: u8,
        flags: u8,
    },
    LinkState {
        node_id: u8,
        starting_point: u8,
        lag_slots: SlotsArray,
        drop_slots: SlotsArray,
        kb_recv_slots: SlotsArray,
    },
}
