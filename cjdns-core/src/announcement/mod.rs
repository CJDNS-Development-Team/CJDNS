//! Announcement message

use sodiumoxide::crypto::hash::sha512;

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    EncodingScheme,
    DefaultRoutingLabel
};

#[derive(Debug, Clone, Copy)]
pub struct Announcement {
    // Announcement header
    pub signature: String,
    pub pub_signing_key: String,
    pub snode_ip: CJDNS_IP6,
    pub ver: u8,
    pub is_reset: bool,
    pub timestamp: u64, // u32 is until 2038

    // Announcement entities
    pub entities: Vec<AnnouncementEntities>,
    // Sender keys
    pub node_pub_key: CJDNSPublicKey,
    pub node_ip: CJDNS_IP6,

    // Announcement Meta
    pub binary: Vec<u8>,
    pub binary_hash: sha512::Digest,
}

#[derive(Debug, PartialEq)]
pub enum AnnouncementEntities {
    Version(u8),
    EncodingScheme { hex: String, scheme: EncodingScheme },
    Peer {
        ipv6: CJDNS_IP6,
        label: DefaultRoutingLabel,
        mtu: u32, // size?
        peer_num: u32, // size?
        unused: u32,
        encoding_form_number: u8, // size?
    }
}

impl Announcement {

    /// Parses announcement message `announcement_msg` and creates `Announcement` struct. Checks message signature if `sig_check_flag` is true.
    pub fn parse(announcement_msg: Vec<u8>, sig_check_flag: bool) -> Result<Self, Box::new(dyn std::error::Error)> {
    }
}
