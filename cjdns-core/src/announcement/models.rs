//! This module exports logic on deserialized announcement message

use sodiumoxide::crypto::hash::sha512::Digest;

use crate::{
    keys::{CJDNSPublicKey, CJDNS_IP6},
    EncodingScheme, RoutingLabel,
};

use super::AnnouncementPacket;

/// Deserialized cjdns route announcement message.
///
/// Contains header, entities and other relevant senders data.
/// A `binary_hash` field stands for the sha512 hash of announcement [packet](struct.Announcement.html#structfield.binary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: AnnouncementEntities,
    pub node_encryption_key: CJDNSPublicKey,
    pub node_ip6: CJDNS_IP6,
    pub binary: AnnouncementPacket,
    pub binary_hash: Digest,
}

/// Deserialized announcement message header.
///
/// As it was stated previously, header size is 120 bytes:
/// * `signature` takes first 64 bytes;
/// * `pub_signing_key` takes 32 bytes after the `signature`;
/// * `super_node_ip6` length is 16 bytes as it should be for cjdns IPv6 addresses.
///
/// Rest data packed in 8 bytes and reserved for `timestamp`. Fields `is_reset` and `version` are encoded in first 4 bits from the right of the `timestamp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementHeader {
    pub signature: String,
    pub pub_signing_key: String,
    pub super_node_ip6: CJDNS_IP6,
    pub version: u8,
    pub is_reset: bool,
    pub timestamp: u64,
}

/// A sequence of entities in the announcement message.
pub type AnnouncementEntities = Vec<Entity>;

// todo
pub type SlotsArray = [u32; 18];

/// Announcement message entity types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entity {
    /// The packet diagram for version entity looks as follows:
    /// ```md
    ///                        1               2               3
    ///        0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     0 |     length    |      type     |             version           |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// * **length**: version entity length is always 4
    /// * **type**: version entity type is always 2
    /// * **version**: big endian representation of the protocol version of the node
    NodeProtocolVersion(u16),

    /// The packet diagram for peer entity looks as follows:
    /// ```md
    ///                        1               2               3
    ///        0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     0 |     length     |      type     | encoding form |     flags    |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     4 |      MTU (8 byte units)       |           peer number         |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///     8 |                               unused                          |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    12 |                                                               |
    ///       +                                                               +
    ///    16 |                                                               |
    ///       +                           Peer IPv6                           +
    ///    20 |                                                               |
    ///       +                                                               +
    ///    24 |                                                               |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///    28 |                             label                             |
    ///       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    ///
    /// * **length**: peer length is always 32
    /// * **type**: peer type is 1
    /// * **encoding form**: this is the number of the form within the encoding scheme which is the smallest
    /// form that can represent the Director for reaching the peer from the announcer. Yes, you read that
    /// right, even though the entity is designed for reaching the announcer from the peer, in order
    /// to chain links for making a label, one must have the inverse encoding form for each hop such that
    /// the reverse label will be the same size as the forward label.
    /// * **flags**: A field for flags for future use such as whether the link is simplex or other
    /// information. Currently there are no flags.
    /// * **MTU8**: The maximum message size for messages going to the announcer from the peer. If this
    /// is set to zero it indicates the announcer is not aware of the MTU.
    /// * **peer number**: number of the peer in the network switch which corresponds to that peer. Used for referencing in [LinkState](enum.Entity.html#variant.LinkState)
    /// * **unused**: alignment padding.
    /// * **Peer IPv6**: The cjdns IPv6 address of the peer from which this node can be reached.
    /// * **label**: The label fragment (Director) which should be used for constructing a label for
    /// reaching the announcer from the peer. A label of 0 indicates that the route is being withdrawn and it is no longer usable.
    /// This is limited to 32 bits because 32 bits is the largest Director that can be represented in an encoding scheme.
    ///
    /// Note that type of **label** field is an `Option`: zero label actually indicates something beneficial here, but we can't
    /// instantiate zero label in current rust implementation. We wrap `Option` over **label**, so `None` case for zero label will be
    /// handled by the user of the `Peer` entity.
    Peer {
        ip6: CJDNS_IP6,
        label: Option<RoutingLabel<u32>>,
        mtu: u32,
        peer_num: u16,
        unused: u32,
        encoding_form_number: u8,
        flags: u8,
    },

    /// As `EncodingScheme` serialization does not have a fixed width in bytes, `EncodingScheme` entities are
    /// prefixed with a number of *pad* entities in order that their length will be a multiple of four
    /// bytes.
    ///
    /// `hex` stands for hexed representation of serialized encoding `scheme`.
    EncodingScheme { hex: String, scheme: EncodingScheme },

    // todo
    LinkState {
        node_id: u32,
        starting_point: u32,
        lag_slots: SlotsArray,
        drop_slots: SlotsArray,
        kb_recv_slots: SlotsArray,
    },
}
