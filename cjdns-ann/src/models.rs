//! This module exports logic on deserialized announcement message

use sodiumoxide::crypto::hash::sha512::Digest;

use cjdns_core::{EncodingScheme, RoutingLabel};
use cjdns_keys::{CJDNS_IP6, CJDNSPublicKey};

use super::AnnouncementPacket;

/// Deserialized cjdns route announcement message.
///
/// Contains header, entities and other relevant senders data.
/// A `binary_hash` field stands for the sha512 hash of announcement [packet](struct.Announcement.html#structfield.binary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub header: AnnouncementHeader,
    pub entities: AnnouncementEntities,
    pub node_pub_key: CJDNSPublicKey,
    pub node_ip: CJDNS_IP6,
    pub binary: AnnouncementPacket,
    pub hash: Digest,
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
    pub snode_ip: CJDNS_IP6,
    pub version: u8,
    pub is_reset: bool,
    pub timestamp: u64,
}

/// A sequence of entities in the announcement message.
pub type AnnouncementEntities = Vec<Entity>;

/// An array of slots, storing network link samples.
///
/// Samples are collected every 10 seconds, normally messages are submitted to the Route Server every minute,
/// resulting in 6 samples. But we would store 3 times more samples so that if there is some reason it is unable
/// to submit a message to the route server for up to 3 minutes, still no link state samples will be lost.
pub type LinkStateSlots<T> = [Option<T>; 18];

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
    /// * **peer number**: number of the peer in the network switch which corresponds to that peer.
    /// Used for referencing in [LinkState](enum.Entity.html#variant.LinkState)
    /// * **unused**: alignment padding.
    /// * **Peer IPv6**: The cjdns IPv6 address of the peer from which this node can be reached.
    /// * **label**: The label fragment (Director) which should be used for constructing a label for
    /// reaching the announcer from the peer. A label of 0 indicates that the route is being withdrawn and it is no longer usable.
    /// This is limited to 32 bits because 32 bits is the largest Director that can be represented in an encoding scheme.
    ///
    /// **Note:** The `label` field is an `Option`: zero label parsed as `None` (the route is being withdrawn and it is no longer usable),
    /// nonzero label is `Some(label)`.
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
    /// prefixed with a number of pads in order that their length will be a multiple of four bytes.
    ///
    /// `hex` stands for hex string representation of serialized encoding `scheme`.
    EncodingScheme { hex: String, scheme: EncodingScheme },

    /// `LinkState` stores data, which is used by route server/super node to plot good paths
    /// through the network and avoid links which have long or unreliable delay.
    /// So the data under `LinkState` represents the quality of network link.
    LinkState {
        node_id: u16,
        slots_start_idx: u8,
        lag_slots: LinkStateSlots<u16>,
        drop_slots: LinkStateSlots<u16>,
        kb_recv_slots: LinkStateSlots<u32>,
    },
}
