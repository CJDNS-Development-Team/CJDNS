//! Library for parsing cjdns route announcement messages.
//!
//! Each cjdns announcement message contains message header, a sequence of entities and some additional data derived from header.
//! For example, senders auth curve25519 encryption key is derived from the announcement header.
//!
//! # Header
//!
//! The header is 120 bytes long and contains an ed25519 signature over the entire announcement,
//! the public signing key (which is used to create senders auth encryption key using `ed25519 -> curve25519` conversion) of the node which created the announcement, the cjdns IPv6 address of the supernode to which this subnode is announcing,
//! a timestamp, version and a reset flag. On the 03.09.2020 announcement protocol version is `1`.
//!
//! Announcement header packet diagram looks as follows:
//! ```md
//!                        1               2               3
//!        0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//!       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     0 |                                                               |
//!       +                                                               +
//!     4 |                                                               |
//!       +                                                               +
//!     8 |                                                               |
//!       +                                                               +
//!    12 |                                                               |
//!       +                                                               +
//!    16 |                                                               |
//!       +                                                               +
//!    20 |                                                               |
//!       +                                                               +
//!    24 |                                                               |
//!       +                                                               +
//!    28 |                                                               |
//!       +                           Signature                           +
//!    32 |                                                               |
//!       +                                                               +
//!    36 |                                                               |
//!       +                                                               +
//!    40 |                                                               |
//!       +                                                               +
//!    44 |                                                               |
//!       +                                                               +
//!    48 |                                                               |
//!       +                                                               +
//!    52 |                                                               |
//!       +                                                               +
//!    56 |                                                               |
//!       +                                                               +
//!    60 |                                                               |
//!       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    64 |                                                               |
//!       +                                                               +
//!    68 |                                                               |
//!       +                                                               +
//!    72 |                                                               |
//!       +                                                               +
//!    76 |                                                               |
//!       +                     Public Signing Key                        +
//!    80 |                                                               |
//!       +                                                               +
//!    84 |                                                               |
//!       +                                                               +
//!    88 |                                                               |
//!       +                                                               +
//!    92 |                                                               |
//!       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!    96 |                                                               |
//!       +                                                               +
//!   100 |                                                               |
//!       +                        SuperNode IP                           +
//!   104 |                                                               |
//!       +                                                               +
//!   108 |                                                               |
//!       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   112 |                                                               |
//!       +                         Timestamp                     +-+-+-+-+
//!   116 |                                                       |R| ver |
//!       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Entities
//!
//! Every entity in announcement message begins with two bytes, indicating length and type, at the time of this writing the types of entities are:
//! 1. `EncodingScheme` with type number `0`. The entity contains serialized representation of encoding scheme created by [serializer](../fn.serialize_forms.html). Please look [here](../fn.deserialize_forms.html) for more information about how this is parsed.
//! 2. `Peer` with type number `1`. Each `Peer` entity contains roughly the information which is needed to reach the announcer from a given peer. It is important to note that this is *not* about ability to reach the *peer*, but to reach the announcer if one can already reach said peer.
//! 3. `NodeProtocolVersion` with type number `2`. The entity tells the protocol version of the node sending it.
//! 4. `LinkState` with type number `3`.
//!
//! Entity messages all begin with the length of the entity such that future entities can be added and skipped over by older versions of the parser.
//! Entities longer than 255 or shorter than 1 byte are invalid. If the entity length field is exactly 1 byte, it is a pad and that byte should be skipped over.
//! Pads can be useful to byte-align messages with oddly sized entities.
//!
//! # Example
//! ```rust
//! # use std::convert::TryFrom;
//! # use sodiumoxide::crypto::hash::sha512;
//! # use cjdns_core::{RoutingLabel, EncodingScheme, EncodingSchemeForm};
//! # use cjdns_keys::{CJDNS_IP6, CJDNSPublicKey};
//! # use cjdns_ann::{Announcement, AnnouncementHeader, AnnouncementEntities, Entity};
//! use cjdns_ann::AnnouncementPacket;
//! #
//! # let announcement_bytes = {
//! #     let hexed_announcement = "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2fc928136dc1fe6e04ef6a6dd7187b85f00001576462f6f69040200120107006114458100200100000000fffffffffffffc928136dc1fe6e04ef6a6dd7187b85f00000015";
//! #     hex::decode(hexed_announcement).expect("invalid hex string")
//! # };
//! # let returning_packet = AnnouncementPacket::try_new(announcement_bytes.clone()).expect("invalid packet length");
//! # let announcement_bytes_hash = sha512::hash(&announcement_bytes);
//!
//! // creating packet
//! let announcement_packet = AnnouncementPacket::try_new(announcement_bytes).unwrap();
//!
//! // checking announcement signature
//! assert!(announcement_packet.check().is_ok());
//!
//! // parsing announcement packet
//! let deserialized_announcement = announcement_packet.parse().unwrap();
//! # assert_eq!(
//! #     deserialized_announcement,
//! #     Announcement {
//! #         header: AnnouncementHeader {
//! #             signature:
//! #                 "3a2349bd342608df20d999ff2384e99f1e179dbdf4aaa61692c2477c011cfe635b42d3cdb8556d94f365cdfa338dc38f40c1fabf69500830af915f41bed71b09"
//! #                     .to_string(),
//! #             pub_signing_key: "f2e1d148ed18b09d16b5766e4250df7b4e83a5ccedd4cfde15f1f474db1a5bc2".to_string(),
//! #             super_node_ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
//! #             version: 1,
//! #             is_reset: true,
//! #             timestamp: 1474857989878
//! #         },
//! #         entities: vec![
//! #             Entity::NodeProtocolVersion(18),
//! #             Entity::EncodingScheme {
//! #                 hex: "6114458100".to_string(),
//! #                 scheme: EncodingScheme::new(&vec![
//! #                     EncodingSchemeForm {
//! #                         bit_count: 3,
//! #                         prefix_len: 1,
//! #                         prefix: 1
//! #                     },
//! #                     EncodingSchemeForm {
//! #                         bit_count: 5,
//! #                         prefix_len: 2,
//! #                         prefix: 2
//! #                     },
//! #                     EncodingSchemeForm {
//! #                         bit_count: 8,
//! #                         prefix_len: 2,
//! #                         prefix: 0
//! #                     },
//! #                 ])
//! #             },
//! #             Entity::Peer {
//! #                 ip6: CJDNS_IP6::try_from("fc92:8136:dc1f:e6e0:4ef6:a6dd:7187:b85f".to_string()).expect("failed ip6 creation"),
//! #                 label: Some(RoutingLabel::<u32>::try_new(21).expect("zero routing label bits")),
//! #                 mtu: 0,
//! #                 peer_num: 65535,
//! #                 unused: 4294967295,
//! #                 encoding_form_number: 0,
//! #                 flags: 0
//! #             }
//! #         ],
//! #         node_encryption_key: CJDNSPublicKey::try_from("z15pzyd9wgzs2g5np7d3swrqc1533yb7xx9dq0pvrqrqs42uwgq0.k".to_string())
//! #             .expect("failed pub key creation"),
//! #         node_ip6: CJDNS_IP6::try_from("fc49:11cb:38c2:8d42:9865:7b8e:0d67:11b3".to_string()).expect("failed ip6 creation"),
//! #         binary: returning_packet,
//! #         binary_hash: announcement_bytes_hash
//! #     }
//! # );
//!
//! ```

pub use models::{Announcement, AnnouncementEntities, AnnouncementHeader, Entity, LinkStateSlots};
pub use serialized_ann::serialized_data::AnnouncementPacket;

mod errors;
mod models;
mod serialized_ann;
