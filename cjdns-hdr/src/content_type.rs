//! Content type enum.

use std::convert::TryFrom;

use num_enum::{FromPrimitive, IntoPrimitive};

/// Header content types.
///
/// The lowest 255 message types are reserved for cjdns/IPv6 packets.
/// AKA: packets where the IP address is within the FC00::/8 block.
/// Any packet sent in this way will have the IPv6 header deconstructed and this
/// field will come from the next header field in the IPv6 header.
#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[repr(u32)]
pub enum ContentType {
    Ip6Hop = 0,
    Ip6Icmp = 1,
    Ip6Igmp = 2,
    Ip6Ipv4 = 4,
    Ip6Tcp = 6,
    Ip6Egp = 8,
    Ip6Pup = 12,
    Ip6Udp = 17,
    Ip6Idp = 22,
    Ip6Tp = 29,
    Ip6Dccp = 33,
    Ip6Ipv6 = 41,
    Ip6Rsvp = 46,
    Ip6Gre = 47,
    Ip6Esp = 50,
    Ip6Ah = 51,
    Ip6Icmpv6 = 58,
    Ip6Mtp = 92,
    Ip6Beetph = 94,
    Ip6Encap = 98,
    Ip6Pim = 103,
    Ip6Comp = 108,
    Ip6Sctp = 132,
    Ip6Udplite = 136,

    /// Bencoded inter-router DHT message
    Cjdht = 256,
    /// Bencoded inter-router DHT message
    Iptun = 257,

    /// This content type will never appear in the wild, it represents unencrypted control frames
    Ctrl = 0xffff + 1,

    /// Unrecognized or user-defined content type.
    ///
    /// If a message with unrecognized content type received, it is parsed as `Other`.
    /// Though if this message should be re-serialized and forwarded, the content type must be preserved.
    /// This should be done by other means, such as storing raw content type elsewhere.
    #[num_enum(default)]
    Other = ContentType::MAX,
}

impl ContentType {
    /// The lowest 255 message types are reserved for cjdns/IPv6 packets
    pub const IP6_MAX: u32 = 255;

    /// Reserved for future allocation
    pub const RESERVED: u32 = 258;
    pub const RESERVED_MAX: u32 = 0x7fff;

    /// Content types in the AVAILABLE range are not defined and can be used
    /// like port numbers for subsystems of cjdns to communicate with subsystems within
    /// cjdns on other machines, providing they first agree on which numbers to use via
    /// CTRL messages
    pub const AVAILABLE: u32 = 0x8000;

    /// Maximum possible defined value for the content type
    pub const MAX: u32 = 0xffff + 2;

    pub fn from_u16(code: u16) -> Self {
        ContentType::from_primitive(code as u32)
    }

    pub fn try_to_u16(self) -> Option<u16> {
        // conversion from content type to u32 is provided by num_enum crate
        u16::try_from(u32::from(self)).ok()
    }
}

#[test]
fn test_content_type_conversion() {
    let unknown_content_types = [3, 5, 13, 18, 30, 150, 250, 258, 0x8000, 0x8001];
    for &code in &unknown_content_types {
        assert_eq!(ContentType::from_primitive(code), ContentType::Other);
    }
}