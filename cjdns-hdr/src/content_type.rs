//! Content type enum.

/** TODO for devs
* When header bytes are being parsed, content type number should be considered as Unknown(u16).
* Also, when it is serialized, its associated u16 value should be used for serialization.
* Using `num_enum` crate doesn't allow us using "Other" variant with associated u16 value. The current payoff is using `ContentType::Max` as a default value.
* What's bad about it, is that we can't serialize header with this "default" (aka `ContentType::Max`, aka u32) content type,
* because it's constant value has u32 type, but serialization requires using u16. Obviously, casting default u32 value to u16 has a consequence - truncation.
*
* Possible solution could be saving u16 value to header field and using enum wrapper over `ContentType` with `Known` and `Unknown` variants.
*/

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
    Ip6Max = 255,

    /// Bencoded inter-router DHT message
    Cjdht = 256,
    /// Bencoded inter-router DHT message
    Iptun = 257,

    /// Reserved for future allocation
    Reserved = 258,
    ReservedMax = 0x7fff,

    /// Content types in the AVAILABLE range are not defined and can be used
    /// like port numbers for subsystems of cjdns to communicate with subsystems within
    /// cjdns on other machines, providing they first agree on which numbers to use via
    /// CTRL messages
    Available = 0x8000,

    /// This content type will never appear in the wild, it represents unencrypted control frames.
    Ctrl = 0xffff + 1,

    // read a big comment at the beginning
    #[num_enum(default)]
    Max = 0xffff + 2,
}

impl ContentType {
    pub fn try_to_u16(self) -> Option<u16> {
        // conversion from content type to u32 is provided by num_enum crate
        u16::try_from(u32::from(self)).ok()
    }
}

#[test]
fn test_content_type_conversion() {
    let unknown_content_types = [3, 5, 13, 18, 30, 150, 250, 0x8001];
    for &code in &unknown_content_types {
        assert_eq!(ContentType::from(code), ContentType::Max);
    }
}