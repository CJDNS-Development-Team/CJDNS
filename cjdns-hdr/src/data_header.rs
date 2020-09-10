//! Logic for parsing and serializing a simple data header, providing type of content

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

use crate::{
    errors::{ParseError, ParseResult, SerializeError, SerializeResult},
    utils::{Reader, Writer},
};

/// Deserialized simple data header struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHeader {
    pub version: u8,
    pub content_type: ContentType,
}

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

impl DataHeader {
    /// Size of serialized `DataHeader`
    pub const SIZE: usize = 4;

    /// Current version of `DataHeader` which is automatically set, if version is not specified during serialization.
    pub const CURRENT_VERSION: u8 = 1;

    /// Parses bytes into `DataHeader` struct. Used as a constructor.
    ///
    /// Results in error if input bytes length isn't equal to 4, which is current size of serialized header.
    ///
    /// `DataHeader` bytes have a following structure : one byte each for version and padding, two bytes for content number.
    /// Content number is a u16 number which is a numerical representation of [ContentType](todo) variant.
    /// If content number is not defined in `ContentType`, default `ContentType` variant will be used.
    /// *Note*: default `ContentType` variant is a temporary solution.
    pub fn parse(data: &[u8]) -> ParseResult<Self> {
        if data.len() != Self::SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut data_reader = Reader::new(data);
        let version = {
            let version_with_flags = data_reader.read_u8().expect("invalid header data size");
            version_with_flags >> 4
        };
        // unused
        let _pad = data_reader.read_u8().expect("invalid header data size");
        let content_type = {
            let content_number = data_reader.read_u16_be().expect("invalid header data size");
            ContentType::from(content_number as u32)
        };
        Ok(DataHeader { version, content_type })
    }

    /// Serializes `DataHeader` instance.
    ///
    /// `DataHeader` type can be instantiated roughly, without using [parse](todo) method as a constructor.
    /// That's why serialization can result in errors. If header [version](todo) is greater than 15, then serialization fails, because [version](todo) is a number which takes 4 bits in `DataHeader`.
    /// Also serialization fails if no suitable 16 bit content type number was found.
    ///
    /// If `DataHeader` was instantiated with 0 `version`, header will be parsed with version equal to [current version](todo).
    pub fn serialize(&self) -> SerializeResult<Vec<u8>> {
        if self.version > 15 {
            return Err(SerializeError::InvalidInvariant("version value can't take more than 4 bits"));
        }
        let mut data_writer = Writer::with_capacity(Self::SIZE);
        let version_with_flags = if self.version == 0 { Self::CURRENT_VERSION << 4 } else { self.version << 4 };
        let content_type_number = self.content_type.try_to_u16().or(Err(SerializeError::InvalidData(
            "content type can't be serialized into bytes slice with respected length",
        )))?;

        data_writer.write_u8(version_with_flags);
        // writing pad to returning bytes vec
        data_writer.write_u8(0);
        data_writer.write_u16_be(content_type_number);

        Ok(data_writer.into_vec())
    }
}

impl ContentType {
    fn try_to_u16(self) -> std::result::Result<u16, ()> {
        // conversion from content type to u32 is provided by num_enum crate
        u16::try_from(u32::from(self)).or(Err(()))
    }
}

#[cfg(test)]
mod tests {
    use hex;

    use super::{ContentType, DataHeader};

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    fn instantiate_header(version: u8, content_type: ContentType) -> DataHeader {
        DataHeader { version, content_type }
    }

    #[test]
    fn test_base() {
        let test_data = decode_hex("10000100");

        let parsed_header = DataHeader::parse(&test_data).expect("invalid header data length");
        let serialized_header = parsed_header.serialize().expect("invalid header");

        assert_eq!(parsed_header.version, 1);
        assert_eq!(parsed_header.content_type, ContentType::Cjdht);
        assert_eq!(serialized_header, test_data);
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_hex_data = [
            // invalid length
            "1000",
            "000110",
            "1010101010",
        ];
        for hex_header in invalid_hex_data.iter() {
            let invalid_bytes = decode_hex(hex_header);
            assert!(DataHeader::parse(&invalid_bytes).is_err());
        }
    }

    #[test]
    fn test_parse_unknown_content_type() {
        let hex_data = [
            // content type number out of IP6 range - 32000
            "10007d00", // content type number in IP6 range - 100
            "10000064", // content type out of available range (greater than 0x8000)
            "10008001", "1000fff0",
        ];
        for data in hex_data.iter() {
            let bytes_data = decode_hex(data);
            let data_header = DataHeader::parse(&bytes_data).expect("invalid header data");
            // read comment at the beginning of the module
            assert_eq!(data_header.content_type, ContentType::Max);
        }
    }

    #[test]
    fn test_serialize() {
        let valid_headers = [
            instantiate_header(10, ContentType::Ip6Ah),
            instantiate_header(15, ContentType::Cjdht),
            instantiate_header(0, ContentType::Iptun),
        ];
        for header in valid_headers.iter() {
            assert!(header.serialize().is_ok());
        }

        let invalid_headers = [
            // invalid version
            instantiate_header(16, ContentType::Ip6Encap),
            // content type number gt u16
            instantiate_header(0, ContentType::Ctrl),
            // even default fails. Read comment at the beginning of the module
            instantiate_header(10, ContentType::Max),
        ];
        for header in invalid_headers.iter() {
            assert!(header.serialize().is_err());
        }
    }

    #[test]
    fn test_content_type_conversion() {
        let unknown_content_numbers = [3, 5, 13, 18, 30, 150, 250, 0x8001];
        for &number in unknown_content_numbers.iter() {
            assert_eq!(ContentType::from(number), ContentType::Max);
        }
    }
}
