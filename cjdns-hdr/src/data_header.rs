//! Logic for a simple data header, providing type of content

use super::{errors::HeaderError, utils::{Reader, Writer}};

type Result<T> = std::result::Result<T, HeaderError>;

const DATA_HEADER_SIZE: usize = 4;
const HEADER_CURRENT_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataHeader {
    pub version: u8,
    pub content_type: header_content::ContentType,
}

impl DataHeader {
    /// Parses bytes into `DataHeader` struct.
    ///
    /// Results in error if bytes length doesn't equal to 4
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() != DATA_HEADER_SIZE {
            return Err(HeaderError::CannotParse("invalid header data size"));
        }
        let mut data_reader = Reader::new(data);
        let version = {
            let version_with_flags = data_reader.read_u8().expect("wrong header bytes size");
            version_with_flags >> 4
        };
        // unused
        let _pad = data_reader.read_u8().expect("wrong header bytes size");
        let content_type = {
            let content_number = data_reader.read_u16_be().expect("wrong header bytes size");
            header_content::ContentType::from(content_number as u32)
        };
        Ok(DataHeader { version, content_type })
    }

    /// Serializes `DataHeader` instance.
    // TODO сделай Writer на подобии Reader, который пишет в себя байт и т.п Владеет Vec<u8>
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut data_writer = Writer::with_capacity(4);
        if self.version > 15 {
            return Err(HeaderError::CannotSerialize("invalid header version"));
        }
        let version_with_flags = if self.version == 0 {
            HEADER_CURRENT_VERSION << 4
        } else {
            self.version << 4
        };
        let content_type_number = header_content::to_u16(self.content_type).map_err(|_| HeaderError::CannotSerialize("invalid content type"))?;

        data_writer.write_u8(version_with_flags);
        // writing pad to returning bytes vec
        data_writer.write_u8(0);
        data_writer.write_u16(content_type_number);

        Ok(data_writer.into_vec())
    }
}

mod header_content {
    use std::convert::TryFrom;
    use std::num::TryFromIntError;

    use num_enum::{FromPrimitive, IntoPrimitive};

    /// The lowest 255 message types are reserved for cjdns/IPv6 packets.
    /// AKA: packets where the IP address is within the FC00::/8 block.
    /// Any packet sent in this way will have the IPv6 header deconstructed and this
    /// field will come from the nextHeader field in the IPv6 header.
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

        /// Bencoded inter-router DHT messages
        Cjdht = 256,
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

        #[num_enum(default)]
        Max = 0xffff + 2,
    }
    
    pub(super) fn to_u16(content_type: ContentType) -> Result<u16, TryFromIntError> {
        u16::try_from(u32::from(content_type))
    }

    #[cfg(test)]
    mod tests {}
}

#[cfg(test)]
mod tests {
    use hex;

    use crate::data_header::header_content::ContentType;
    use crate::data_header::DataHeader;

    #[test]
    fn test_data_header_parse() {
        let test_data = hex::decode("10000100").expect("invalid hex string");
        let parsed_header = DataHeader::parse(&test_data).expect("invalid header data length");
        assert_eq!(parsed_header.version, 1);
        assert_eq!(parsed_header.content_type, ContentType::Cjdht)
    }

    #[test]
    fn test_data_header_serialize() {
        let header_bytes = hex::decode("10000100").expect("invalid hex string");
        let data_header = DataHeader {
            version: 1,
            content_type: ContentType::Cjdht,
        };
        let serialized_header = data_header.serialize().expect("invalid content type");
        assert_eq!(header_bytes, serialized_header);
    }
}
