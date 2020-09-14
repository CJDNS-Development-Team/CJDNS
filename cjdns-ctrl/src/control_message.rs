use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder as BO};
use num_enum::{TryFromPrimitive, TryFromPrimitiveError};

use cjdns_bytes::{ParseError, Reader, SerializeError};
use cjdns_core::keys::CJDNSPublicKey;
use netchecksum;

use crate::{connection_data::ConnectionData, error_data::ErrorData};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrlMessage {
    pub msg_type: CtrlMessageType,
    pub msg_data: CtrlMessageData,
    pub endian: ByteOrder,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, TryFromPrimitive)]
#[repr(u16)]
pub enum CtrlMessageType {
    Error = 2,
    Ping,
    Pong,
    KeyPing,
    KeyPong,
    GetsNodeQ,
    GetsNodeR,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlMessageData {
    ConnectionData(ConnectionData),
    ErrorData(ErrorData),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ByteOrder {
    LE,
    BE,
}

impl CtrlMessage {
    // todo 1 does not comply with C impl https://github.com/cjdelisle/cjdnsctrl/blob/ec6c8b68aac6cd4fde3011ef1321f776f76d03d0/index.js#L40
    // pub const MIN_SIZE: usize = Self::HEADER_SIZE + 40; // keyping is 40, but ping is 8. which consider as smallest?
    pub const HEADER_SIZE: usize = 4;

    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        // TODO 1 check bytes len only for being less than HEADER_SIZE? because other data lengths we could handle in msg data handlers
        // or https://github.com/cjdelisle/cjdns/blob/77259a49e5bc7ca7bc6dca5bd423e02be563bdc5/wire/Control.h#L213 ? But what to do then if we get ping message
        let mut reader = Reader::new(bytes);
        let endian = {
            let encoded_checksum = reader.read_u16_be().expect("invalid message size");
            let computed_checksum = netchecksum::cksum_raw(reader.read_all_pure());
            if encoded_checksum == computed_checksum {
                ByteOrder::LE
            } else if computed_checksum == BigEndian::read_u16(&encoded_checksum.to_le_bytes()) {
                ByteOrder::BE
            } else {
                return Err(ParseError::InvalidData("invalid checksum"));
            }
        };
        let msg_type = {
            let type_code = reader.read_u16_be().expect("invalid message size");
            CtrlMessageType::from_u16(type_code).or(Err(ParseError::InvalidData("unknown ctrl packet")))?
        };
        let raw_data = reader.read_all_mut();
        let msg_data = match msg_type {
            CtrlMessageType::Error => CtrlMessageData::ErrorData(ErrorData::parse(raw_data)?),
            CtrlMessageType::GetsNodeQ | CtrlMessageType::GetsNodeR => unimplemented!(), // todo 4 or unreachable? https://github.com/cjdelisle/cjdnsctrl/blob/ec6c8b68aac6cd4fde3011ef1321f776f76d03d0/index.js#L96
            // Ping | Pong | KeyPing | KeyPong
            conn_type => CtrlMessageData::ConnectionData(ConnectionData::parse(raw_data, conn_type)?),
        };
        Ok(CtrlMessage { msg_type, msg_data, endian })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        todo!()
    }
}

impl CtrlMessageType {
    fn from_u16(code: u16) -> Result<CtrlMessageType, ()> {
        CtrlMessageType::try_from(code).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;
    use crate::error_data::ErrorMessageType;
    use cjdns_core::RoutingLabel;
    use cjdns_hdr::SwitchHeader;

    fn decode_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).expect("invalid hex string")
    }

    #[test]
    fn test_ping() {
        let test_bytes = decode_hex("a2e5000309f91102000000124d160b1eee2929e12e19a3b1");
        let parsed_msg = CtrlMessage::parse(&test_bytes).expect("invalid message data");
        assert_eq!(
            parsed_msg,
            CtrlMessage {
                msg_type: CtrlMessageType::Ping,
                msg_data: CtrlMessageData::ConnectionData(ConnectionData {
                    version: 18,
                    key: None,
                    content: decode_hex("4d160b1eee2929e12e19a3b1")
                }),
                endian: ByteOrder::LE
            }
        );
    }

    #[test]
    fn test_key_ping() {
        let test_bytes = decode_hex("994b00050123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3");
        let parsed_msg = CtrlMessage::parse(&test_bytes).expect("invalid message data");
        assert_eq!(
            parsed_msg,
            CtrlMessage {
                msg_type: CtrlMessageType::KeyPing,
                msg_data: CtrlMessageData::ConnectionData(ConnectionData {
                    version: 18,
                    key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).ok(),
                    content: decode_hex("02e29842b42aedb6bce2ead3")
                }),
                endian: ByteOrder::LE
            }
        );
    }

    #[test]
    fn test_error() {
        let error_hex = "bce300020000000a62c1d23a648114010379000000012d7c000006c378e071c46aefad3aa\
            295fff396371d10678e9833807de083a4a40da39bf0f68f15c4380afbe92405196242a74bb3\
            04a8285088579f94fb01867be2171aa8d2c7b54198a89bbdb80c668e9c05";
        let test_bytes = decode_hex(error_hex);
        let parsed_msg = CtrlMessage::parse(&test_bytes).expect("invalid message data");
        let parsed_additional = vec![
            0u8, 0, 6, 195, 120, 224, 113, 196, 106, 239, 173, 58, 162, 149, 255, 243, 150, 55, 29, 16, 103, 142, 152, 51, 128, 125, 224, 131, 164, 164, 13,
            163, 155, 240, 246, 143, 21, 196, 56, 10, 251, 233, 36, 5, 25, 98, 66, 167, 75, 179, 4, 168, 40, 80, 136, 87, 159, 148, 251, 1, 134, 123, 226, 23,
            26, 168, 210, 199, 181, 65, 152, 168, 155, 189, 184, 12, 102, 142, 156, 5,
        ];
        assert_eq!(
            parsed_msg,
            CtrlMessage {
                msg_type: CtrlMessageType::Error,
                msg_data: CtrlMessageData::ErrorData(ErrorData {
                    err_type: ErrorMessageType::ReturnPathInvalid,
                    switch_header: Some(SwitchHeader {
                        label: RoutingLabel::<u64>::try_from("62c1.d23a.6481.1401").expect("invalid routing label string"),
                        congestion: 1,
                        suppress_errors: true,
                        version: 1,
                        label_shift: 57,
                        penalty: 0
                    }),
                    nonce: Some(77180),
                    additional: parsed_additional
                }),
                endian: ByteOrder::LE
            }
        );
    }
}
