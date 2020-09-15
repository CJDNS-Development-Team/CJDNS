use std::convert::TryFrom;
use std::mem::size_of_val;

use byteorder::{BigEndian, ByteOrder as BO};
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};

use cjdns_bytes::{ParseError, Reader, SerializeError, Writer};
use cjdns_core::keys::CJDNSPublicKey;
use netchecksum;

use crate::{connection_data::PingData, error_data::ErrorData};

/// Serialized control message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtrlMessage {
    pub msg_type: CtrlMessageType,
    pub msg_data: CtrlMessageData,
}

/// Control message type, which is considered as message header
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, TryFromPrimitive, IntoPrimitive)]
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

/// Control message serialized body data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtrlMessageData {
    ConnectionData(PingData),
    ErrorData(ErrorData),
}

impl CtrlMessage {
    /// Control message header size
    pub const HEADER_SIZE: usize = 4;

    /// Parses raw bytes into `CtrlMessage`.
    ///
    /// Result in error in several situations:
    /// * input bytes length is less then `CtrlMessage::HEADER_SIZE`
    /// * input data got invalid checksum
    /// * unrecognized control message type code was parsed
    /// * control message body parsing methods failed. For more information about this read documentation for corresponding data structs (i.e. `PingData`, `ErrorData`)
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut reader = Reader::new(bytes);
        // Validating message checksum
        {
            let encoded_checksum = reader.read_u16_be().expect("invalid message size");
            let computed_checksum = netchecksum::cksum_raw(reader.read_all_pure());
            if encoded_checksum != computed_checksum {
                // todo as alex if it's ok to use external crate only for this
                if computed_checksum != BigEndian::read_u16(&encoded_checksum.to_le_bytes()) {
                    return Err(ParseError::InvalidData("invalid checksum"));
                }
            }
        }
        let msg_type = {
            let type_code = reader.read_u16_be().expect("invalid message size");
            CtrlMessageType::from_u16(type_code).or(Err(ParseError::InvalidData("unknown ctrl packet")))?
        };
        let raw_data = reader.read_all_mut();
        let msg_data = match msg_type {
            CtrlMessageType::Error => CtrlMessageData::ErrorData(ErrorData::parse(raw_data)?),
            CtrlMessageType::GetsNodeQ | CtrlMessageType::GetsNodeR => todo!(),
            // Ping | Pong | KeyPing | KeyPong
            ping_type => CtrlMessageData::ConnectionData(PingData::parse(raw_data, ping_type)?),
        };
        Ok(CtrlMessage {
            msg_type,
            msg_data,
        })
    }

    /// Serialized `CtrlMessage` instance.
    ///
    /// `CtrlMessage` type can be instantiated directly, without using `parse` method.
    /// That's why serialization can result in errors in several situations:
    /// * instantiated message with different header and body types. For example, message with error type stated in header and ping data will fail serialization
    /// * error/ping data serialization failed
    pub fn serialize(&self) -> Result<Vec<u8>, SerializeError> {
        let raw_data = match self.msg_type {
            CtrlMessageType::Error => {
                let error_data = self.msg_data.extract_error_data().ok_or(SerializeError::InvalidInvariant("message with error header, but ping data body"))?;
                error_data.serialize()?
            }
            CtrlMessageType::GetsNodeQ | CtrlMessageType::GetsNodeR => todo!(),
            // Ping | Pong | KeyPing | KeyPong
            ping_type => {
                let ping_data = self.msg_data.extract_ping_data().ok_or(SerializeError::InvalidInvariant("message with ping header, but error data body"))?;
                ping_data.serialize(ping_type)?
            }
        };
        let checksum_data = {
            let msg_type_bytes = self.msg_type.to_u16();
            // encoded msg type and msg raw data
            let mut data = Vec::with_capacity(size_of_val(&msg_type_bytes) + raw_data.len());
            data.extend_from_slice(&msg_type_bytes.to_be_bytes());
            data.extend_from_slice(&raw_data);
            data
        };
        let checksum = netchecksum::cksum_raw(&checksum_data);

        let mut writer = Writer::with_capacity(size_of_val(&checksum) + checksum_data.len());
        writer.write_u16_be(checksum);
        writer.write_slice(&checksum_data);

        Ok(writer.into_vec())
    }
}

impl CtrlMessageType {
    fn from_u16(code: u16) -> Result<CtrlMessageType, ()> {
        CtrlMessageType::try_from(code).map_err(|_| ())
    }

    fn to_u16(self) -> u16 {
        self.into()
    }
}

impl CtrlMessageData {
    fn extract_error_data(&self) -> Option<&ErrorData> {
        match self {
            Self::ErrorData(data) => Some(data),
            _ => None,
        }
    }

    fn extract_ping_data(&self) -> Option<&PingData> {
        match self {
            Self::ConnectionData(data) => Some(data),
            _ => None,
        }
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
        let serialized_msg = parsed_msg.serialize().expect("invalid message data");
        assert_eq!(
            parsed_msg,
            CtrlMessage {
                msg_type: CtrlMessageType::Ping,
                msg_data: CtrlMessageData::ConnectionData(PingData {
                    version: 18,
                    key: None,
                    content: decode_hex("4d160b1eee2929e12e19a3b1")
                }),
            }
        );
        assert_eq!(serialized_msg, test_bytes);
    }

    #[test]
    fn test_key_ping() {
        let test_bytes = decode_hex("994b00050123456700000012a331ebbed8d92ac03b10efed3e389cd0c6ec7331a72dbde198476c5eb4d14a1f02e29842b42aedb6bce2ead3");
        let parsed_msg = CtrlMessage::parse(&test_bytes).expect("invalid message data");
        let serialized_msg = parsed_msg.serialize().expect("invalid message data");
        assert_eq!(
            parsed_msg,
            CtrlMessage {
                msg_type: CtrlMessageType::KeyPing,
                msg_data: CtrlMessageData::ConnectionData(PingData {
                    version: 18,
                    key: CJDNSPublicKey::try_from("3fdqgz2vtqb0wx02hhvx3wjmjqktyt567fcuvj3m72vw5u6ubu70.k".to_string()).ok(),
                    content: decode_hex("02e29842b42aedb6bce2ead3")
                }),
            }
        );
        assert_eq!(serialized_msg, test_bytes);
    }

    #[test]
    fn test_error() {
        let error_hex = "bce300020000000a62c1d23a648114010379000000012d7c000006c378e071c46aefad3aa\
            295fff396371d10678e9833807de083a4a40da39bf0f68f15c4380afbe92405196242a74bb3\
            04a8285088579f94fb01867be2171aa8d2c7b54198a89bbdb80c668e9c05";
        let test_bytes = decode_hex(error_hex);
        let parsed_msg = CtrlMessage::parse(&test_bytes).expect("invalid message data");
        let parsed_additional = vec![
            0u8, 1, 45, 124, 0, 0, 6, 195, 120, 224, 113, 196, 106, 239, 173, 58, 162, 149, 255, 243, 150, 55, 29, 16, 103, 142, 152, 51, 128, 125, 224, 131,
            164, 164, 13, 163, 155, 240, 246, 143, 21, 196, 56, 10, 251, 233, 36, 5, 25, 98, 66, 167, 75, 179, 4, 168, 40, 80, 136, 87, 159, 148, 251, 1, 134,
            123, 226, 23, 26, 168, 210, 199, 181, 65, 152, 168, 155, 189, 184, 12, 102, 142, 156, 5,
        ];
        let serialized_msg = parsed_msg.serialize().expect("invalid message data");
        assert_eq!(
            parsed_msg,
            CtrlMessage {
                msg_type: CtrlMessageType::Error,
                msg_data: CtrlMessageData::ErrorData(ErrorData {
                    err_type: ErrorMessageType::ReturnPathInvalid,
                    switch_header: SwitchHeader {
                        label: RoutingLabel::<u64>::try_from("62c1.d23a.6481.1401").expect("invalid routing label string"),
                        congestion: 1,
                        suppress_errors: true,
                        version: 1,
                        label_shift: 57,
                        penalty: 0
                    },
                    additional: parsed_additional
                }),
            }
        );
        assert_eq!(serialized_msg, test_bytes);
    }
}
