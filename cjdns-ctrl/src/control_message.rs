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
    pub const MIN_SIZE: usize = Self::HEADER_SIZE + 40; // todo keyping is 40, but ping is 8. which condider as smallest?
    pub const HEADER_SIZE: usize = 4;

    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < Self::MIN_SIZE {
            return Err(ParseError::InvalidPacketSize);
        }
        let mut reader = Reader::new(bytes);
        let endian = {
            let encoded_checksum = reader.read_u16_be().expect("invalid message size");
            let computed_checksum = {
                let checksum_bytes = reader.read_all_pure();
                netchecksum::cksum_raw(checksum_bytes)
            };
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
        let raw_data = reader.read_all_mut().expect("broken reader indexing");
        debug_assert!(raw_data.len() >= 40, "minimum size: 4 bytes for header and minimum 40 bytes for raw data");
        let msg_data = match msg_type {
            CtrlMessageType::Error => CtrlMessageData::ErrorData(ErrorData::parse(raw_data)?),
            CtrlMessageType::GetsNodeQ | CtrlMessageType::GetsNodeR => unimplemented!(),
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
    pub fn from_u16(code: u16) -> Result<CtrlMessageType, ()> {
        CtrlMessageType::try_from(code).map_err(|_| ())
    }
}
