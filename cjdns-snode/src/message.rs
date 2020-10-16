//! Msgpack-encodable message that is sent between cjdns supernodes.

use std::collections::VecDeque;

use rmpv::{decode, encode, Utf8String, Value};
use thiserror::Error;

use cjdns_ann::AnnHash;

use crate::peer::AnnData;

/// Message consisting of an unique reply ID and message data.
/// ID can be zero if no reply is required.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message(pub u64, pub MessageData);

#[allow(non_camel_case_types)] // To keep naming consistent with JS code
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MessageData {
    HELLO(u64),
    OLLEH(u64),
    PING,
    ACK,
    GET_DATA(AnnHash),
    DATA(AnnData),
    INV(Vec<AnnHash>)
}

#[derive(Error, Clone, PartialEq, Eq, Debug)]
pub enum EncodingError {
    #[error("Message encoding ended up with an error: {0}")]
    CannotWriteMessageToBuf(String)
}

#[derive(Error, Clone, PartialEq, Eq, Debug)]
pub enum DecodingError {
    #[error("Message decoding ended up with an error: {0}")]
    CannotReadMessageFromBuf(String),

    #[error("Received value type can't be used to decode message")]
    InvalidMsgPackValueType,

    #[error("Conversion from message pack value to intended type failed")]
    CannotConvertFromMsgPackValue,

    #[error("Received message pack array with invalid length")]
    InvalidMsgPackArrayLength,

    #[error("Received message with unrecognized type and data")]
    UnrecognizedMessage,

    #[error("Message type value isn't utf-8 string")]
    InvalidMessageTypeEncoding
}

impl Message {
    pub fn decode_msgpack(bytes: &[u8]) -> Result<Self, DecodingError> {
        let msg = decode::read_value(&mut &bytes[..]).map_err(|e| DecodingError::CannotReadMessageFromBuf(e.to_string()))?;
        Ok(Self::from_msgpack_value(msg)?)
    }

    pub fn encode_msgpack(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::new();
        let msg = self.as_msgpack_value();
        encode::write_value(&mut res, &msg).map_err(|e| EncodingError::CannotWriteMessageToBuf(e.to_string()))?;
        Ok(res)
    }

    fn from_msgpack_value(msg: Value) -> Result<Self, DecodingError> {
        if let Value::Array(mut msg_array) = msg {
            if msg_array.len() <= 1 || msg_array.len() > 4 {
                return Err(DecodingError::InvalidMsgPackArrayLength);
            }
            let id = msg_array.remove(0).as_u64().ok_or(DecodingError::CannotConvertFromMsgPackValue)?;
            let data = MessageData::from_msgpack_value(msg_array)?;
            Ok(Message(id, data))
        } else {
            return Err(DecodingError::InvalidMsgPackValueType);
        }
    }

    fn as_msgpack_value(&self) -> Value {
        let id = Value::from(self.0);
        let data = MessageData::as_msgpack_values(&self.1);
        let mut res = Vec::with_capacity(1 + data.len());
        res.push(id);
        res.extend_from_slice(&data);
        Value::Array(res)
    }
}

impl MessageData {
    /// Create MessageData instance.
    ///
    /// This method is not part of public API, though it need to be `pub` so it can be used with the `msg!` macro.
    #[inline]
    pub fn new(type_str: &str, int_arg: Option<u64>, hash_arr_arg: Option<&[AnnHash]>, data_arg: Option<AnnData>) -> Option<Self> {
        let res = match (type_str, int_arg, hash_arr_arg, data_arg) {
            ("HELLO", Some(version), None, None) => MessageData::HELLO(version),
            ("OLLEH", Some(version), None, None) => MessageData::OLLEH(version),
            ("PING", None, None, None) => MessageData::PING,
            ("ACK", None, None, None) => MessageData::ACK,
            ("GET_DATA", None, Some(hashes), None) if hashes.len() == 1 => MessageData::GET_DATA(hashes[0].clone()),
            ("DATA", None, None, Some(data)) => MessageData::DATA(data.clone()),
            ("INV", Some(0), Some(hashes), None) => MessageData::INV(hashes.iter().cloned().collect()),
            _ => return None
        };
        Some(res)
    }

    /// `msg_data` length is checked in `Message::from_msgpack_value`
    fn from_msgpack_value(msg_data: Vec<Value>) -> Result<Self, DecodingError> {
        let mut msg_data = VecDeque::from(msg_data);
        let type_str = msg_data.pop_front().expect("internal error: message data without message type");
        let data = msg_data.pop_back();
        match type_str {
            Value::String(msg_type) if msg_type == Utf8String::from("PING") && data.is_none() => {
                Ok(MessageData::PING)
            }
            Value::String(msg_type) if msg_type == Utf8String::from("ACK") && data.is_none() => {
                Ok(MessageData::ACK)
            }
            Value::String(msg_type) => {
                if data.is_none() {
                    return Err(DecodingError::UnrecognizedMessage)
                }
                match data.expect("internal error: data is none") {
                    Value::Integer(int) if msg_type == Utf8String::from("HELLO") => {
                        let a = int.as_u64().ok_or(DecodingError::CannotConvertFromMsgPackValue)?;
                        Ok(MessageData::HELLO(a))
                    }
                    Value::Integer(int) if msg_type == Utf8String::from("OLLEH") => {
                        let a = int.as_u64().ok_or(DecodingError::CannotConvertFromMsgPackValue)?;
                        Ok(MessageData::OLLEH(a))
                    }
                    Value::Binary(buf) if msg_type == Utf8String::from("GET_DATA") && !buf.is_empty() => {
                        Ok(MessageData::GET_DATA(AnnHash(buf)))
                    }
                    Value::Binary(buf) if msg_type == Utf8String::from("DATA") && !buf.is_empty() => {
                        Ok(MessageData::DATA(buf))
                    }
                    Value::Array(arr) if msg_type == Utf8String::from("INV") && !arr.is_empty() => {
                        let mut ret = Vec::new();
                        for val in arr {
                            match val {
                                Value::Binary(buf) if !buf.is_empty() => ret.push(AnnHash(buf)),
                                _ => return Err(DecodingError::InvalidMsgPackValueType)
                            }
                        }
                        Ok(MessageData::INV(ret))
                    }
                    _ => Err(DecodingError::UnrecognizedMessage)
                }
            }
            _ => Err(DecodingError::InvalidMessageTypeEncoding)
        }
    }

    fn as_msgpack_values(&self) -> Vec<Value> {
        let mut ret = Vec::with_capacity(2);
        match self {
            MessageData::HELLO(a) => {
                let type_str = Value::from("HELLO");
                let int_arg = Value::from(*a);
                ret.push(type_str);
                ret.push(int_arg);
            },
            MessageData::OLLEH(a) => {
                let type_str = Value::from("OLLEH");
                let int_arg = Value::from(*a);
                ret.push(type_str);
                ret.push(int_arg);
            },
            MessageData::PING => {
                let type_str = Value::from("PING");
                ret.push(type_str);
            },
            MessageData::ACK => {
                let type_str = Value::from("ACK");
                ret.push(type_str);
            },
            MessageData::GET_DATA(data) => {
                let type_str = Value::from("GET_DATA");
                let arr_arg = Value::from(data.bytes());
                ret.push(type_str);
                ret.push(arr_arg);
            },
            MessageData::DATA(data) => {
                let type_str = Value::from("DATA");
                let arr_arg = Value::from(data.as_slice());
                ret.push(type_str);
                ret.push(arr_arg);
            },
            MessageData::INV(data) => {
                let type_str = Value::from("INV");
                let arr_arg = data.iter().map(|v| Value::from(v.bytes())).collect();
                ret.push(type_str);
                ret.push(arr_arg);
            },
        }
        ret
    }
}

#[macro_export]
macro_rules! msg {
    ( $id:expr, $msgtype:literal ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, None, None, None).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal, $int:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, Some($int), None, None).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal | hash = $arr:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, None, Some(&[$arr]), None).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal | data = $bytes:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, None, None, Some($bytes)).expect("bad message literal"))
    }};

    ( $id:expr, $msgtype:literal, $int:expr => hashes = $arrs:expr ) => {{
        use $crate::message::{Message, MessageData};
        Message($id, MessageData::new($msgtype, Some($int), Some($arrs), None).expect("bad message literal"))
    }};
}

#[cfg(test)]
mod tests {
    use cjdns_ann::AnnHash;

    use super::{DecodingError, Message};

    macro_rules! hex {
        ( $hex:literal ) => {
            &hex::decode($hex).expect("bad hex value")
        }
    }

    macro_rules! hash {
        ( $( $bytes:expr ),* ) => {
            AnnHash(vec![$( $bytes ),*])
        }
    }

    #[test]
    fn test_message_simple() {
        let version = 0x42;

        let test = |msg: Message| {
            let bytes = msg.encode_msgpack().expect("failed writing value to buf");
            let decoded = Message::decode_msgpack(&bytes).expect("failed decoding");
            assert_eq!(msg, decoded, "msgpack encode/decode test failed for message {:?}", msg);
        };

        test(msg![0, "HELLO", version]);
        test(msg![0, "OLLEH", version]);
        test(msg![1, "PING"]);
        test(msg![1, "ACK"]);
        test(msg![2, "GET_DATA" | hash = hash![0x11, 0x12, 0x13, 0x14]]);
        test(msg![2, "DATA" | data = vec![0x11, 0x12, 0x13, 0x14]]);
        test(msg![0, "INV", 0 => hashes = &[ hash![1, 2, 3], hash![4, 5, 6], hash![7, 8, 9] ]]);
    }

    #[test]
    fn test_message_real() {
        let test = |msg: Message, bytes: &[u8]| {
            let decoded = Message::decode_msgpack(bytes).expect("failed decoding");
            assert_eq!(msg, decoded, "msgpack decode test failed for message {:?}", msg);

            let encoded = msg.encode_msgpack().expect("failed writing value to buf");
            assert_eq!(encoded, bytes, "msgpack encode test failed for message {:?}", msg);
        };

        test(msg![0, "HELLO", 42], hex!("9300a548454c4c4f2a"));
        test(msg![0, "OLLEH", 42], hex!("9300a54f4c4c45482a"));
        test(msg![1, "PING"], hex!("9201a450494e47"));
        test(msg![1, "ACK"], hex!("9201a341434b"));
        test(msg![2, "GET_DATA" | hash = hash![0xA1, 0xB2, 0xC3, 0xD4]], hex!("9302a84745545f44415441c404a1b2c3d4"));
        test(msg![2, "DATA" | data = vec![0xA1, 0xB2, 0xC3, 0xD4]], hex!("9302a444415441c404a1b2c3d4"));
        test(msg![0, "INV", 0 => hashes = &[ hash![0xA1, 0xB2, 0xC3, 0xD4], hash![0xE5, 0xF6, 0x01, 0x02], hash![0x12, 0x34, 0x56, 0x78] ]], hex!("9300a3494e5693c404a1b2c3d4c404e5f60102c40412345678"));
    }

    #[test]
    fn test_message_decode_err() {
        let test = |bytes:  &[u8], err: DecodingError| {
            let decoded_err = Message::decode_msgpack(bytes).expect_err("valid message bytes");
            assert_eq!(decoded_err, err, "msgpack decode test failed for bytes {:X?}", bytes);
        };

        test(&[0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f], DecodingError::InvalidMsgPackValueType);
        // len == 1
        test(&[0x91, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f], DecodingError::InvalidMsgPackArrayLength);
        // len > 4
        test(&[0x95, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x00, 0x01, 0x02, 0x3], DecodingError::InvalidMsgPackArrayLength);
        // got string instead of int
        test(&[0x92, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x01], DecodingError::CannotConvertFromMsgPackValue);
        // message type isn't string
        test(&[0x92, 0x01, 0x1], DecodingError::InvalidMessageTypeEncoding);
        // unrecognized msg type
        test(&[0x92, 0x01, 0xa6, 0x53, 0x55, 0x50, 0x4d, 0x41, 0x4e], DecodingError::UnrecognizedMessage);
        test(&[0x93, 0x01, 0xa6, 0x53, 0x55, 0x50, 0x4d, 0x41, 0x4e, 0x01], DecodingError::UnrecognizedMessage);
        test(&[0x93, 0x00, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f], DecodingError::UnrecognizedMessage);
        // GET_DATA msg with empty buf
        test(&[0x93, 0x02, 0xa8, 0x47, 0x45, 0x54, 0x5f, 0x44, 0x41, 0x54, 0x41, 0xc4, 0x00], DecodingError::UnrecognizedMessage);
        // INV message with non buf type
        test(&[0x93, 0x02, 0xa3, 0x49, 0x4e, 0x56, 0x93, 0x01, 0x02, 0x03], DecodingError::InvalidMsgPackValueType)
    }
}