//! Msgpack-encodable message that is sent between cjdns supernodes.

use rmpv::{decode::read_value, encode::write_value, Value};
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
    INV(Vec<AnnHash>),
}

#[derive(Error, Clone, PartialEq, Eq, Debug)]
pub enum EncodingError {
    #[error("Failed to serialize MsgPack message: {0}")]
    MsgpackSerializeError(String),
}

#[derive(Error, Clone, PartialEq, Eq, Debug)]
pub enum DecodingError {
    #[error("Failed to deserialize MsgPack message: {0}")]
    MsgpackDeserializeError(String),

    #[error("Bad message: Array of length 2..4 expected at the root")]
    BadMessageRootType,

    #[error("Bad message: Array of length 2..4 expected at the root, got {0}")]
    BadMessageRootArrayLength(usize),

    #[error("Bad message: ID field expected to be numeric")]
    BadIdFieldType,

    #[error("Bad message: TYPE field expected to be String")]
    BadTypeFieldType,

    #[error("Bad message: `{0}` message expected to have {1} args but found {2}")]
    BadArgsCount(String, usize, usize),

    #[error("Bad message: `{0}` message's arg(s) have wrong type(s)")]
    BadArgType(String),

    #[error("Bad HELLO message: VERSION field expected to be numeric")]
    BadHelloVersionFieldType,

    #[error("Bad message: `{0}` not recognized")]
    UnrecognizedMessageType(String),
}

impl Message {
    pub fn decode_msgpack(bytes: &[u8]) -> Result<Self, DecodingError> {
        let msg = read_value(&mut &bytes[..]).map_err(|e| DecodingError::MsgpackDeserializeError(e.to_string()))?;
        Self::from_msgpack(msg)
    }

    pub fn encode_msgpack(&self) -> Result<Vec<u8>, EncodingError> {
        let msg = self.as_msgpack();
        let mut res = Vec::new();
        write_value(&mut res, &msg).map_err(|e| EncodingError::MsgpackSerializeError(e.to_string()))?;
        Ok(res)
    }

    fn from_msgpack(msg: Value) -> Result<Self, DecodingError> {
        if let Value::Array(root_arr) = msg {
            let n = root_arr.len();
            if n < 2 || n > 4 {
                return Err(DecodingError::BadMessageRootArrayLength(n));
            }
            let id = root_arr[0].as_u64().ok_or(DecodingError::BadIdFieldType)?;
            let data = MessageData::from_msgpack(&root_arr[1..])?;
            Ok(Message(id, data))
        } else {
            return Err(DecodingError::BadMessageRootType);
        }
    }

    fn as_msgpack(&self) -> Value {
        let Message(id, ref data) = *self;
        let mut res = Vec::with_capacity(4);

        let id = Value::from(id);
        res.push(id);

        let res = data.as_msgpack(res);

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
            _ => return None,
        };
        Some(res)
    }

    fn from_msgpack(msg_data: &[Value]) -> Result<Self, DecodingError> {
        debug_assert!(msg_data.len() >= 1 && msg_data.len() <= 4); // checked by the caller
        let type_str = if let Value::String(s) = &msg_data[0] {
            s.as_str().ok_or(DecodingError::BadTypeFieldType)?
        } else {
            return Err(DecodingError::BadTypeFieldType);
        };
        let data = &msg_data[1..];
        let n = data.len();

        let check_data_len = |expected_len: usize| -> Result<(), DecodingError> {
            if n != expected_len {
                Err(DecodingError::BadArgsCount(type_str.to_string(), expected_len, n))
            } else {
                Ok(())
            }
        };

        match type_str {
            "PING" => {
                check_data_len(0)?;
                Ok(MessageData::PING)
            }

            "ACK" => {
                check_data_len(0)?;
                Ok(MessageData::ACK)
            }

            "HELLO" => {
                check_data_len(1)?;
                let ver = data[0].as_u64().ok_or(DecodingError::BadHelloVersionFieldType)?;
                Ok(MessageData::HELLO(ver))
            }

            "OLLEH" => {
                check_data_len(1)?;
                let ver = data[0].as_u64().ok_or(DecodingError::BadHelloVersionFieldType)?;
                Ok(MessageData::OLLEH(ver))
            }

            "GET_DATA" => {
                check_data_len(1)?;
                if let Value::Binary(hash) = &data[0] {
                    if hash.len() > 0 {
                        // Hash str can't be empty
                        return Ok(MessageData::GET_DATA(AnnHash(hash.clone())));
                    }
                }
                return Err(DecodingError::BadArgType(type_str.to_string()));
            }

            "DATA" => {
                check_data_len(1)?;
                match &data[0] {
                    Value::Binary(data) => {
                        // Empty data is allowed
                        Ok(MessageData::DATA(data.clone()))
                    }
                    Value::Nil => {
                        // Nil data is allowed (same as empty)
                        Ok(MessageData::DATA(Vec::new()))
                    }
                    _ => {
                        trace!(">>> {:?}", msg_data);
                        Err(DecodingError::BadArgType(type_str.to_string()))
                    }
                }
            }

            "INV" => {
                check_data_len(2)?;
                let arr = data[1].as_array().ok_or(DecodingError::BadArgType(type_str.to_string()))?;
                let try_hashes: Result<_, _> = arr
                    .iter()
                    .map(|val| {
                        if let Value::Binary(hash) = val {
                            if hash.len() > 0 {
                                Ok(AnnHash(hash.clone()))
                            } else {
                                Err(DecodingError::BadArgType(type_str.to_string()))
                            }
                        } else {
                            Err(DecodingError::BadArgType(type_str.to_string()))
                        }
                    })
                    .collect();
                let hashes = try_hashes?;
                Ok(MessageData::INV(hashes))
            }

            _ => Err(DecodingError::UnrecognizedMessageType(type_str.to_string())),
        }
    }

    fn as_msgpack(&self, mut res: Vec<Value>) -> Vec<Value> {
        match self {
            MessageData::HELLO(a) => {
                res.push(Value::from("HELLO"));
                res.push(Value::from(*a));
            }
            MessageData::OLLEH(a) => {
                res.push(Value::from("OLLEH"));
                res.push(Value::from(*a));
            }
            MessageData::PING => {
                res.push(Value::from("PING"));
            }
            MessageData::ACK => {
                res.push(Value::from("ACK"));
            }
            MessageData::GET_DATA(data) => {
                res.push(Value::from("GET_DATA"));
                res.push(Value::from(data.bytes()));
            }
            MessageData::DATA(data) => {
                res.push(Value::from("DATA"));
                if data.is_empty() {
                    res.push(Value::Nil);
                } else {
                    res.push(Value::from(data.as_slice()));
                }
            }
            MessageData::INV(data) => {
                res.push(Value::from("INV"));
                res.push(Value::from(0)); // Dummy 0 integer
                res.push(data.iter().map(|v| Value::from(v.bytes())).collect());
            }
        }
        res
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
        };
    }

    macro_rules! hash {
        ( $( $bytes:expr ),* ) => {
            AnnHash(vec![$( $bytes ),*])
        }
    }

    #[test]
    fn test_message_encode_decode() {
        let version = 0x42;

        let test = |msg: Message| {
            let try_encoded = msg.encode_msgpack();
            assert_eq!(try_encoded.as_ref().err(), None, "failed to encode {:?}", msg);
            let encoded = try_encoded.unwrap();
            let try_decoded = Message::decode_msgpack(&encoded);
            assert_eq!(try_decoded.as_ref().err(), None, "failed to decode {:?}", hex::encode(encoded));
            let decoded = try_decoded.unwrap();
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
    fn test_message_decode_encode() {
        let test = |msg: Message, bytes: &[u8]| {
            let try_decoded = Message::decode_msgpack(bytes);
            assert_eq!(try_decoded.as_ref().err(), None, "failed to decode {:?}", hex::encode(bytes));
            let decoded = try_decoded.unwrap();
            assert_eq!(msg, decoded, "msgpack decode test failed for message {:?}", msg);

            let try_encoded = msg.encode_msgpack();
            assert_eq!(try_encoded.as_ref().err(), None, "failed to encode {:?}", msg);
            let encoded = try_encoded.unwrap();
            assert_eq!(encoded, bytes, "msgpack encode test failed for message {:?}", msg);
        };

        test(msg![0, "HELLO", 42], hex!("9300a548454c4c4f2a"));
        test(msg![0, "OLLEH", 42], hex!("9300a54f4c4c45482a"));
        test(msg![1, "PING"], hex!("9201a450494e47"));
        test(msg![1, "ACK"], hex!("9201a341434b"));
        test(
            msg![2, "GET_DATA" | hash = hash![0xA1, 0xB2, 0xC3, 0xD4]],
            hex!("9302a84745545f44415441c404a1b2c3d4"),
        );
        test(msg![2, "DATA" | data = vec![0xA1, 0xB2, 0xC3, 0xD4]], hex!("9302a444415441c404a1b2c3d4"));
        test(
            msg![0, "INV", 0 => hashes = &[ hash![0xA1, 0xB2, 0xC3, 0xD4], hash![0xE5, 0xF6, 0x01, 0x02], hash![0x12, 0x34, 0x56, 0x78] ]],
            hex!("9400a3494e560093c404a1b2c3d4c404e5f60102c40412345678"),
        );
    }

    #[test]
    fn test_message_decode_err() {
        let test = |bytes: &[u8], err: DecodingError| {
            let decoded_err = Message::decode_msgpack(bytes).expect_err("decode not failed");
            assert_eq!(decoded_err, err, "decode failed with different error: {}", hex::encode(bytes));
        };

        // not array
        test(&[0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f], DecodingError::BadMessageRootType);
        // len < 2
        test(&[0x91, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f], DecodingError::BadMessageRootArrayLength(1));
        // len > 4
        test(
            &[0x95, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x00, 0x01, 0x02, 0x3],
            DecodingError::BadMessageRootArrayLength(5),
        );
        // got string instead of int
        test(&[0x92, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x01], DecodingError::BadIdFieldType);
        // message type isn't string
        test(&[0x92, 0x01, 0x1], DecodingError::BadTypeFieldType);
        // unrecognized msg type
        test(
            &[0x92, 0x01, 0xa6, 0x53, 0x55, 0x50, 0x4d, 0x41, 0x4e],
            DecodingError::UnrecognizedMessageType("SUPMAN".to_string()),
        );
        test(
            &[0x93, 0x01, 0xa6, 0x53, 0x55, 0x50, 0x4d, 0x41, 0x4e, 0x01],
            DecodingError::UnrecognizedMessageType("SUPMAN".to_string()),
        );
        test(
            &[0x93, 0x00, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0xa5, 0x48, 0x45, 0x4c, 0x4c, 0x4f],
            DecodingError::BadHelloVersionFieldType,
        );
        // GET_DATA msg with empty hash
        test(
            &[0x93, 0x02, 0xa8, 0x47, 0x45, 0x54, 0x5f, 0x44, 0x41, 0x54, 0x41, 0xc4, 0x00],
            DecodingError::BadArgType("GET_DATA".to_string()),
        );
        // INV message with non-array type
        test(
            &[0x94, 0x02, 0xa3, 0x49, 0x4e, 0x56, 0x00, 0x93, 0x01, 0x02, 0x03],
            DecodingError::BadArgType("INV".to_string()),
        )
    }
}
